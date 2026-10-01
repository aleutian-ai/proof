// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// Verify checks every chain in the evidence file, each on its own, and that the
// subject index accounts for every chain.
//
// # Description
//
// The steps are docs/sink-format.md §6, numbered as there:
//
//  1. Ids are valid before any path is built from them.
//  2. Links: the chain's hashes recompute.
//  3. Checkpoints: every checkpoint is signed by a key in keys, is for this
//     chain, and binds the entries it covered. This is what catches entries
//     removed from the front, which step 2 cannot.
//  4. Entries: every event's stored content opens its commitment with its
//     nonce, and every erasure record matches its digest. Events before the
//     last GENUINE erasure entry are gone (content and nonce both deleted) and
//     count as erased; an event missing WITHOUT a genuine erasure after it is a
//     problem.
//  5. Nothing left over: no content or nonce row that matches no entry, and
//     no row keyed outside the sink's layout (counted, never shown).
//  6. Nothing removed: no checkpoint folder or secrets rows for a chain the
//     evidence file does not hold (unless the index binds it or has it
//     pending, for secrets rows).
//  7. Index accountability (read-only; ChainReport.Index): live, erased,
//     erased-unanchored and index-only are not problems; pending, unaccounted,
//     relinked and malformed are. "erased" needs a verified checkpoint over the
//     erasure; until then it is erased-unanchored.
//
// The report never names a subject, nor prints an index key that is not a
// valid chain id. ChainSubjects is the separate, deliberate call that names
// subjects.
//
// Steps 2 and 3 need only the evidence file, the checkpoints and a public key.
// Steps 4 to 7 need the secrets file and the subject index,
// which only the operator holds.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - keys: the public keys checkpoints may be signed with
//
// # Outputs
//
//   - Report: per chain, in chain-id order. Report.OK is the verdict.
//   - error: only when verification could not run (a file unreadable). A broken
//     chain is a finding in the Report, not an error.
func (s *Sink) Verify(ctx context.Context, keys anchor.KeySource, opts ...VerifyOption) (Report, error) {
	if keys == nil {
		return Report{}, errors.New("sink: a key source is required")
	}
	var cfg verifyConfig
	for _, o := range opts {
		o(&cfg)
		if cfg.err != nil {
			return Report{}, cfg.err
		}
	}
	var rc *recordChecker
	if cfg.recordTrust != nil {
		rc = &recordChecker{src: cfg.recordTrust, keys: map[string][]byte{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read-only throughout: a verifier must not modify the evidence it checks,
	// and must not create anything (a mistyped folder is reported, not made).
	f, err := s.openFolder(false)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	st, err := s.openStore(true)
	if err != nil {
		return Report{}, err
	}
	defer st.Close()
	// No secrets file: every event reports as unopenable, which is the truth.
	sec, err := openSecretsReadOnly(s.secretsPath(), s.lockTimeout)
	if err != nil {
		return Report{}, err
	}
	if sec != nil {
		defer sec.Close()
	}
	// The signatures file: what Verify checks with record trust, and the
	// folder-side checks (orphans, removed chains) either way.
	sig, err := openSignaturesReadOnly(s.signaturesPath(), s.lockTimeout)
	if err != nil {
		return Report{}, err
	}
	signing := false
	if sig != nil {
		defer sig.Close()
		if signing, err = sig.signing(); err != nil {
			return Report{}, err
		}
	}
	// No index file means no rows: every live chain is then unaccounted.
	subj, err := openSubjectsReadOnly(s.subjectsPath(), s.lockTimeout)
	if err != nil {
		return Report{}, err
	}
	var ix *indexSnapshot // nil: no index, no rows
	if subj != nil {
		defer subj.Close()
		if ix, err = subj.snapshot(); err != nil {
			return Report{}, err
		}
		defer ix.close()
	}
	chains, err := st.Chains(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("sink: %w", err)
	}

	var rep Report
	switch {
	case rc != nil:
		rep.RecordSignatures = RecordSignaturesChecked
	case signing:
		rep.RecordSignatures = RecordSignaturesNotChecked
	}
	inStore := map[string]bool{}
	reported := map[string]int{} // chain → its report's index in rep.Chains
	for _, chain := range chains {
		inStore[chain] = true
		reported[chain] = len(rep.Chains)
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if !ValidChainID(chain) {
			// Never build a path from it: it could be "../../somewhere".
			rep.Chains = append(rep.Chains, ChainReport{Chain: chain, Anomaly: "invalid-id",
				Problems: []string{"the evidence file holds a chain id this sink never writes; it was not read"}})
			continue
		}
		cr, err := s.verifyChain(ctx, st, sec, sig, rc, f, chain, keys, ix.state(chain))
		if err != nil {
			return rep, err
		}
		rep.Chains = append(rep.Chains, cr)
	}

	// Index rows with no chain in the evidence file. A key that is not a valid
	// chain id is never shown: it could hold anything, even a subject.
	invalidRows := 0
	addInvalid := func() {
		invalidRows++
		rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("<invalid index row #%d>", invalidRows),
			Index: IndexMalformed, Problems: []string{indexInconsistent}})
	}
	if err := ix.eachReverse(ctx, func(key []byte, row IndexState) {
		chain := string(key)
		if !ValidChainID(chain) {
			addInvalid()
			return
		}
		if inStore[chain] {
			return
		}
		cr := ChainReport{Chain: chain, Class: classOf(chain), Index: row}
		switch row {
		case IndexLive:
			cr.Index = IndexOnly // a note, not a problem: the next commit of the pair uses it
		case IndexPending:
			cr.Problems = append(cr.Problems, erasureInterrupted)
		default:
			cr.Problems = append(cr.Problems, indexInconsistent)
		}
		reported[chain] = len(rep.Chains)
		rep.Chains = append(rep.Chains, cr)
	}); err != nil {
		return rep, fmt.Errorf("sink: read the subject index: %w", err)
	}
	// Forward rows that disagree with the index: each still names a subject (in
	// its key, never shown) that no consistent row accounts for, and makes every
	// commit of its pair fail.
	if err := ix.eachBadForward(ctx, func(v []byte) {
		chain := string(v)
		i, known := reported[chain]
		if !ValidChainID(chain) || !known {
			addInvalid()
			return
		}
		cr := &rep.Chains[i]
		if cr.Index != IndexMalformed {
			cr.Problems = append(cr.Problems, indexInconsistent)
		}
		cr.Index = IndexMalformed
	}); err != nil {
		return rep, fmt.Errorf("sink: read the subject index: %w", err)
	}

	// A chain removed from the evidence file leaves its checkpoints and its
	// secrets behind. They are the only trace of it, so look for them.
	reportFor := func(name string) *ChainReport {
		i, known := reported[name]
		if !known {
			reported[name] = len(rep.Chains)
			rep.Chains = append(rep.Chains, ChainReport{Chain: name, Class: classOf(name)})
			i = len(rep.Chains) - 1
		}
		return &rep.Chains[i]
	}
	dirs, err := f.list("anchors")
	switch {
	case errors.Is(err, errNotRealDir):
		rep.Chains = append(rep.Chains, ChainReport{Chain: "anchors/", Anomaly: "invalid-folder",
			Problems: []string{fmt.Sprintf("anchors/ is %v", errNotRealDir)}})
	case err != nil:
		return rep, fmt.Errorf("sink: %w", err)
	}
	for _, d := range dirs {
		if inStore[d.Name()] {
			continue
		}
		// Checkpoints are written only for chains with entries: whatever the
		// index says, entries were removed.
		cr := reportFor(d.Name())
		cr.Anomaly = "removed"
		cr.Problems = append(cr.Problems, "anchors/ has checkpoints for this chain, but the "+
			"evidence file has no entries for it: the chain was REMOVED")
	}
	if sec != nil {
		withRows, err := sec.chainsWithRows()
		if err != nil {
			return rep, fmt.Errorf("sink: read the secrets file: %w", err)
		}
		invalidSecrets := 0
		if n, err := sec.malformedKeys(); err != nil {
			return rep, fmt.Errorf("sink: read the secrets file: %w", err)
		} else if n > 0 {
			invalidSecrets++
			rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("<invalid secrets row #%d>", invalidSecrets),
				Anomaly: "removed", Problems: []string{fmt.Sprintf("the secrets file holds %d rows whose key "+
					"this sink never writes; an erasure may not reach them: remove them by hand", n)}})
		}
		for _, name := range withRows {
			if inStore[name] {
				continue
			}
			if !ValidChainID(name) {
				// Never shown: a crafted key could hold anything.
				invalidSecrets++
				rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("<invalid secrets row #%d>", invalidSecrets),
					Anomaly: "removed", Problems: []string{"the secrets file holds content or nonces under an " +
						"id this sink never mints; remove them by hand"}})
				continue
			}
			cr := reportFor(name)
			if cr.Index != IndexOnly && cr.Index != IndexPending {
				cr.Anomaly = "removed"
			}
			cr.Problems = append(cr.Problems, "the secrets file holds content or nonces for this chain, "+
				"but the evidence file has no entries for it: the chain was removed, or a first commit "+
				"stopped before its append; "+remedy(cr.Index))
		}
	}
	if sig != nil {
		if err := checkSignatureRows(&rep, sig, inStore, reportFor); err != nil {
			return rep, err
		}
	}
	sort.Slice(rep.Chains, func(i, j int) bool { return rep.Chains[i].Chain < rep.Chains[j].Chain })
	return rep, nil
}

// checkSignatureRows reports what the signatures file holds for chains the
// evidence file does not: REMOVED (a problem), unless the index binds the chain
// or has it pending (a first commit's leftovers: a note); and rows keyed off
// the layout, by count. Record trust plays no part: this is about the folder.
func checkSignatureRows(rep *Report, sig *signaturesStore, inStore map[string]bool,
	reportFor func(string) *ChainReport) error {
	invalid := 0
	addInvalid := func(problem string) {
		invalid++
		rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("<invalid signatures row #%d>", invalid),
			Anomaly: "removed", Problems: []string{problem}})
	}
	if n, err := sig.malformedKeys(); err != nil {
		return fmt.Errorf("sink: read the signatures file: %w", err)
	} else if n > 0 {
		addInvalid(fmt.Sprintf("the signatures file holds %d rows whose key this sink never writes", n))
	}
	withRows, err := sig.chainsWithRows()
	if err != nil {
		return fmt.Errorf("sink: read the signatures file: %w", err)
	}
	for _, name := range withRows {
		if inStore[name] {
			continue
		}
		if !ValidChainID(name) {
			continue // counted by malformedKeys; never shown
		}
		ids, err := sig.rowIDs(name)
		if err != nil {
			return fmt.Errorf("sink: read the signatures file: %w", err)
		}
		cr := reportFor(name)
		if cr.Index == IndexOnly || cr.Index == IndexPending {
			cr.OrphanSignatures += len(ids)
			continue
		}
		cr.Anomaly = "removed"
		cr.Problems = append(cr.Problems, "the signatures file holds record signatures for this chain, "+
			"but the evidence file has no entries for it: the chain was REMOVED")
	}
	return nil
}

// Index problems, worded once.
const (
	erasureInterrupted = "erasure interrupted: the subject is forgotten but this chain is not yet " +
		"erased; run `proof sink erase --resume`"
	indexInconsistent = "the subject index is inconsistent for this chain (a row that disagrees with " +
		"the rest of the index); repair it by hand. Restoring an older copy is no fix: it re-links " +
		"every subject erased since"
	indexRelinked = "the subject index binds a subject to this chain, which ends with its erasure: the " +
		"index was restored from before an erasure, or edited, and re-links an erased subject; run " +
		"`proof sink erase --resume` to forget it again"
)

// remedy says how to remove leftover files of a chain in a given index state.
func remedy(index IndexState) string {
	switch index {
	case IndexLive, IndexOnly:
		return "erasing its subject removes them"
	case IndexPending:
		return "`proof sink erase --resume` removes them"
	default:
		return "nothing in the sink will remove them (no index row): check, then remove by hand"
	}
}

// classOf is the class prefix of a valid chain id, or "".
func classOf(chain string) string {
	if !ValidChainID(chain) {
		return ""
	}
	class, _, _ := strings.Cut(chain, ".")
	return class
}

// verifyChain verifies one chain in two paged passes, never holding it whole:
// the first counts it and finds its last erasure; the second walks it, binding
// each checkpoint as the walk reaches its end, and checks each entry's content.
func (s *Sink) verifyChain(ctx context.Context, st *boltstore.Store, sec *secretsStore, sig *signaturesStore,
	rc *recordChecker, f *folder, chain string, keys anchor.KeySource, row IndexState) (ChainReport, error) {
	cr := ChainReport{Chain: chain, Class: classOf(chain)}
	anchors, problem, err := f.readAnchors(chain)
	if err != nil {
		return cr, err
	}

	// Pass 1: the length, where the last GENUINE erasure is (its hash is that of
	// the exact record; the entry type alone is not evidence), and whether the
	// chain ends with one. Erase applies the same rule.
	total, lastErasure := 0, -1
	endsErased, tailSeq := false, int64(0)
	if err := forEachEntry(ctx, st, chain, func(e store.Entry) {
		endsErased = total > 0 && e.EntryType == EntryTypeErasure &&
			e.ContentHash == erasureHash(erasureRecord(tailSeq))
		if endsErased {
			lastErasure = total
		}
		tailSeq = e.GlobalSeq
		total++
	}); err != nil {
		return cr, err
	}
	cr.Entries = total
	switch {
	case row == IndexLive && endsErased:
		cr.Index = IndexRelinked
		cr.Problems = append(cr.Problems, indexRelinked)
	case row == IndexLive:
		cr.Index = IndexLive
	case row == IndexPending:
		cr.Index = IndexPending
		cr.Problems = append(cr.Problems, erasureInterrupted)
	case row == IndexMalformed:
		cr.Index = IndexMalformed
		cr.Problems = append(cr.Problems, indexInconsistent)
	case endsErased:
		// Upgraded to IndexErased below, once a verified checkpoint is known to
		// cover the erasure entry.
		cr.Index = IndexErasedUnanchored
	default:
		cr.Index = IndexUnaccounted
		cr.Problems = append(cr.Problems, "not accounted for: the subject index has no row for this "+
			"chain, and it does not end with an erasure (the index was lost or edited, or another "+
			"writer added the chain)")
	}

	// The chain's content and nonce rows, as a set of entry ids to tick off.
	unmatched := map[string]bool{}
	if sec != nil {
		ids, err := sec.rowIDs(chain)
		if err != nil {
			return cr, fmt.Errorf("sink: read the secrets file: %w", err)
		}
		for _, id := range ids {
			unmatched[id] = true
		}
	}

	// The chain's signature rows, to tick off: those left are orphans.
	sigUnmatched := map[string]bool{}
	if sig != nil {
		ids, err := sig.rowIDs(chain)
		if err != nil {
			return cr, fmt.Errorf("sink: read the signatures file: %w", err)
		}
		for _, id := range ids {
			sigUnmatched[id] = true
		}
	}
	var tally signatureTally

	// Pass 2: walk, bind checkpoints, check content (and record signatures).
	w := verify.NewWalker(verify.Options{MaxBreaks: 1})
	var series *seriesCheck
	if problem != "" {
		cr.Problems = append(cr.Problems, problem)
	} else {
		series = newSeriesCheck(chain, anchors, keys)
	}
	i, prevSeq := 0, int64(0)
	var contentErr error
	// The STORED linkage, which the walker does not read (it links from the hash
	// it computes): each entry's stored previous_hash must be the previous
	// entry's chain hash, and a sink chain starts at sequence 0 with none. A
	// record signature covers the stored previous_hash, so without this check
	// a signed record could be spliced in, or the front cut off, with the
	// keyless chain hashes recomputed (_75d review). The first break only.
	prevChainHash, linkProblem, formatProblem := "", "", ""
	err = forEachEntry(ctx, st, chain, func(e store.Entry) {
		if linkProblem == "" {
			switch {
			case i == 0 && (e.GlobalSeq != 0 || e.PreviousHash != ""):
				linkProblem = "links BROKEN: the chain does not start at sequence 0 with no previous_hash " +
					"(entries were removed from the front)"
			case i > 0 && e.PreviousHash != prevChainHash:
				linkProblem = fmt.Sprintf("links BROKEN at entry %d: its stored previous_hash is not the "+
					"previous entry's chain hash (an entry was replaced, or the hashes rewritten)", i)
			}
		}
		prevChainHash = e.ChainHash
		if formatProblem == "" && e.FormatVersion != chainformat.FormatV3 {
			formatProblem = fmt.Sprintf("entry %d is not in chain format v3, which is all this sink writes", i)
		}
		ve := toVerifyEntry(e)
		w.Add(ve)
		if series != nil {
			series.reached(w)
		}
		if contentErr == nil {
			contentErr = s.checkEntry(&cr, sec, ve, i, lastErasure, prevSeq, unmatched)
		}
		delete(sigUnmatched, e.EntryID)
		if rc != nil && contentErr == nil {
			contentErr = rc.check(&tally, sig, chain, e)
		}
		prevSeq = e.GlobalSeq
		i++
	})
	if err != nil {
		return cr, err
	}
	if contentErr != nil {
		return cr, contentErr
	}

	for _, p := range []string{linkProblem, formatProblem} {
		if p != "" {
			cr.Problems = append(cr.Problems, p)
		}
	}
	if res := w.Result(); len(res.Breaks) > 0 {
		cr.Problems = append(cr.Problems, fmt.Sprintf("links BROKEN at entry %d: %s",
			res.FirstBreak, res.Breaks[0].Type))
	}
	covered := int64(0)
	if series != nil {
		series.finish(total)
		cr.Problems = append(cr.Problems, series.problems...)
		cr.Checkpoints, covered = series.verified, series.covered
	}
	cr.Unanchored = total - int(covered)
	if cr.Index == IndexErasedUnanchored && series != nil && len(series.problems) == 0 && int(covered) == total {
		cr.Index = IndexErased
	}

	// A content or nonce row matching no entry was never committed: a commit
	// that stopped before its append. It is still personal data, so say so.
	// Only a valid entry id is shown; any other (a crafted file could put
	// anything there, even a subject) is counted.
	names := make([]string, 0, len(unmatched))
	odd := 0
	for n := range unmatched {
		if entryIDPattern.MatchString(n) {
			names = append(names, n)
		} else {
			odd++
		}
	}
	sort.Strings(names)
	for _, n := range names {
		cr.Problems = append(cr.Problems, fmt.Sprintf("stored content or nonce for %s matches no entry "+
			"(a commit that did not finish?); %s", n, remedy(cr.Index)))
	}
	if odd > 0 {
		cr.Problems = append(cr.Problems, fmt.Sprintf("%d stored rows under an entry id this sink never "+
			"assigns; %s", odd, remedy(cr.Index)))
	}

	cr.OrphanSignatures = len(sigUnmatched)
	if rc != nil {
		tally.report(&cr)
		// R6: a genuine erasure whose own record signature verified under record
		// trust is authentic without a checkpoint, provided EVERYTHING else
		// about the chain holds (content and nonces gone, index, nothing
		// pending): the signature replaces only the checkpoint-coverage check.
		// With record trust, no problem at all means every entry's signature
		// verified, the erasure entry's included.
		if cr.Index == IndexErasedUnanchored && endsErased && len(cr.Problems) == 0 {
			cr.Index = IndexErased
		}
	}
	return cr, nil
}

// VerifyOption configures one Verify call.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	recordTrust anchor.KeySource
	err         error
}

// WithRecordTrust makes Verify check every entry's record signature against
// the record keys src holds (docs/sink-format.md §9).
//
// # Description
//
// The verifier's policy, never the folder's: with record trust, EVERY entry
// must carry a valid signature by a key src holds, whether or not the folder
// says the sink signs. Each entry's envelope is rebuilt from the entry as
// stored (its own previous_hash included) and must verify under the key its
// row names, which must be exactly that key's id. Failures are counted per kind
// (ChainReport.Unsigned, MalformedSignatures, UnknownKeySignatures,
// BadSignatures) and reported as one line each. A genuine erasure whose own
// signature verifies counts as erased without a checkpoint, when nothing else
// about its chain fails.
//
// # Inputs
//
//   - src: the record keys. A separate source from the checkpoint keys:
//     trusting a key for one never trusts it for the other. nil makes Verify
//     fail.
//
// # Outputs
//
//   - VerifyOption: to pass to Verify
//
// # Example
//
//	ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{recordKeyID: recordPub})
//	rep, err := s.Verify(ctx, checkpointKeys, sink.WithRecordTrust(ring))
//
// # Limitations
//
//   - ML-DSA-65 only (record.v1); the algorithm is never taken from the file.
//   - About 30 µs per entry.
//
// # Assumptions
//
//   - src is safe for concurrent use. Each key id is looked up once per call.
func WithRecordTrust(src anchor.KeySource) VerifyOption {
	return func(c *verifyConfig) {
		if src == nil {
			c.err = errors.New("sink: WithRecordTrust needs a key source")
			return
		}
		if v := reflect.ValueOf(src); v.Kind() == reflect.Pointer && v.IsNil() {
			c.err = errors.New("sink: WithRecordTrust needs a key source (got a nil pointer)")
			return
		}
		c.recordTrust = src
	}
}

// recordChecker checks entries' record signatures, looking each key id up once.
type recordChecker struct {
	src  anchor.KeySource
	keys map[string][]byte // key id → public key; nil: not trusted
}

// signatureTally counts one chain's signature results, and the first VALID
// entry id of each failure kind (a crafted id is counted, never shown).
type signatureTally struct {
	signed                        int
	unsigned, malformed, unknown  int
	bad                           int
	firstUnsigned, firstMalformed string
	firstUnknown, firstBad        string
}

// check checks one entry's record signature, counting the result in t. An
// error means the signatures file or the key source failed, not the signature.
func (rc *recordChecker) check(t *signatureTally, sig *signaturesStore, chain string, e store.Entry) error {
	first := func(dst *string) {
		if *dst == "" && entryIDPattern.MatchString(e.EntryID) {
			*dst = e.EntryID
		}
	}
	if sig == nil {
		t.unsigned++
		first(&t.firstUnsigned)
		return nil
	}
	row, found, malformed, err := sig.get(chain, e.EntryID)
	switch {
	case err != nil:
		return fmt.Errorf("sink: read the signatures file: %w", err)
	case !found:
		t.unsigned++
		first(&t.firstUnsigned)
		return nil
	case malformed:
		t.malformed++
		first(&t.firstMalformed)
		return nil
	}
	pub, ok := rc.keys[row.keyID]
	if !ok {
		p, _, err := rc.src.PublicKey(row.keyID)
		switch {
		case errors.Is(err, anchor.ErrUnknownKeyID):
			p = nil
		case err != nil:
			return fmt.Errorf("sink: look up record key %s: %w", row.keyID, err)
		}
		rc.keys[row.keyID] = p
		pub = p
	}
	if pub == nil {
		t.unknown++
		first(&t.firstUnknown)
		return nil
	}
	f := recordFields{chainID: chain, entryID: e.EntryID, entryType: e.EntryType, globalSeq: e.GlobalSeq,
		prevHash: e.PreviousHash, timestamp: e.Timestamp, contentHash: e.ContentHash, keyID: row.keyID}
	if err := verifyRecordSignature(pub, f, row.sig); err != nil {
		t.bad++
		first(&t.firstBad)
		return nil
	}
	t.signed++
	return nil
}

// report writes the tally into cr: the counts, and one problem line per kind.
func (t signatureTally) report(cr *ChainReport) {
	cr.Signed, cr.Unsigned, cr.MalformedSignatures = t.signed, t.unsigned, t.malformed
	cr.UnknownKeySignatures, cr.BadSignatures = t.unknown, t.bad
	line := func(n int, what, first string) {
		if n == 0 {
			return
		}
		subject := fmt.Sprintf("%d entries have", n)
		if n == 1 {
			subject = "1 entry has"
		}
		p := fmt.Sprintf("%s %s", subject, what)
		if first != "" {
			p += fmt.Sprintf(" (first: %s)", first)
		}
		cr.Problems = append(cr.Problems, p)
	}
	line(t.unsigned, "no record signature", t.firstUnsigned)
	line(t.malformed, "a malformed record signature row", t.firstMalformed)
	line(t.unknown, "a record signature by a key not trusted for records", t.firstUnknown)
	line(t.bad, "a BAD record signature: the stored entry is not what was signed", t.firstBad)
}

// seriesCheck verifies a chain's checkpoint series during a single walk: each
// checkpoint is bound when the walk reaches its last entry. The first problem
// stops the series; later checkpoints are not reported as verified.
type seriesCheck struct {
	chain    string
	anchors  []anchor.Anchor
	keys     anchor.KeySource
	next     int
	prevHash string
	prevID   string
	covered  int64
	verified int
	problems []string
	stopped  bool
}

func newSeriesCheck(chain string, anchors []anchor.Anchor, keys anchor.KeySource) *seriesCheck {
	c := &seriesCheck{chain: chain, anchors: anchors, keys: keys,
		prevHash: anchor.SeedAnchorHash, prevID: anchor.SeedAnchorID}
	c.checkNext()
	return c
}

func (c *seriesCheck) fail(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
	c.stopped = true
}

// checkNext applies the series rules that need no entries to the next
// checkpoint, as soon as it becomes the next.
func (c *seriesCheck) checkNext() {
	if c.stopped || c.next >= len(c.anchors) {
		return
	}
	a, n := c.anchors[c.next], c.next+1
	switch {
	case a.Subject != c.chain:
		c.fail("checkpoint %04d is for another chain", n)
	case a.PreviousAnchorID != c.prevID:
		// The hash already binds the predecessor; checking the id too keeps
		// this verifier in step with one following format-spec §9.7 literally.
		c.fail("checkpoint %04d does not name checkpoint %04d as its predecessor", n, n-1)
	case a.EntryCount <= c.covered:
		c.fail("checkpoint %04d covers %d entries, no more than checkpoint %04d did: a series must grow",
			n, a.EntryCount, n-1)
	}
}

// reached binds the next checkpoint if the walk has just reached its last entry.
func (c *seriesCheck) reached(w *verify.Walker) {
	if c.stopped || c.next >= len(c.anchors) || int64(w.Count()) != c.anchors[c.next].EntryCount {
		return
	}
	a, n := c.anchors[c.next], c.next+1
	// A checkpoint commits to the chain as it was when signed: it is bound to
	// exactly the entries it covered, which is what the walker holds now.
	br, err := w.VerifyAnchor(a, c.prevHash, c.keys)
	switch {
	case err != nil:
		c.fail("checkpoint %04d: %v", n, err)
		return
	case !br.Bound || !br.SignatureVerified:
		c.fail("checkpoint %04d does NOT verify: %s", n, br.Detail)
		return
	}
	c.verified++
	c.covered = a.EntryCount
	c.prevHash, c.prevID = a.ChainHash, a.AnchorID
	c.next++
	c.checkNext()
}

// finish reports a checkpoint the walk never reached: it claims more entries
// than the chain holds.
func (c *seriesCheck) finish(total int) {
	if !c.stopped && c.next < len(c.anchors) {
		c.fail("checkpoint %04d claims %d entries; the chain has %d",
			c.next+1, c.anchors[c.next].EntryCount, total)
	}
}

// checkEntry checks one entry's content against the rules of
// docs/sink-format.md §6, given the index of the chain's last erasure and the
// previous entry's sequence. It ticks the entry's content row off unmatched.
func (s *Sink) checkEntry(cr *ChainReport, sec *secretsStore, e verify.Entry, i, lastErasure int,
	prevSeq int64, unmatched map[string]bool) error {
	if !entryIDPattern.MatchString(e.EntryID) {
		// Never shown: a crafted id could hold anything, even a subject.
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %d has an id this sink never assigns; "+
			"it was not read", i))
		return nil
	}
	delete(unmatched, e.EntryID)
	var content, nonce []byte
	tooBig := false
	if sec != nil { // no secrets file at all: nothing can be opened
		var err error
		if content, nonce, tooBig, err = sec.get(cr.Chain, e.EntryID); err != nil {
			return fmt.Errorf("sink: read the secrets of %s: %w", e.EntryID, err)
		}
	}
	missing, noNonce := content == nil && !tooBig, nonce == nil
	if tooBig {
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s: its content is %d bytes, over the "+
			"%d byte limit; it was not checked", e.EntryID, MaxContentBytes+1, MaxContentBytes))
		return nil
	}

	switch {
	case e.EntryType == EntryTypeErasure:
		// The record must be EXACTLY the one for this position, and hash under
		// the erasure domain. An event relabelled as an erasure fails both:
		// its commitment is not a domain-separated hash of any record.
		if i == 0 {
			cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s is the first entry: "+
				"there is nothing before it to erase", e.EntryID))
			return nil
		}
		want := erasureRecord(prevSeq)
		if !noNonce {
			cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s has a nonce stored "+
				"beside it; the sink never writes one", e.EntryID))
		}
		if missing || !bytes.Equal(content, want) || erasureHash(want) != e.ContentHash {
			cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s is missing, MODIFIED, "+
				"or not the erasure record for its position", e.EntryID))
		}
	case e.EntryType != EntryTypeEvent:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s has type %q, which this sink never writes",
			e.EntryID, e.EntryType))
	case i < lastErasure:
		if !missing || !noNonce {
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was erased, but its content or nonce "+
				"is still here: run erase again", e.EntryID))
			return nil
		}
		cr.Erased++
	case missing:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s is MISSING: the chain records it, "+
			"its content is gone, and no erasure was recorded", e.EntryID))
	case noNonce:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s cannot be opened: its nonce is gone, "+
			"and no erasure was recorded", e.EntryID))
	case !commitment.Verify(e.ContentHash, nonce, content):
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was MODIFIED: its content no longer "+
			"opens the commitment", e.EntryID))
	default:
		cr.Opened++
	}
	return nil
}
