// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/fault"
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
//  2. Links: the chain's hashes recompute, AND every entry's stored
//     previous_hash is the previous entry's chain hash, the chain starting at
//     sequence 0 with none (what a record signature covers); every entry is
//     chain format v3.
//  3. Checkpoints: every checkpoint is signed by a key in keys, is for this
//     chain, and binds the entries it covered.
//  4. Entries: every event's stored content opens its commitment with its
//     nonce, and every erasure record matches its digest. Events before the
//     last GENUINE erasure entry are gone (content and nonce both deleted) and
//     count as erased; an event missing WITHOUT a genuine erasure after it is a
//     problem.
//  5. Nothing left over: no content or nonce row that matches no entry, and
//     no row keyed outside the sink's layout (counted, never shown).
//  6. Nothing removed: no checkpoint folder, secrets rows or signature rows
//     for a chain the evidence file does not hold (unless the index binds it or
//     has it pending: a first commit's leftovers).
//  7. Index accountability (read-only; ChainReport.Index): live, erased,
//     erased-unanchored and index-only are not problems; pending, unaccounted,
//     relinked and malformed are. "erased" needs a verified checkpoint over the
//     erasure, or (step 8) its verified record signature; until then it is
//     erased-unanchored.
//  8. Record signatures, with WithRecordTrust: every entry's, rebuilt from the
//     stored entry (Report.RecordSignatures says whether they were checked;
//     orphan rows are counted as a note).
//
// The report never names a subject, nor prints an id read from the folder
// that is not of the sink's own shape. ChainSubjects is the separate,
// deliberate call that names subjects.
//
// Steps 2, 3 and 8 need only the evidence file, the checkpoints, the
// signatures file and public keys. Steps 4 to 7 (and the "erased" verdict)
// need the secrets file and the subject index, which only the operator holds.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - keys: the public keys checkpoints may be signed with
//   - opts: WithRecordTrust, to check record signatures
//
// # Outputs
//
//   - Report: per chain, in chain-id order. Report.OK is the verdict; a
//     damaged side file is a problem row, not an error.
//   - error: only when verification could not run (a file unreadable, a key
//     source failing). A broken chain is a finding in the Report.
//
// # Example
//
//	rep, err := s.Verify(ctx, checkpointKeys, sink.WithRecordTrust(recordKeys))
//	if err != nil {
//	    return err
//	}
//	if !rep.OK() {
//	    // report rep.Chains[i].Problems
//	}
//
// # Limitations
//
//   - Opens every file read-only, but parses them with bbolt, which may panic
//     on a crafted file: verify a folder from someone else as an exported
//     bundle (ticket _72), not the files.
//   - Reads a page at a time (VerifyEach): not one snapshot of the folder.
//     Memory holds every report (VerifyEach streams them instead).
//   - Front truncation of a chain without record signatures is caught only
//     by checkpoints (and, for a sink chain, the start at sequence 0).
//
// # Assumptions
//
//   - keys and any record trust source are safe for concurrent use.
func (s *Sink) Verify(ctx context.Context, keys anchor.KeySource, opts ...VerifyOption) (_ Report, err error) {
	defer fault.Recover(&err)()
	var rep Report
	at := map[string]int{} // chain → its report's index, to merge a sweep row into it
	sum, err := s.VerifyEach(ctx, keys, func(cr ChainReport) error {
		if i, ok := at[cr.Chain]; ok {
			mergeReport(&rep.Chains[i], cr)
			return nil
		}
		at[cr.Chain] = len(rep.Chains)
		rep.Chains = append(rep.Chains, cr)
		return nil
	}, opts...)
	rep.RecordSignatures = sum.RecordSignatures
	sort.Slice(rep.Chains, func(i, j int) bool { return rep.Chains[i].Chain < rep.Chains[j].Chain })
	return rep, err
}

// mergeReport folds a later row for the same chain (from the sweep) into the
// first one.
func mergeReport(dst *ChainReport, extra ChainReport) {
	if extra.Index == IndexMalformed && dst.Index == IndexMalformed {
		return // already reported inconsistent
	}
	if extra.Index != "" {
		dst.Index = extra.Index
	}
	if extra.Anomaly != "" {
		dst.Anomaly = extra.Anomaly
	}
	dst.OrphanSignatures += extra.OrphanSignatures
	dst.Problems = append(dst.Problems, extra.Problems...)
}

// Summary is what VerifyEach reports besides the chains themselves.
type Summary struct {
	// Reports is how many reports fn was given; Failed, how many had problems.
	Reports int `json:"reports"`
	Failed  int `json:"failed"`
	// RecordSignatures says whether record signatures were checked (as
	// Report.RecordSignatures), from the signatures file's mode at the start.
	RecordSignatures RecordSignatureCheck `json:"record_signatures,omitempty"`
}

// OK reports whether no report had a problem.
func (s Summary) OK() bool { return s.Failed == 0 }

// VerifyEach verifies the sink as Verify does, handing each report to fn as
// it is done instead of collecting them, and reading the folder a page at a
// time so writers are never blocked for the whole run.
//
// # Description
//
// Chains are verified in chain-id order, whole chains per page (a page ends
// after about 50 ms of work); the files are released between pages, for longer
// than bbolt's 50 ms lock retry, so a waiting writer gets in. Then a
// cross-chain sweep (index rows, checkpoint folders, secrets and signature
// rows for chains the evidence file does not hold; rows keyed off the layout)
// runs, also in pages, each candidate checked against the evidence file at
// that moment. Its rows come after the chains'. A sweep finding about a chain
// already reported (an index row that disagrees with it) comes as a second
// row for that chain (at most one): Verify merges them, and Summary counts it
// as the same chain.
//
// The result is NOT one snapshot of the folder: each chain is reported as it
// was when its page read it. A chain committed during the run is reported if
// its id sorts after the page being read, and never falsely reported REMOVED.
// For a point-in-time verdict, stop the writers, or verify a copy.
//
// # Inputs
//
//   - ctx: honoured between chains and between pages
//   - keys: the public keys checkpoints may be signed with
//   - fn: called for each report, with no file held; an error stops the run
//     and is returned
//   - opts: WithRecordTrust
//
// # Outputs
//
//   - Summary: counts (chains, not rows), and whether record signatures were
//     checked
//   - error: verification could not run, or fn's error. Each page takes the
//     files again under the lock timeout: a writer holding them longer than
//     that (a very large erase), or committing without pause, makes the run
//     stop part-way (ErrBusy), with the reports so far already handed to fn.
//     bbolt retries a held lock every 50 ms without queueing, so neither side
//     is guaranteed a turn: Verify pauses longer than that between pages for
//     writers, and a writer should pause between commits (a consumer does,
//     while it fetches).
//
// # Example
//
//	sum, err := s.VerifyEach(ctx, keys, func(cr sink.ChainReport) error {
//	    fmt.Println(cr.Chain, len(cr.Problems) == 0)
//	    return nil
//	})
//
// # Limitations
//
//   - One chain is read under one lock hold: a very large chain still holds
//     the lock for its own duration (incremental verification is ticket _74d).
//   - Memory is one page plus the largest chain's stored rows, plus the
//     sweep's reports for chains the evidence file does not hold.
//
// # Assumptions
//
//   - keys and any record trust source are safe for concurrent use.
func (s *Sink) VerifyEach(ctx context.Context, keys anchor.KeySource, fn func(ChainReport) error,
	opts ...VerifyOption) (_ Summary, err error) {
	defer fault.Recover(&err)()
	var sum Summary
	if keys == nil {
		return sum, errors.New("sink: a key source is required")
	}
	if fn == nil {
		return sum, errors.New("sink: a report function is required")
	}
	var cfg verifyConfig
	for _, o := range opts {
		o(&cfg)
		if cfg.err != nil {
			return sum, cfg.err
		}
	}
	var rc *recordChecker
	if cfg.recordTrust != nil {
		rc = &recordChecker{src: cfg.recordTrust, keys: map[string][]byte{}}
	}

	// A sweep row about a chain already reported (an index row that disagrees
	// with it) is handed to fn too, but counted as the same chain: not a new
	// report, and a new failure only if the chain had none.
	type out struct {
		cr    ChainReport
		again bool
	}
	var pending []out
	failed := map[string]bool{} // chains already counted as failed (failures are few)
	flush := func() error {
		for _, o := range pending {
			bad := len(o.cr.Problems) > 0
			if !o.again {
				sum.Reports++
			}
			if bad && !failed[o.cr.Chain] {
				sum.Failed++
				failed[o.cr.Chain] = true
			}
			if err := fn(o.cr); err != nil {
				return err
			}
		}
		pending = pending[:0]
		return nil
	}

	// 1. The chains, whole chains per page.
	first, invalidChains := true, 0
	var cursor *string // nil: from the first chain ("" can be a crafted chain id)
	err = s.inPages(ctx, true, func(p *pageFiles, deadline time.Time) (bool, error) {
		if first {
			first = false
			switch {
			case rc != nil:
				sum.RecordSignatures = RecordSignaturesChecked
			case p.signing:
				sum.RecordSignatures = RecordSignaturesNotChecked
			}
		}
		chains, err := p.st.ChainsAfter(ctx, cursor, pageMaxChains)
		if err != nil {
			return false, fmt.Errorf("sink: %w", err)
		}
		for i, chain := range chains {
			if i > 0 && time.Now().After(deadline) {
				return false, nil
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			cursor = &chains[i]
			if !ValidChainID(chain) {
				// Never build a path from it: it could be "../../somewhere".
				// Nor shown: a crafted id could hold anything, even a subject.
				invalidChains++
				pending = append(pending, out{cr: ChainReport{Chain: fmt.Sprintf("<invalid chain #%d>", invalidChains),
					Anomaly:  "invalid-id",
					Problems: []string{"the evidence file holds a chain id this sink never writes; it was not read"}}})
				continue
			}
			cr, err := s.verifyChain(ctx, p.st, p.sec, p.sig, rc, p.f, chain, keys, p.ix.state(chain))
			if err != nil {
				return false, err
			}
			pending = append(pending, out{cr: cr})
		}
		return len(chains) < pageMaxChains, nil
	}, flush)
	if err != nil {
		return sum, err
	}

	// 2. The cross-chain sweep.
	sw := &sweep{rows: map[string]*ChainReport{}, againSeen: map[string]bool{}}
	defer sw.closeAnchors()
	if err := s.inPages(ctx, true, func(p *pageFiles, deadline time.Time) (bool, error) {
		return sw.step(ctx, p, deadline)
	}, nil); err != nil {
		return sum, err
	}
	names := make([]string, 0, len(sw.rows))
	for n := range sw.rows {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		pending = append(pending, out{cr: *sw.rows[n]})
	}
	for _, cr := range sw.extra {
		pending = append(pending, out{cr: cr})
	}
	for _, cr := range sw.again {
		pending = append(pending, out{cr: cr, again: true})
	}
	return sum, flush()
}

// sweep is the cross-chain checks' state across pages: one stage after
// another, each with its own cursor.
type sweep struct {
	stage int
	// rows are reports for chains the evidence file does not hold; extra are
	// rows for chains it does (an index row that disagrees) and numbered rows
	// for ids never shown.
	rows  map[string]*ChainReport
	extra []ChainReport
	// again are second rows for chains the walk already reported (an index
	// row that disagrees with one), at most one per chain.
	again     []ChainReport
	againSeen map[string]bool

	revAfter       string
	fwdAfter       []byte
	anchors        *os.File
	secAfter       *string
	sigAfter       *string
	mal            keyCursor
	malCount       int
	invalidIndex   int
	invalidSecrets int
	invalidSigs    int
	invalidAnchors int
}

func (w *sweep) closeAnchors() {
	if w.anchors != nil {
		w.anchors.Close()
		w.anchors = nil
	}
}

// rowFor is the report of a chain the evidence file does not hold.
func (w *sweep) rowFor(name string) *ChainReport {
	if r, ok := w.rows[name]; ok {
		return r
	}
	r := &ChainReport{Chain: name, Class: classOf(name)}
	w.rows[name] = r
	return r
}

func (w *sweep) invalidIndexRow() {
	w.invalidIndex++
	w.extra = append(w.extra, ChainReport{Chain: fmt.Sprintf("<invalid index row #%d>", w.invalidIndex),
		Index: IndexMalformed, Problems: []string{indexInconsistent}})
}

// beforeAnchorsOpen runs between the sweep's Lstat of anchors/ and its open: a
// test hook (it swaps the folder in exactly that window). nil outside tests.
var beforeAnchorsOpen func()

// inStore reports whether the evidence file holds entries for chain, now.
func inStore(ctx context.Context, p *pageFiles, chain string) (bool, error) {
	_, _, err := p.st.ReadTail(ctx, chain)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrEmptyChain):
		return false, nil
	}
	return false, fmt.Errorf("sink: read chain %s: %w", chain, err)
}

// step does one page of the sweep and reports whether it is done.
func (w *sweep) step(ctx context.Context, p *pageFiles, deadline time.Time) (bool, error) {
	progressed := false // at least one unit per page, whatever the budget
	for ; w.stage < 8; w.stage++ {
		for {
			if progressed && time.Now().After(deadline) {
				return false, nil
			}
			progressed = true
			done, err := w.stageStep(ctx, p)
			if err != nil {
				return false, err
			}
			if done {
				break
			}
		}
	}
	return true, nil
}

// stageStep does one bounded unit of the current stage; done means the stage
// is complete.
func (w *sweep) stageStep(ctx context.Context, p *pageFiles) (bool, error) {
	switch w.stage {
	case 0: // index rows with no chain in the evidence file
		rows := p.ix.reverseAfter(w.revAfter, pageMaxKeys)
		for _, r := range rows {
			w.revAfter = r.key
			if !ValidChainID(r.key) {
				w.invalidIndexRow() // never shown: it could hold anything, even a subject
				continue
			}
			in, err := inStore(ctx, p, r.key)
			if err != nil {
				return false, err
			}
			if in {
				continue
			}
			cr := w.rowFor(r.key)
			cr.Index = r.state
			switch r.state {
			case IndexLive:
				cr.Index = IndexOnly // a note, not a problem: the next commit of the pair uses it
			case IndexPending:
				cr.Problems = append(cr.Problems, erasureInterrupted)
			default:
				cr.Problems = append(cr.Problems, indexInconsistent)
			}
		}
		return len(rows) < pageMaxKeys, nil

	case 1: // forward rows that disagree with the index (their keys name subjects: never shown)
		bad, next, done := p.ix.badForwardAfter(w.fwdAfter, pageMaxKeys)
		if next != nil {
			w.fwdAfter = next
		}
		for _, chain := range bad {
			if !ValidChainID(chain) {
				w.invalidIndexRow()
				continue
			}
			in, err := inStore(ctx, p, chain)
			if err != nil {
				return false, err
			}
			switch r, known := w.rows[chain]; {
			case in:
				if !w.againSeen[chain] {
					w.againSeen[chain] = true
					w.again = append(w.again, ChainReport{Chain: chain, Class: classOf(chain), Index: IndexMalformed,
						Problems: []string{indexInconsistent}})
				}
			case known:
				if r.Index != IndexMalformed {
					r.Problems = append(r.Problems, indexInconsistent)
				}
				r.Index = IndexMalformed
			default:
				w.invalidIndexRow()
			}
		}
		return done, nil

	case 2: // checkpoint folders of chains the evidence file does not hold
		if w.anchors == nil {
			ok, err := p.f.realDir("anchors")
			switch {
			case errors.Is(err, errNotRealDir):
				w.extra = append(w.extra, ChainReport{Chain: "anchors/", Anomaly: "invalid-folder",
					Problems: []string{fmt.Sprintf("anchors/ is %v", errNotRealDir)}})
				return true, nil
			case err != nil:
				return false, fmt.Errorf("sink: %w", err)
			case !ok:
				return true, nil
			}
			// Held across pages: a handle, not a lock. It must be the folder just
			// inspected (a symlink swapped in meanwhile is refused).
			before, err := p.f.root.Lstat("anchors")
			if err != nil {
				return false, fmt.Errorf("sink: %w", err)
			}
			if beforeAnchorsOpen != nil {
				beforeAnchorsOpen()
			}
			if w.anchors, err = p.f.root.Open("anchors"); err != nil {
				// os.Root refuses a symlink leading out of the sink: a finding,
				// like any other anchors/ that is not a real folder.
				w.anchors = nil
				w.extra = append(w.extra, ChainReport{Chain: "anchors/", Anomaly: "invalid-folder",
					Problems: []string{"anchors/ could not be opened as a folder inside the sink"}})
				return true, nil
			}
			if after, err := w.anchors.Stat(); err != nil || !os.SameFile(before, after) {
				w.closeAnchors()
				w.extra = append(w.extra, ChainReport{Chain: "anchors/", Anomaly: "invalid-folder",
					Problems: []string{"anchors/ changed while it was being read"}})
				return true, nil
			}
		}
		ents, err := w.anchors.ReadDir(pageMaxKeys)
		for _, d := range ents {
			if !ValidChainID(d.Name()) {
				// Never shown: a folder name could hold anything.
				w.invalidAnchors++
				w.extra = append(w.extra, ChainReport{Chain: fmt.Sprintf("<invalid anchors folder #%d>", w.invalidAnchors),
					Anomaly: "removed", Problems: []string{"anchors/ holds a folder named with an id this sink never mints"}})
				continue
			}
			in, err := inStore(ctx, p, d.Name())
			if err != nil {
				return false, err
			}
			if in {
				continue
			}
			// Checkpoints are written only for chains with entries: whatever the
			// index says, entries were removed.
			cr := w.rowFor(d.Name())
			cr.Anomaly = "removed"
			cr.Problems = append(cr.Problems, "anchors/ has checkpoints for this chain, but the "+
				"evidence file has no entries for it: the chain was REMOVED")
		}
		if err != nil || len(ents) < pageMaxKeys {
			w.closeAnchors()
			if err != nil && !errors.Is(err, io.EOF) {
				return false, fmt.Errorf("sink: %w", err)
			}
			return true, nil
		}
		return false, nil

	case 3: // secrets rows keyed off the layout (counted)
		if p.sec == nil {
			return true, nil
		}
		n, cur, done, err := p.sec.malformedKeysAfter(w.mal, pageMaxKeys)
		if err != nil {
			return false, fmt.Errorf("sink: read the secrets file: %w", err)
		}
		w.malCount, w.mal = w.malCount+n, cur
		if done {
			if w.malCount > 0 {
				w.invalidSecrets++
				w.extra = append(w.extra, ChainReport{Chain: fmt.Sprintf("<invalid secrets row #%d>", w.invalidSecrets),
					Anomaly: "removed", Problems: []string{fmt.Sprintf("the secrets file holds %d rows whose key "+
						"this sink never writes; an erasure may not reach them: remove them by hand", w.malCount)}})
			}
			w.malCount, w.mal = 0, keyCursor{}
		}
		return done, nil

	case 4: // secrets rows of chains the evidence file does not hold
		if p.sec == nil {
			return true, nil
		}
		names, err := p.sec.chainsWithRowsAfter(w.secAfter, pageMaxKeys)
		if err != nil {
			return false, fmt.Errorf("sink: read the secrets file: %w", err)
		}
		for i, name := range names {
			w.secAfter = &names[i]
			in, err := inStore(ctx, p, name)
			if err != nil {
				return false, err
			}
			if in {
				continue // its rows were checked with the chain
			}
			if !ValidChainID(name) {
				// Never shown: a crafted key could hold anything.
				w.invalidSecrets++
				w.extra = append(w.extra, ChainReport{Chain: fmt.Sprintf("<invalid secrets row #%d>", w.invalidSecrets),
					Anomaly: "removed", Problems: []string{"the secrets file holds content or nonces under an " +
						"id this sink never mints; remove them by hand"}})
				continue
			}
			cr := w.rowFor(name)
			if cr.Index != IndexOnly && cr.Index != IndexPending {
				cr.Anomaly = "removed"
			}
			cr.Problems = append(cr.Problems, "the secrets file holds content or nonces for this chain, "+
				"but the evidence file has no entries for it: the chain was removed, or a first commit "+
				"stopped before its append; "+remedy(cr.Index))
		}
		return len(names) < pageMaxKeys, nil

	case 5: // a signatures file that is not one this sink writes
		if p.sigErr != nil {
			problem := "the signatures file's signing mode was altered (a value this sink never writes)"
			if p.sig == nil {
				problem = "the signatures file is not one this sink writes (a bucket is missing); " +
					"its record signatures could not be read"
			}
			w.extra = append(w.extra, ChainReport{Chain: "<invalid signatures file>", Anomaly: "invalid-file",
				Problems: []string{problem}})
		}
		return true, nil

	case 6: // signature rows keyed off the layout (counted)
		if p.sig == nil {
			return true, nil
		}
		n, cur, done, err := p.sig.malformedKeysAfter(w.mal, pageMaxKeys)
		if err != nil {
			return false, fmt.Errorf("sink: read the signatures file: %w", err)
		}
		w.malCount, w.mal = w.malCount+n, cur
		if done {
			if w.malCount > 0 {
				w.invalidSigs++
				w.extra = append(w.extra, ChainReport{Chain: fmt.Sprintf("<invalid signatures row #%d>", w.invalidSigs),
					Anomaly: "removed", Problems: []string{fmt.Sprintf("the signatures file holds %d rows whose "+
						"key this sink never writes", w.malCount)}})
			}
			w.malCount, w.mal = 0, keyCursor{}
		}
		return done, nil

	case 7: // signature rows of chains the evidence file does not hold
		if p.sig == nil {
			return true, nil
		}
		names, err := p.sig.chainsWithRowsAfter(w.sigAfter, pageMaxKeys)
		if err != nil {
			return false, fmt.Errorf("sink: read the signatures file: %w", err)
		}
		for i, name := range names {
			w.sigAfter = &names[i]
			if !ValidChainID(name) {
				continue // counted by the malformed-keys stage; never shown
			}
			in, err := inStore(ctx, p, name)
			if err != nil {
				return false, err
			}
			if in {
				continue
			}
			cr := w.rowFor(name)
			if cr.Index == IndexOnly || cr.Index == IndexPending {
				n, err := p.sig.validRowCount(name)
				if err != nil {
					return false, fmt.Errorf("sink: read the signatures file: %w", err)
				}
				cr.OrphanSignatures += n
				continue
			}
			cr.Anomaly = "removed"
			cr.Problems = append(cr.Problems, "the signatures file holds record signatures for this chain, "+
				"but the evidence file has no entries for it: the chain was REMOVED")
		}
		return len(names) < pageMaxKeys, nil
	}
	return true, nil
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
			if entryIDPattern.MatchString(id) { // others are counted by malformedKeys
				sigUnmatched[id] = true
			}
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
		// Nor orphan signatures: a trailing run of them is how an erasure could
		// be reversed after truncation (sink-format §9.3); a benign crash's
		// orphan just waits for a checkpoint.
		if cr.Index == IndexErasedUnanchored && endsErased && len(cr.Problems) == 0 && cr.OrphanSignatures == 0 {
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
	line(t.unknown, "a record signature by a key not trusted for records (a --record-trust key "+
		"missing, or a forgery)", t.firstUnknown)
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
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s has a type this sink never writes",
			e.EntryID))
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
