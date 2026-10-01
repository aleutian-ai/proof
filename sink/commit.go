// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	boltstore "github.com/aleutian-ai/proof/store/bolt"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
)

// Commit commits records, each to the chain its key names.
//
// # Description
//
// Every record is validated before any file is touched. Records are then
// grouped by (class, subject), keeping their order. For each record: a salted
// commitment goes on its chain, and the content and nonce go to the secrets file.
// Content and nonces are written, durably, BEFORE the append, and removed again
// if it fails: an entry whose content was never stored could never be opened.
//
// Each file is written ONCE per call, whatever the number of chains: the new
// index rows in one transaction, content and nonces in one, the source positions in
// one, and every chain's entries and head in ONE evidence transaction
// (linker.AppendChains). That evidence transaction is the commit point
// (docs/sink-format.md §7): the records are committed if and only if it
// commits. Everything written before it is preparatory.
//
// Entry ids and timestamps are assigned here, never taken from the records.
// Every entry's chain hash is computed here first and pinned on the append
// (linker ExpectChainHash): the entries land exactly where predicted, or not at
// all. A sink opened WithRecordSigner also signs every record against that
// prediction, verifies each signature, and writes them (evidence.db.signatures,
// one durable transaction) before the append; a signer failure writes nothing.
//
// A record with a Source is committed at most once per chain, across calls and
// crashes: its position is recorded (in evidence.db.sources) before the append,
// and checked against the chain on every later Commit of that Source. A crash
// between the two leaves a recorded position that is not on the chain, and the
// record is then committed normally. This is what lets a streaming consumer
// acknowledge after committing without committing a redelivery twice.
//
// # Inputs
//
//   - ctx: honoured by record signing and the append. With a remote record
//     signer, give it a deadline: the call holds the sink's files until every
//     signature it started has returned.
//   - records: 1 to MaxBatch records
//
// # Outputs
//
//   - []Outcome: nil, or exactly one per record in the order given (see
//     Outcome). Nil when nothing was attempted: a bad record count, an invalid
//     record, or the files could not be opened. Otherwise non-nil, and on an
//     error none is Committed.
//   - error: on ANY returned error no record is committed, and the call leaves
//     nothing new behind: its content, nonces, source positions and new index
//     rows are removed (a cleanup failure is joined to the error). The one
//     exception is an append whose outcome could not be checked: then nothing
//     is removed, all of it erasable. Errors never name a chain (a chain id
//     beside the caller's records would be a row of the secret index); they
//     still unwrap to their cause. The kinds:
//   - *RecordError: an invalid record.
//   - *PairError: one (class, subject) pair's own stored state failed (an
//     inconsistent index row, an index that re-links an erased chain, a
//     chain id that could not be minted). Records names that pair's records:
//     set them aside and retry the rest.
//   - ErrBusy: another process holds the folder.
//   - ErrRecordSignerRequired, ErrSinkNotSigning: this Sink's signing does not
//     match the sink's mode (WithRecordSigner). Configuration: do not retry.
//   - A record signer failure: nothing was written; retry when it recovers.
//   - Anything else: a write failed; retry the call.
//
// # Example
//
//	out, err := s.Commit(ctx, recs)
//	for i, m := range msgs {
//	    if out != nil && out[i].Committed {
//	        m.Ack()
//	    } else {
//	        m.Nak()
//	    }
//	}
//
// # Limitations
//
//   - All-or-none on RETURNED errors, not across a crash: the files are
//     separate, so a process crash or power loss can leave preparatory state
//     (index rows, content, nonces, positions) without the entries. It is
//     recoverable: the next Commit of the same records reuses or recommits it,
//     erasure removes it, and Verify reports leftovers. It is never committed
//     evidence.
//   - A reused Source is taken as the same record (see Record.Source): its
//     outcome is Committed and Duplicate even if its content differs.
//
// # Assumptions
//
//   - Records are validated here; callers need not, but a streaming consumer
//     should (Record.Validate) so one bad record does not fail its batch.
//   - Safe for concurrent use: calls on one Sink queue on its mutex, and other
//     processes on the evidence file's lock.
func (s *Sink) Commit(ctx context.Context, records []Record) ([]Outcome, error) {
	if n := len(records); n == 0 || n > MaxBatch {
		return nil, fmt.Errorf("sink: commit 1 to %d records, got %d", MaxBatch, n)
	}
	type pair struct{ class, subject string }
	var order []pair
	groups := map[pair][]int{} // record indexes, in order
	sourced := false
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return nil, &RecordError{Index: i, Err: err}
		}
		p := pair{r.Class, r.Subject}
		if r.Source != "" {
			sourced = true
		}
		if _, seen := groups[p]; !seen {
			order = append(order, p)
		}
		groups[p] = append(groups[p], i)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The first Commit creates the folder; nothing else does.
	f, err := s.openFolder(true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, sec, err := s.openFiles()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	defer sec.Close()
	// Opened only when needed, so a sink that never sees a Source has no
	// sources file.
	var src *sourcesStore
	if sourced {
		if src, err = openSources(s.sourcesPath(), s.lockTimeout); err != nil {
			return nil, err
		}
		defer src.Close()
	}
	// The subject index. The evidence file is opened first by every writer, and
	// its exclusive lock is what serializes them: whoever holds it can open the
	// secret files in any order without deadlock (erase opens them in another
	// order). Readers open the evidence file first too (a shared lock), so none
	// can hold a secret file while a writer holds the evidence file.
	subj, err := openSubjects(s.subjectsPath(), s.lockTimeout)
	if err != nil {
		return nil, err
	}
	defer subj.Close()
	// The signing mode, before anything is written (docs/sink-format.md §9.2).
	rs, closeRS, err := s.openRecordSigning(ctx, st)
	if err != nil {
		return nil, err
	}
	defer closeRS()
	l, err := linker.New(st)
	if err != nil {
		return nil, fmt.Errorf("sink: prepare the chains: %w", err)
	}

	out := make([]Outcome, len(records))
	// 1. Every pair's chain: looked up, or minted for a new pair (bound in 2).
	// A failure here is the pair's own stored state: a *PairError naming its
	// records, so a consumer can set those aside and retry the rest.
	chains := make([]string, len(order))
	var fresh []binding
	minted := map[string]bool{}
	for pi, p := range order {
		chain, isNew, err := s.resolvePair(ctx, st, subj, p.class, p.subject, minted)
		if err != nil {
			return out, redact(fmt.Errorf("sink: %w; nothing was committed",
				&PairError{Records: groups[p], Err: err}))
		}
		chains[pi] = chain
		if isNew {
			fresh = append(fresh, binding{subject: p.subject, class: p.class, chain: chain})
			minted[chain] = true
		}
	}
	// 2. The new pairs' index rows, in ONE transaction, BEFORE any of their
	// chains gets an entry: a chain never exists without its row.
	if len(fresh) > 0 {
		if err := subj.bindAll(fresh); err != nil {
			return out, redact(fmt.Errorf("sink: %w; nothing was committed", err))
		}
	}
	// From here, a returned error also undoes step 2: the new pairs' rows and
	// source positions go, so an error leaves nothing new behind.
	fail := func(err error) ([]Outcome, error) {
		if uerr := s.forgetFresh(subj, src, fresh); uerr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup: %w (the new index rows remain; erasing "+
				"their subjects removes them)", uerr))
		}
		return out, redact(fmt.Errorf("sink: %w; nothing was committed", err))
	}
	// 3. Duplicates, per pair.
	dups := make([][]bool, len(order))
	var plans []pairPlan
	for pi, p := range order {
		idx := groups[p]
		recs := make([]Record, len(idx))
		for j, i := range idx {
			recs[j] = records[i]
		}
		keep, dup, err := dropDuplicates(ctx, st, src, chains[pi], recs)
		if err != nil {
			return fail(&PairError{Records: idx, Err: err})
		}
		dups[pi] = dup
		if len(keep) > 0 {
			plans = append(plans, pairPlan{chain: chains[pi], recs: keep})
		}
	}
	// 4. Content, nonces, positions, then every chain in ONE append.
	if len(plans) > 0 {
		var pw positionWriter
		if src != nil {
			pw = src
		}
		var ap chainsAppender = l
		if s.wrapAppender != nil {
			ap = s.wrapAppender(l)
		}
		var sw secretsWriter = sec
		if s.wrapSecrets != nil {
			sw = s.wrapSecrets(sec)
		}
		if err := s.commitPairs(ctx, ap, st, sw, pw, rs, plans); err != nil {
			if errors.Is(err, errUnknownOutcome) || errors.Is(err, errCleanupFailed) {
				// Whether the append landed could not be checked, or this call's
				// content could not be removed: keep the index rows, so that
				// erasing the subject can still reach what is left.
				return out, redact(fmt.Errorf("sink: %w", err))
			}
			return fail(err)
		}
	}
	for pi, p := range order {
		for j, i := range groups[p] {
			out[i].Committed, out[i].Duplicate = true, dups[pi][j]
		}
	}
	return out, nil
}

// forgetFresh undoes this call's new bindings after a returned error: their
// source positions first, then their index rows. If the positions cannot be
// removed the rows stay, so that erasure can still find (and remove) both.
func (s *Sink) forgetFresh(subj *subjectsStore, src *sourcesStore, fresh []binding) error {
	if len(fresh) == 0 {
		return nil
	}
	if src != nil {
		for _, b := range fresh {
			if _, err := src.deleteChain(b.chain); err != nil {
				return fmt.Errorf("remove new chains' source positions: %w", err)
			}
		}
	}
	return subj.unbindAll(fresh)
}

// resolvePair returns the chain of a (class, subject) pair without writing
// anything: the bound chain (isNew false), or a freshly minted, unused id
// (isNew true) that the caller must bind. minted holds ids already minted in
// this call, which are skipped too.
func (s *Sink) resolvePair(ctx context.Context, st *boltstore.Store, subj *subjectsStore,
	class, subject string, minted map[string]bool) (chain string, isNew bool, err error) {
	chain, ok, err := subj.lookup(subject, class)
	if err != nil {
		return "", false, err
	}
	if ok {
		// Never append to an erased history: a live row on a chain that ends with
		// its erasure means the index was restored from before the erasure.
		erased, err := endsWithGenuineErasure(ctx, st, chain)
		if err != nil {
			return "", false, err
		}
		if erased {
			return "", false, errors.New("sink: the subject index re-links an erased chain (restored from " +
				"before an erasure?); run `proof sink erase --resume`")
		}
		return chain, false, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		if chain, err = s.mintChainID(class); err != nil {
			return "", false, err
		}
		if !ValidChainID(chain) || !strings.HasPrefix(chain, class+".") {
			return "", false, fmt.Errorf("sink: minted an invalid chain id for class %s; nothing was bound", class)
		}
		if minted[chain] {
			continue // already minted for another pair in this call
		}
		// 128 random bits do not collide in practice, but a collision would
		// merge two subjects' histories, so it is checked, not assumed: the id
		// must be unused both in the store and in the index.
		_, _, terr := st.ReadTail(ctx, chain)
		if terr == nil {
			continue // the id has entries already: taken
		}
		if !errors.Is(terr, store.ErrEmptyChain) {
			return "", false, fmt.Errorf("sink: check a new chain id is unused: %w", terr)
		}
		taken, err := subj.taken(chain) // live OR pending
		if err != nil {
			return "", false, fmt.Errorf("sink: check a new chain id is unused: %w", err)
		}
		if taken {
			continue
		}
		return chain, true, nil
	}
	return "", false, errors.New("sink: could not mint an unused chain id; the random source is suspect")
}

// dropDuplicates removes records whose Source is already committed on the
// chain, or repeated earlier in the batch. dup[j] reports whether recs[j] was
// dropped.
func dropDuplicates(ctx context.Context, st *boltstore.Store, src *sourcesStore, chain string,
	recs []Record) ([]Record, []bool, error) {
	dup := make([]bool, len(recs))
	if src == nil {
		return recs, dup, nil
	}
	keep := make([]Record, 0, len(recs))
	inBatch := map[string]bool{}
	for j, r := range recs {
		if r.Source == "" {
			keep = append(keep, r)
			continue
		}
		if inBatch[r.Source] {
			dup[j] = true
			continue
		}
		inBatch[r.Source] = true
		p, found, err := src.get(chain, r.Source)
		if err != nil {
			return nil, nil, err
		}
		if found {
			// Recorded. Committed only if the chain holds that entry at that
			// position; otherwise the earlier attempt stopped before its append.
			rows, err := st.Range(ctx, chain, p.seq, p.seq, 1)
			if err != nil {
				return nil, nil, fmt.Errorf("check source position: %w", err)
			}
			if len(rows) == 1 && rows[0].EntryID == p.entryID {
				dup[j] = true
				continue
			}
		}
		keep = append(keep, r)
	}
	return keep, dup, nil
}

// pairPlan is one pair's records still to commit (duplicates dropped), on its
// chain.
type pairPlan struct {
	chain string
	recs  []Record
}

// The writes commitPairs makes, each as the smallest interface it needs.
// Production passes the real stores; a test passes one that fails, to prove that
// whatever failed part-way leaves nothing behind.
type (
	secretsWriter interface {
		putAll(rows map[string]map[string]secret) error
		deleteRows(ids map[string][]string) error
	}
	positionWriter interface {
		putAll(positions map[string]map[string]position) error
	}
	chainsAppender interface {
		AppendChains(ctx context.Context, batches []linker.ChainInputs) ([]linker.Result, error)
	}
	// oneAppender is erasure's append (one chain), as its smallest interface.
	oneAppender interface {
		Append(ctx context.Context, chain string, inputs []linker.Input) (linker.Result, error)
	}
)

// commitPairs writes every pair's content and nonces (ONE durable
// transaction), then, in a signing sink, their record signatures (ONE durable
// transaction), then source positions (one transaction), then appends every
// chain in ONE transaction: the commit point.
//
// Every entry's chain hash is computed here first, from its chain's tail, and
// pinned (linker ExpectChainHash): the append writes exactly these entries at
// exactly these positions, or nothing. In a signing sink each record is signed
// against that prediction, and every signature is verified before anything is
// written: a signer failure writes nothing at all.
//
// Content, nonces and signatures are durable before any entry that commits to
// them exists. If a later step fails, this call's content, nonce and signature
// rows are removed, for EVERY pair. Positions are left: a position with no entry
// behind it is harmless, because the next Commit of that source checks the
// chain and commits it.
func (s *Sink) commitPairs(ctx context.Context, l chainsAppender, st *boltstore.Store,
	sec secretsWriter, src positionWriter, rs *recordSigning, plans []pairPlan) error {
	// One plan per chain: two pairs on one chain means a corrupt index. Refused
	// before anything is written.
	seenChain := make(map[string]bool, len(plans))
	for _, p := range plans {
		if seenChain[p.chain] {
			return fmt.Errorf("two pairs resolve to one chain (the subject index is inconsistent); nothing was written")
		}
		seenChain[p.chain] = true
	}
	// Stamped now, one microsecond apart within a chain: the linker orders a
	// batch by arrival and hashes timestamps at microsecond precision. The
	// chain's sequence, not these, is the authoritative order.
	now := time.Now().UTC().Truncate(time.Microsecond)
	batches := make([]linker.ChainInputs, len(plans))
	next := make([]int64, len(plans))
	rows := map[string]map[string]secret{}
	positions := map[string]map[string]position{}
	var toSign []recordFields

	for k, p := range plans {
		// The sequence and previous hash of the chain's first new entry. Nothing
		// else can append meanwhile: this process holds Sink.mu and the evidence
		// file; and the append refuses anything else (ExpectChainHash).
		n, prev := int64(0), ""
		if tailHash, tail, err := st.ReadTail(ctx, p.chain); err == nil {
			n, prev = tail+1, tailHash
		} else if !errors.Is(err, store.ErrEmptyChain) {
			return fmt.Errorf("chain %s: read tail: %w", p.chain, err)
		}
		next[k] = n
		inputs := make([]linker.Input, len(p.recs))
		rows[p.chain] = map[string]secret{}
		for i, r := range p.recs {
			id, err := newEntryID()
			if err != nil {
				return err
			}
			// One copy, used for both the commitment and the stored row: the
			// caller's slice could change before the row is written.
			content := append([]byte(nil), r.Content...)
			c, nonce, err := commitment.Salted(content)
			if err != nil {
				return err
			}
			rows[p.chain][id] = secret{content: content, nonce: nonce}
			stamp := now.Add(time.Duration(i) * time.Microsecond)
			seq := n + int64(i)
			h, err := chainformat.ComputeChainHashV3(prev, seq, stamp, c)
			if err != nil {
				return fmt.Errorf("predict an entry's chain hash: %w", err)
			}
			inputs[i] = linker.Input{EntryID: id, EntryType: EntryTypeEvent,
				Timestamp: stamp, ContentHash: c, IngestedAt: stamp, ExpectChainHash: h}
			if rs != nil {
				toSign = append(toSign, recordFields{chainID: p.chain, entryID: id, entryType: EntryTypeEvent,
					globalSeq: seq, prevHash: prev, timestamp: stamp, contentHash: c})
			}
			prev = h
			if r.Source != "" {
				// Strictly increasing stamps keep the linker's arrival order equal
				// to this order, so entry i lands at n+i.
				if positions[p.chain] == nil {
					positions[p.chain] = map[string]position{}
				}
				positions[p.chain][r.Source] = position{entryID: id, seq: n + int64(i)}
			}
		}
		batches[k] = linker.ChainInputs{ChainID: p.chain, Inputs: inputs}
	}

	// Record signatures, every one verified under the call's key, BEFORE
	// anything is written: a signer that fails, rotates or misbehaves leaves
	// every file as it was.
	var sigRows map[string]map[string]signatureRow
	if rs != nil {
		sigs, err := signAll(ctx, rs.signer, rs.key, rs.n, toSign)
		if err != nil {
			return fmt.Errorf("sign records: %w", err)
		}
		sigRows = map[string]map[string]signatureRow{}
		for i, f := range toSign {
			if sigRows[f.chainID] == nil {
				sigRows[f.chainID] = map[string]signatureRow{}
			}
			sigRows[f.chainID][f.entryID] = signatureRow{keyID: rs.key.id, sig: sigs[i]}
		}
	}

	// cleanup removes this call's content, nonce and signature rows (one
	// transaction per file). A failure is returned (joined): what it leaves is
	// still erasable, but not gone.
	cleanup := func() error {
		ids := map[string][]string{}
		for chain, byEntry := range rows {
			for id := range byEntry {
				ids[chain] = append(ids[chain], id)
			}
		}
		var errs []error
		if err := sec.deleteRows(ids); err != nil {
			errs = append(errs, err)
		}
		if rs != nil {
			if err := rs.writer.deleteRows(ids); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("cleanup: %w: %w", errCleanupFailed, errors.Join(errs...))
		}
		return nil
	}
	fail := func(err error) error {
		return errors.Join(err, cleanup())
	}

	// Content and nonces: durable BEFORE the entries that commit to them.
	if err := sec.putAll(rows); err != nil {
		// One transaction: nothing was written.
		return fmt.Errorf("store content and nonces: %w", err)
	}
	// Signatures likewise (one transaction; the first sets the sink's mode).
	if rs != nil {
		if err := rs.writer.putAll(sigRows); err != nil {
			return fail(fmt.Errorf("store record signatures: %w", err))
		}
	}
	// Positions go down BEFORE the append. A position with no entry behind it is
	// harmless: the next Commit of that source sees it is not on the chain. An
	// entry with no position is the duplicate this exists to prevent.
	if len(positions) > 0 {
		if err := src.putAll(positions); err != nil {
			return fail(fmt.Errorf("record sources: %w", err))
		}
	}
	_, err := l.AppendChains(ctx, batches)
	if err != nil {
		// An error normally means the transaction rolled back. But a store can
		// report an error after its commit reached the disk; deleting content
		// and nonces then would leave committed entries that can never be
		// opened. So check before cleaning up.
		landed, cerr := appendLanded(ctx, st, batches, next)
		switch {
		case cerr != nil:
			return fmt.Errorf("append: %w; whether it landed could not be checked (%v): %w; "+
				"content and nonces are kept", err, cerr, errUnknownOutcome)
		case !landed:
			// Nothing was appended, so nothing may be left behind.
			return fail(fmt.Errorf("append: %w", err))
		}
		// It landed: the records are committed. Positions were written before
		// the append, as predicted, so there is nothing to repair.
		return nil
	}
	// Every entry's chain hash was pinned, so the entries are exactly where
	// predicted: the positions recorded above are right.
	return nil
}

// errCleanupFailed marks a failed call whose prepared rows (content and
// nonces, or record signatures) could not be removed: the index rows are kept,
// so the subject's erasure still reaches them.
var errCleanupFailed = errors.New("this call's prepared rows could not be removed")

// errUnknownOutcome marks an append whose error left it unclear whether it
// landed: nothing is cleaned up, and nothing is unbound.
var errUnknownOutcome = errors.New("the outcome of the append is unknown")

// appendLanded reports whether every batch's first entry is on its chain at the
// sequence predicted for it: the append committed although it returned an
// error. Entry ids are random, so a match cannot be a coincidence.
func appendLanded(ctx context.Context, st *boltstore.Store, batches []linker.ChainInputs,
	next []int64) (bool, error) {
	landed := 0
	for k, b := range batches {
		rows, err := st.Range(ctx, b.ChainID, next[k], next[k], 1)
		if err != nil {
			return false, err
		}
		if len(rows) == 1 && rows[0].EntryID == b.Inputs[0].EntryID {
			landed++
		}
	}
	switch landed {
	case 0:
		return false, nil
	case len(batches):
		return true, nil
	}
	return false, fmt.Errorf("%d of %d chains hold this call's entries", landed, len(batches))
}
