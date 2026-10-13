// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// RepairSummary reports what Repair removed. Counts only: it names no chain
// and no entry.
type RepairSummary struct {
	// Chains is how many chains had something removed.
	Chains int `json:"chains"`
	// Content and Nonces are the rows removed from the secrets file: rows that
	// matched no entry of their chain.
	Content int `json:"content_rows"`
	Nonces  int `json:"nonce_rows"`
	// Sources is the source positions removed: positions no entry stands at.
	Sources int `json:"source_positions"`
	// Signatures is the record signature rows removed: signatures of no entry.
	Signatures int `json:"signature_rows"`
	// Skipped is how many chains have such rows and were left alone, because
	// something says they may not be a crashed commit's, or they are another
	// operation's to finish. For any chain: its erasure is pending (`erase
	// --resume` removes them), its checkpoints cannot be read, a checkpoint
	// covers more entries than it holds (entries were removed), its checkpoint
	// series is behind its recorded head, or it cannot be read to its end. For
	// a chain with NO entries, also: the index does not bind it, or it has any
	// checkpoint, a recorded head, or any record signature row (each says the
	// chain may once have held entries). Verify says which.
	Skipped int `json:"skipped_chains"`
}

// RepairOption configures one Repair call.
type RepairOption func(*repairConfig)

type repairConfig struct {
	heads CheckpointHeads
	err   error
}

// RepairHeads gives Repair the checkpoint heads kept outside the folder
// (TrackHeads), as one more witness that a chain once held entries.
//
// # Description
//
// With heads, Repair leaves alone a chain with no entries that has a recorded
// head (it was checkpointed once: its entries were removed, with their
// checkpoints), and a chain whose checkpoint series is shorter than its head
// or differs from it (its checkpoints were removed, so they cannot show how
// many entries it held).
//
// # Inputs
//
//   - h: where heads are kept; nil makes Repair fail. A FileHeads file inside
//     the sink folder is refused.
//
// # Outputs
//
//   - RepairOption: to pass to Repair
//
// # Example
//
//	sum, err := s.Repair(ctx, sink.RepairHeads(sink.FileHeads(path)))
//
// # Limitations
//
//   - Repair never writes h.
//
// # Assumptions
//
//   - h is safe for concurrent use.
func RepairHeads(h CheckpointHeads) RepairOption {
	return func(c *repairConfig) {
		if h == nil {
			c.err = errors.New("sink: RepairHeads needs a CheckpointHeads")
			return
		}
		if v := reflect.ValueOf(h); v.Kind() == reflect.Pointer && v.IsNil() {
			c.err = errors.New("sink: RepairHeads needs a CheckpointHeads (got a nil pointer)")
			return
		}
		c.heads = h
	}
}

// repairer is one Repair run's open files.
type repairer struct {
	s   *Sink
	f   *folder
	st  *boltstore.Store
	sec *secretsStore
	src *sourcesStore
	sig *signaturesStore
	ix  *indexSnapshot
	// heads is nil unless the caller gave them.
	heads CheckpointHeads
	sum   *RepairSummary
}

// Removed is the total number of rows removed.
func (r RepairSummary) Removed() int { return r.Content + r.Nonces + r.Sources + r.Signatures }

// Repair removes what a commit that stopped before its append left behind:
// content, nonce, source and record signature rows that match no entry of
// their chain.
//
// # Description
//
// A commit writes its content and nonces, then its record signatures and
// source positions, then appends (docs/sink-format.md §7). A returned error
// removes them again. A crash in between does not, and neither does a failed
// removal: Verify then reports "stored content or nonce … matches no entry"
// until the subject is erased. Repair removes those rows, holding the folder
// for the whole call, and rewrites the secrets, sources and signatures files
// so the removed content leaves the live files.
//
// For each chain with entries it removes every content and nonce row, source
// position and signature row that no entry of the chain accounts for. For a
// chain the index binds but which has no entries yet (a first commit that
// stopped), it removes its content, nonces and source positions and keeps the
// index row, which the next commit of the pair uses.
//
// On a chain WITH entries, orphan signature rows go too, although Verify counts
// one only as a note: a folder cannot tell a crashed commit's from a truncated
// chain's, and that is equally true of the content rows. Left behind, a
// trailing run of orphan signatures is what could stand in for removed entries
// (§9.3), and while any exists an erasure is not accepted on its record
// signature alone.
//
// Rows that match no entry are also what REMOVING entries leaves. Repair has
// no proof that a row never belonged to a committed entry, so it deletes
// nothing for a chain when anything it can see says the chain held more than
// it does now: a checkpoint, a recorded head (RepairHeads), or, for a chain
// with no entries at all, any signature row. On a signing sink a first commit
// that stopped is therefore left alone (its signatures were stored before its
// append): commit the pair again, and what the first attempt left is then
// removed like any other leftover. A chain whose erasure is pending is left to
// `erase --resume`. See RepairSummary.Skipped.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - opts: RepairHeads
//
// # Outputs
//
//   - RepairSummary: counts of what was removed and how many chains were
//     skipped
//   - error: the folder is not a sink, is busy (ErrBusy) or damaged
//     (ErrCorrupt), or a file could not be read, written or rewritten. Rows
//     removed before the error stay removed; running it again is safe.
//
// # Example
//
//	sum, err := s.Repair(ctx)
//	if err != nil {
//	    return err
//	}
//	log.Printf("removed %d leftover rows", sum.Removed())
//
// # Limitations
//
//   - What it deletes cannot be brought back. Rows that match no entry are
//     also what is left when entries are REMOVED from the end of a chain no
//     checkpoint covers; nothing in the folder tells that from a crash. If
//     entries may have been removed, look before repairing.
//   - It holds the folder for the whole run: writers wait. It holds one
//     chain's entry ids in memory at a time (about 70 bytes an entry).
//   - It does not remove rows keyed outside the sink's layout, or rows of a
//     chain with no index row; Verify reports those, to be removed by hand.
//   - Like erasure, it reaches only the live files.
//
// # Assumptions
//
//   - No commit is part-way in another process: the evidence file's lock
//     ensures it.
func (s *Sink) Repair(ctx context.Context, opts ...RepairOption) (RepairSummary, error) {
	var sum RepairSummary
	var cfg repairConfig
	for _, o := range opts {
		o(&cfg)
		if cfg.err != nil {
			return sum, cfg.err
		}
	}
	if cfg.heads != nil {
		if err := s.headsOutsideFolder(cfg.heads); err != nil {
			return sum, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.openFolder(false)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	if _, err := os.Lstat(s.DBPath()); errors.Is(err, os.ErrNotExist) {
		return sum, fmt.Errorf("sink: %s: %w", s.dir, errNoSink)
	}
	if err := s.preflight(); err != nil {
		return sum, err
	}
	st, sec, err := s.openFiles()
	if err != nil {
		return sum, err
	}
	defer st.Close()
	secOpen := true
	defer func() {
		if secOpen {
			sec.Close()
		}
	}()
	// The other files only if they exist: repairing never creates one.
	var src *sourcesStore
	if !created(s.sourcesPath()) {
		if src, err = openSources(s.sourcesPath(), s.lockTimeout); err != nil {
			return sum, err
		}
	}
	var sig *signaturesStore
	if !created(s.signaturesPath()) {
		if sig, err = openSignatures(s.signaturesPath(), s.lockTimeout); err != nil {
			if src != nil {
				src.Close()
			}
			return sum, err
		}
	}
	closeSide := func() {
		if src != nil {
			src.Close()
			src = nil
		}
		if sig != nil {
			sig.Close()
			sig = nil
		}
	}
	defer closeSide()

	err = func() error {
		subj, err := openSubjectsReadOnly(s.subjectsPath(), s.lockTimeout)
		if err != nil {
			return err
		}
		var ix *indexSnapshot
		if subj != nil {
			defer subj.Close()
			if ix, err = subj.snapshot(); err != nil {
				return err
			}
			defer ix.close()
		}
		r := &repairer{s: s, f: f, st: st, sec: sec, src: src, sig: sig, ix: ix, heads: cfg.heads, sum: &sum}
		// 1. Chains with entries.
		var cursor *string
		for {
			chains, err := st.ChainsAfter(ctx, cursor, pageMaxChains)
			if err != nil {
				return fmt.Errorf("sink: %w", err)
			}
			for i, chain := range chains {
				if err := ctx.Err(); err != nil {
					return err
				}
				cursor = &chains[i]
				if !ValidChainID(chain) {
					continue // not a chain this sink wrote; Verify reports it
				}
				if err := r.chainWithEntries(ctx, chain); err != nil {
					return err
				}
			}
			if len(chains) < pageMaxChains {
				break
			}
		}
		// 2. Chains with rows and no entries: a first commit that stopped.
		return r.chainsWithoutEntries(ctx)
	}()

	// Rewrite the files rows were deleted from, whatever happened: a deleted
	// row stays in a file's free pages until then. Always, as erasure does, so
	// a rewrite an earlier run failed in is redone.
	sec.Close()
	secOpen = false
	closeSide()
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, p := range []string{s.secretsPath(), s.sourcesPath(), s.signaturesPath()} {
		if cerr := s.compactChecked(p); cerr != nil {
			errs = append(errs, fmt.Errorf("sink: rewriting %s failed: %w; the removed rows may still be "+
				"in its free pages: run repair again", filepath.Base(p), cerr))
		}
	}
	return sum, redact(errors.Join(errs...))
}

// chainWithEntries removes one chain's rows that match no entry of it.
func (r *repairer) chainWithEntries(ctx context.Context, chain string) error {
	seqOf := map[string]int64{} // entry id → its sequence
	total := int64(0)
	walkErr := forEachEntry(ctx, r.st, chain, func(e store.Entry) {
		seqOf[e.EntryID] = e.GlobalSeq
		total++
	})
	if errors.Is(walkErr, ErrCorrupt) || (walkErr != nil && ctx.Err() != nil) {
		return walkErr // the file itself, or the caller: nothing more can be done
	}
	if walkErr != nil {
		// This one chain cannot be read to its end. Which rows are its entries'
		// is then unknown: left alone, and the other chains go on.
		r.sum.Skipped++
		return nil
	}
	isEntry := func(id string) bool { _, ok := seqOf[id]; return ok }
	stands := func(p position) (bool, error) {
		seq, ok := seqOf[p.entryID]
		return ok && seq == p.seq, nil
	}
	// What is there to remove? Counted first, so that a chain left alone is
	// reported, and one with nothing to remove costs no write.
	content, nonces, err := r.sec.unmatched(chain, isEntry, false)
	if err != nil {
		return fmt.Errorf("sink: read the secrets file: %w", err)
	}
	sources, sigs := 0, 0
	if r.src != nil {
		if sources, err = r.src.dangling(chain, stands, false); err != nil {
			return fmt.Errorf("sink: read the sources file: %w", err)
		}
	}
	if r.sig != nil {
		if sigs, err = r.sig.unmatched(chain, isEntry, false); err != nil {
			return fmt.Errorf("sink: read the signatures file: %w", err)
		}
	}
	if content+nonces+sources+sigs == 0 {
		return nil
	}
	// An erasure in progress owns every row of the chain: resume removes them.
	row, err := r.ix.state(chain)
	if err != nil {
		return err
	}
	if row == IndexPending {
		r.sum.Skipped++
		return nil
	}
	// Leftovers of a crash, or of entries removed from the chain's end? Those
	// rows are evidence when anything says the chain held more.
	held, err := r.heldMore(ctx, chain, total)
	if err != nil {
		return err
	}
	if held {
		r.sum.Skipped++
		return nil
	}
	return r.remove(chain, isEntry, stands)
}

// heldMore reports whether anything Repair can see says a chain held more
// entries than the total it holds now: a checkpoint series that cannot be
// read, a checkpoint that covers more entries, or a series behind its recorded
// head (checkpoints were removed, so the series cannot say how many it held).
// For a chain with no entries, total is 0 and any checkpoint or head says so.
func (r *repairer) heldMore(ctx context.Context, chain string, total int64) (bool, error) {
	anchors, problem, err := r.f.readAnchors(chain)
	if err != nil {
		return false, err
	}
	if problem != "" {
		return true, nil
	}
	for _, a := range anchors {
		if a.EntryCount > total {
			return true, nil
		}
	}
	if r.heads != nil {
		count, hash, ok, err := r.heads.Head(ctx, chain)
		if err != nil {
			return false, fmt.Errorf("sink: read the checkpoint heads: %w", err)
		}
		if ok && (total == 0 || headProblem(anchors, count, hash) != "") {
			return true, nil
		}
	}
	return false, nil
}

// remove deletes one chain's unmatched rows and adds them to the summary.
func (r *repairer) remove(chain string, isEntry func(string) bool, stands func(position) (bool, error)) error {
	content, nonces, err := r.sec.unmatched(chain, isEntry, true)
	if err != nil {
		return fmt.Errorf("sink: remove leftover content and nonces: %w", err)
	}
	r.sum.Content, r.sum.Nonces = r.sum.Content+content, r.sum.Nonces+nonces
	sources, sigs := 0, 0
	if r.src != nil {
		if sources, err = r.src.dangling(chain, stands, true); err != nil {
			return fmt.Errorf("sink: remove leftover source positions: %w", err)
		}
		r.sum.Sources += sources
	}
	if r.sig != nil {
		if sigs, err = r.sig.unmatched(chain, isEntry, true); err != nil {
			return fmt.Errorf("sink: remove leftover record signatures: %w", err)
		}
		r.sum.Signatures += sigs
	}
	if content+nonces+sources+sigs > 0 {
		r.sum.Chains++
	}
	return nil
}

// chainsWithoutEntries handles every chain that has rows in a side file and no
// entries: removed when the index binds it (a first commit that stopped
// before its append), left alone otherwise.
func (r *repairer) chainsWithoutEntries(ctx context.Context) error {
	seen := map[string]bool{}
	none := func(string) bool { return false }
	nowhere := func(position) (bool, error) { return false, nil }
	one := func(chain string) error {
		if seen[chain] || !ValidChainID(chain) {
			return nil
		}
		_, _, err := r.st.ReadTail(ctx, chain)
		if err == nil {
			return nil // has entries: done above
		}
		if errors.Is(err, ErrCorrupt) {
			return fmt.Errorf("sink: read chain %s: %w", chain, err)
		}
		if !errors.Is(err, store.ErrEmptyChain) {
			return nil // it has entries that cannot be read: counted above, left alone
		}
		seen[chain] = true
		row, err := r.ix.state(chain)
		if err != nil {
			return err
		}
		if row != IndexLive {
			// Pending: `erase --resume` removes them. No row, or a malformed one:
			// the rows of a chain that was removed, or nobody's; never guessed at.
			r.sum.Skipped++
			return nil
		}
		// A chain with no entries and a live row is what a first commit that
		// stopped leaves. It is also what removing every entry of a chain
		// leaves. Nothing proves the first; these each suggest the second.
		held, err := r.heldMore(ctx, chain, 0)
		if err != nil {
			return err
		}
		if !held && r.sig != nil {
			// A signature is stored before the append, so a stopped first commit
			// of a signing sink has them too; so does a chain whose signed
			// entries were removed. Not told apart: kept.
			ids, err := r.sig.rowIDs(chain)
			if err != nil {
				return fmt.Errorf("sink: read the signatures file: %w", err)
			}
			held = len(ids) > 0
		}
		if held {
			r.sum.Skipped++
			return nil
		}
		return r.remove(chain, none, nowhere)
	}
	lists := []func(after *string, limit int) ([]string, error){r.sec.chainsWithRowsAfter}
	if r.src != nil {
		lists = append(lists, r.src.chainsWithRowsAfter)
	}
	if r.sig != nil {
		lists = append(lists, r.sig.chainsWithRowsAfter)
	}
	for _, list := range lists {
		var after *string
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			names, err := list(after, pageMaxKeys)
			if err != nil {
				return fmt.Errorf("sink: read the folder's files: %w", err)
			}
			for i, name := range names {
				after = &names[i]
				if err := one(name); err != nil {
					return err
				}
			}
			if len(names) < pageMaxKeys {
				break
			}
		}
	}
	return nil
}

// RequireRecordSigning puts a sink that holds no entries yet into signing
// mode, so that a first commit without a record signer is refused.
//
// # Description
//
// A sink signs from its first commit, or never: the mode is otherwise set by
// the first commit whose record signatures were stored. A first commit made
// without a signer, by mistake, would therefore make the sink unsigned for
// good. This sets the mode ahead of that commit (it creates the folder, the
// evidence file and the signatures file if needed), so Commit without
// WithRecordSigner returns ErrRecordSignerRequired. `proof sink init` calls it.
//
// # Inputs
//
//   - ctx: checked before writing
//
// # Outputs
//
//   - error: nil when the sink is in signing mode (already, or now).
//     ErrSinkNotSigning when it already holds unsigned entries: its mode is
//     fixed, and nothing was changed. ErrBusy, ErrCorrupt, or a write failure.
//
// # Example
//
//	s, err := sink.Open("sink-data")
//	if err := s.RequireRecordSigning(ctx); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - The mode only guards the writer. Anyone who can delete the signatures
//     file can delete it; whether signatures are required is the verifier's
//     decision (WithRecordTrust).
//   - It cannot be undone through the sink.
//
// # Assumptions
//
//   - The caller means every record of this sink to be signed.
func (s *Sink) RequireRecordSigning(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.openFolder(true)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := s.preflight(); err != nil {
		return err
	}
	// The evidence file first, as every writer: its lock serializes them.
	st, err := s.openStore(false)
	if err != nil {
		return err
	}
	defer st.Close()
	ro, err := openSignaturesReadOnly(s.signaturesPath(), s.lockTimeout)
	if err != nil {
		return err
	}
	if ro != nil {
		signing, err := ro.signing()
		ro.Close()
		if err != nil {
			return err
		}
		if signing {
			return nil
		}
	}
	chains, err := st.ChainsAfter(ctx, nil, 1)
	if err != nil {
		return fmt.Errorf("sink: read the chains: %w", err)
	}
	if len(chains) > 0 {
		return ErrSinkNotSigning
	}
	sig, err := openSignatures(s.signaturesPath(), s.lockTimeout)
	if err != nil {
		return err
	}
	defer sig.Close()
	if err := sig.setSigning(); err != nil {
		return fmt.Errorf("sink: record the signing mode: %w", err)
	}
	return nil
}
