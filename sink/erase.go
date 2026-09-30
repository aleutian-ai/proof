// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// EraseSubject erases everything the sink holds about a subject, in every
// class, and then forgets the subject.
//
// # Description
//
// In this order (docs/AleutianChain/subject_index_design.md, "Crash
// consistency"):
//
//  1. Check first: every one of the subject's chains can be erased (a valid id,
//     readable to its end). If one cannot,
//     the call refuses and nothing changes: the subject is never forgotten by an
//     erasure already known to be stuck.
//  2. Forget: in ONE index transaction, delete the subject's forward rows and
//     mark each of its chains pending erasure, a marker that holds no subject.
//     From here, a new event for the subject gets a NEW chain; it can never
//     rejoin an erased history.
//  3. Complete every pending erasure, this subject's and any an earlier call
//     left: for each chain, a genuine erasure entry (unless the chain already
//     ends with one), then its content and nonce rows and source positions go.
//     A chain that fails stays pending and the others go on.
//  4. Rewrite the secrets, sources and subject-index files, so the deleted
//     values are gone from the live files and not left in free pages. Every
//     call does this, so a rewrite an earlier call missed is always redone.
//  5. Only then clear the erased chains' pending markers (and rewrite the
//     subject index once more). A chain stays pending until its content has
//     left the live files, so a crash or a failed rewrite is always resumed.
//
// Afterwards the sink has no memory that it ever held the subject: the chains
// remain, verifiable, under opaque ids that nothing in the folder links to it.
// There is deliberately no suppression list; refusing future data for a person
// is a different operation (remembering them), and belongs upstream.
//
// # Inputs
//
//   - ctx: honoured by each append
//   - subject: as committed; must pass ValidSubject (an empty subject is
//     invalid; ResumeErasures is the call that erases no subject)
//
// # Outputs
//
//   - SubjectErasure: the chains erased, and any pending erasures of earlier,
//     interrupted calls that were completed. No chains means the sink holds
//     nothing for the subject (never committed, or already erased).
//   - error: nil means the erasure recovery invariant holds (ticket _69b):
//     nothing of the subject in the index, every chain erased, every file
//     rewritten. ErrInvalidSubject, or a plain error from a check before
//     forgetting: nothing changed. *ErasureIncompleteError: part done, and what
//     is left is marked pending; ResumeErasures (or any later erasure) finishes
//     it without re-linking the subject.
//
// # Example
//
//	res, err := s.EraseSubject(ctx, "u-81")
//	if err != nil {
//	    return err
//	}
//	log.Printf("erased %d chains", len(res.Erased))
//
// # Limitations
//
//   - Reaches only the live files in this folder. Not backups, filesystem
//     snapshots or journals, SSD wear-levelled blocks, copies made before the
//     erasure, or anyone content or a nonce was disclosed to. Nor process memory
//     or swap, or a rewrite's temporary copy left by a crash (removed by the
//     next erasure). Deleted rows leave the live files when they are rewritten,
//     not when deleted.
//   - The erased chains keep their class, entry counts and timestamps, and each
//     ends with a signed-to-be erasure entry: that a subject of that class was
//     erased, and when, stays visible. Who it was does not.
//   - Correlation leakage, not an erasure failure: the subject's chains are
//     erased within the same moment, so an observer of the evidence file can
//     infer they belonged to one subject. Timestamps are never altered to hide
//     this (they record when the erasure happened). See docs/sink-format.md.
func (s *Sink) EraseSubject(ctx context.Context, subject string) (SubjectErasure, error) {
	if !ValidSubject(subject) {
		return SubjectErasure{}, ErrInvalidSubject
	}
	return s.eraseSubject(ctx, subject, "", false)
}

// EraseSubjectClass erases one class of a subject's evidence and keeps the
// others: "forget their payments, keep their audit trail". The subject stays
// known to the sink while it has evidence in any other class.
//
// # Inputs
//
//   - ctx, subject: as for EraseSubject
//   - class: the one class to erase; must pass ValidClass
//
// # Outputs
//
//   - SubjectErasure: with Class set, so it can never be mistaken for a subject
//     erasure
//   - error: as for EraseSubject
func (s *Sink) EraseSubjectClass(ctx context.Context, subject, class string) (SubjectErasure, error) {
	if !ValidSubject(subject) {
		return SubjectErasure{}, ErrInvalidSubject
	}
	if !ValidClass(class) {
		return SubjectErasure{}, ErrInvalidClass
	}
	return s.eraseSubject(ctx, subject, class, false)
}

// ResumeErasures completes every erasure an earlier call started and did not
// finish (a crash, or an *ErasureIncompleteError), then compacts the secret
// files. EraseSubject does this too, first; this does only that. It never
// links a subject to anything.
//
// # Outputs
//
//   - []EraseResult: the pending chains it completed
//   - error: nil when nothing is left pending and every file was compacted;
//     otherwise an *ErasureIncompleteError (safe to run again), or a plain
//     error when the files could not be opened (nothing changed)
func (s *Sink) ResumeErasures(ctx context.Context) ([]EraseResult, error) {
	res, err := s.eraseSubject(ctx, "", "", true)
	return res.Resumed, err
}

// eraseSubject does the work of the three public calls. With resumeOnly, subject
// and class are ignored; otherwise the caller has validated them.
func (s *Sink) eraseSubject(ctx context.Context, subject, class string, resumeOnly bool) (SubjectErasure, error) {
	out := SubjectErasure{Class: class}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.openFolder(false)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if _, err := os.Lstat(s.DBPath()); errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("sink: %s: %w", s.dir, errNoSink)
	}
	st, sec, err := s.openFiles()
	if err != nil {
		return out, err
	}
	defer st.Close()
	secOpen := true
	defer func() {
		if secOpen {
			sec.Close()
		}
	}()
	subj, err := openSubjects(s.subjectsPath(), s.lockTimeout)
	if err != nil {
		return out, err
	}
	subjOpen := true
	defer func() {
		if subjOpen {
			subj.Close()
		}
	}()
	l, err := linker.New(st)
	if err != nil {
		return out, fmt.Errorf("sink: prepare the chains: %w", err)
	}

	if resumeOnly {
		// A live row on a chain that ends with a genuine erasure (the index was
		// restored from before an erasure, or edited) re-links an erased subject:
		// forget it again, so it is completed below like any pending erasure.
		if err := s.forgetRelinked(ctx, st, subj); err != nil {
			return out, err
		}
	}
	// Interrupted erasures of earlier calls: completed too, reported apart.
	earlier, err := subj.pending()
	if err != nil {
		return out, fmt.Errorf("sink: read pending erasures: %w", err)
	}
	var mine []string
	if !resumeOnly {
		// 1. Check BEFORE forgetting that each of the subject's chains can be
		// erased. A subject is never forgotten by an erasure already known to be
		// stuck: the refusal changes nothing, and the subject stays findable.
		chains, err := subj.chainsOf(subject, class)
		if err != nil {
			return out, err
		}
		for _, chain := range chains {
			if err := s.checkErasable(ctx, st, chain); err != nil {
				return out, fmt.Errorf("%w; the subject was not forgotten and nothing was erased", err)
			}
		}
		// 2. Forget the subject (one transaction).
		if mine, err = subj.forget(subject, class); err != nil {
			return out, fmt.Errorf("sink: forget the subject: %w; nothing was erased", err)
		}
	}

	// 3. Erase each pending chain, then drop its row. A chain that fails stays
	// pending, and the rest go on: one stuck chain never blocks the others.
	incomplete := &ErasureIncompleteError{Forgotten: !resumeOnly}
	var errs []error
	var erased []string // erased in step 3, their pending rows still set
	for _, group := range []struct {
		chains []string
		into   *[]EraseResult
	}{{earlier, &out.Resumed}, {mine, &out.Erased}} {
		for _, chain := range group.chains {
			if !ValidChainID(chain) {
				// Not an id this sink mints, so there is no chain of ours to erase.
				// Left pending, it would fail every later call: remove the row, and
				// report it once.
				if err := subj.clear(chain); err != nil {
					errs = append(errs, err)
					incomplete.Pending = append(incomplete.Pending, chain)
					continue
				}
				errs = append(errs, fmt.Errorf("sink: a pending index row held an id this sink never "+
					"mints (%q); the row was removed", chain))
				continue
			}
			res, err := s.eraseChain(ctx, st, sec, l, chain)
			if err == nil {
				// Its pending row is cleared only AFTER the files are rewritten
				// (step 5): until then the erased values may still be in free
				// pages, and the pending row is what says so, across a crash.
				erased = append(erased, chain)
			}
			if err != nil {
				errs = append(errs, err)
				incomplete.Pending = append(incomplete.Pending, chain)
				continue
			}
			*group.into = append(*group.into, res)
		}
	}

	// 4. Rewrite every file deleted values lived in, on EVERY call, even when
	// nothing was pending or a chain failed: a compaction that an earlier call
	// failed, or crashed in, is then always redone. The evidence file is still
	// held, so no other process can open these meanwhile.
	sec.Close()
	secOpen = false
	subj.Close()
	subjOpen = false
	incomplete.Compacted = true
	for _, p := range []string{s.secretsPath(), s.sourcesPath(), s.subjectsPath()} {
		if err := s.compact(p, s.lockTimeout); err != nil {
			incomplete.Compacted = false
			errs = append(errs, fmt.Errorf("sink: rewriting %s failed: %w; the deleted values may "+
				"still be in its free pages", filepath.Base(p), err))
		}
	}
	// 5. Only now that the deleted values are out of the live files: clear the
	// erased chains' pending rows. If the rewrite failed, they stay pending, so
	// Verify reports them and the next erasure or resume rewrites again.
	if incomplete.Compacted {
		if err := s.clearErased(erased); err != nil {
			errs = append(errs, err)
			incomplete.Pending = append(incomplete.Pending, erased...)
		} else if len(erased) > 0 {
			// The cleared rows held only chain ids (a pending row holds no
			// subject; the subject's rows went, and were rewritten away, above).
			// Rewrite the index once more so those ids leave it too.
			if err := s.compact(s.subjectsPath(), s.lockTimeout); err != nil {
				errs = append(errs, fmt.Errorf("sink: rewriting %s after clearing erased chains failed: "+
					"%w; their (opaque) ids may remain in its free pages", filepath.Base(s.subjectsPath()), err))
			}
		}
	} else {
		incomplete.Pending = append(incomplete.Pending, erased...)
	}
	if len(errs) == 0 {
		return out, nil
	}
	incomplete.Err = errors.Join(errs...)
	return out, incomplete
}

// clearErased removes the pending rows of chains whose erasure is complete and
// whose values are out of the live files.
func (s *Sink) clearErased(chains []string) error {
	if len(chains) == 0 {
		return nil
	}
	subj, err := openSubjects(s.subjectsPath(), s.lockTimeout)
	if err != nil {
		return fmt.Errorf("sink: clear erased chains' index rows: %w", err)
	}
	defer subj.Close()
	for _, chain := range chains {
		if err := subj.clear(chain); err != nil {
			return fmt.Errorf("sink: chain %s erased, but clearing its index row failed: %w", chain, err)
		}
	}
	return nil
}

// forgetRelinked turns every relinked chain's live row into a pending erasure.
func (s *Sink) forgetRelinked(ctx context.Context, st *boltstore.Store, subj *subjectsStore) error {
	live, err := subj.liveChains()
	if err != nil {
		return fmt.Errorf("sink: read the subject index: %w", err)
	}
	for _, chain := range live {
		erased, err := endsWithGenuineErasure(ctx, st, chain)
		if err != nil {
			return err
		}
		if erased {
			if err := subj.forgetChain(chain); err != nil {
				return fmt.Errorf("sink: forget the subject of relinked chain %s: %w", chain, err)
			}
		}
	}
	return nil
}

// endsWithGenuineErasure reports whether a chain's last entry is a genuine
// erasure: of the erasure type, with the hash of the exact record for its
// predecessor's sequence. The same rule as eraseChain and Verify.
func endsWithGenuineErasure(ctx context.Context, st *boltstore.Store, chain string) (bool, error) {
	_, tail, err := st.ReadTail(ctx, chain)
	if errors.Is(err, store.ErrEmptyChain) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sink: read chain %s: %w", chain, err)
	}
	rows, err := st.Range(ctx, chain, tail, tail, 1)
	if err != nil {
		return false, fmt.Errorf("sink: read chain %s's last entry: %w", chain, err)
	}
	if len(rows) != 1 {
		return false, fmt.Errorf("sink: chain %s: its last entry is not where its tail says", chain)
	}
	prev, err := st.Predecessor(ctx, chain, tail)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil // an erasure needs a predecessor
	}
	if err != nil {
		return false, fmt.Errorf("sink: read chain %s: %w", chain, err)
	}
	last := rows[0]
	return last.EntryType == EntryTypeErasure && last.ContentHash == erasureHash(erasureRecord(prev.GlobalSeq)), nil
}

// checkErasable runs, read-only, the checks eraseChain makes before it records
// anything: a valid id, and a chain that can be read to its end.
func (s *Sink) checkErasable(ctx context.Context, st *boltstore.Store, chain string) error {
	if !ValidChainID(chain) {
		return fmt.Errorf("sink: the index holds a chain id this sink never mints (%q)", chain)
	}
	return forEachEntry(ctx, st, chain, func(store.Entry) {})
}

// eraseChain erases one chain: an erasure entry (unless the chain already ends
// with one), then its nonces, source positions and content, keeping erasure
// records. A chain with no entries has its leftovers removed instead. It does
// not compact; the caller does, once, at the end.
//
// It is idempotent, so a crash at any point is repaired by running it again.
func (s *Sink) eraseChain(ctx context.Context, st *boltstore.Store, sec *secretsStore,
	l oneAppender, chain string) (EraseResult, error) {
	if !ValidChainID(chain) {
		return EraseResult{}, fmt.Errorf("sink: the index holds a chain id this sink never mints (%q)", chain)
	}
	// One pass, in pages: the tail's sequence, the erasure records to keep, the
	// entries since the last erasure, and whether the chain already ends with one.
	//
	// An erasure counts only if it is GENUINE: its content_hash is the hash of the
	// exact record for its predecessor's sequence. The entry type alone is not
	// evidence (it is not in the chain hash); an event relabelled as an erasure
	// is an event, and its content goes.
	var (
		seen           int
		lastSeq        int64
		events         int
		lastWasErasure bool
		lastErasureID  string
		keep           = map[string][]byte{} // entry id → the exact erasure record its row must hold
	)
	err := forEachEntry(ctx, st, chain, func(e store.Entry) {
		genuine := false
		if seen > 0 && e.EntryType == EntryTypeErasure {
			record := erasureRecord(lastSeq)
			if e.ContentHash == erasureHash(record) {
				genuine = true
				keep[e.EntryID] = record
			}
		}
		seen++
		lastSeq = e.GlobalSeq
		lastWasErasure = genuine
		if genuine {
			lastErasureID = e.EntryID
			events = 0
		} else {
			events++
		}
	})
	if err != nil {
		return EraseResult{}, err
	}
	if seen == 0 {
		// Nothing reached the chain, but a first commit that stopped before its
		// append can have left content, nonces and positions behind. They are
		// still personal data: remove them. No erasure entry: there is no chain
		// to put it on.
		n, err := s.eraseLeftovers(sec, chain)
		if err != nil {
			return EraseResult{}, err
		}
		return EraseResult{Chain: chain, Leftovers: n}, nil
	}

	id := lastErasureID
	if !lastWasErasure {
		// 1. The erasure goes on the record first: its record row (durable), then
		// the entry.
		if id, err = newEntryID(); err != nil {
			return EraseResult{}, err
		}
		record := erasureRecord(lastSeq)
		if err := sec.putAll(map[string]map[string]secret{chain: {id: {content: record}}}); err != nil {
			return EraseResult{}, fmt.Errorf("sink: store the erasure record of %s: %w; chain %s was not erased",
				chain, err, chain)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		_, err = l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
			Timestamp: now, ContentHash: erasureHash(record), IngestedAt: now}})
		if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
			// A store can report an error after its commit reached the disk:
			// only remove the record if the entry is really not on the chain.
			rows, rerr := st.Range(ctx, chain, lastSeq+1, lastSeq+1, 1)
			if rerr != nil || len(rows) != 1 || rows[0].EntryID != id {
				_ = sec.deleteRows(map[string][]string{chain: {id}})
				return EraseResult{}, fmt.Errorf("sink: record the erasure of %s: %w", chain, err)
			}
		}
		keep[id] = record
	}

	// 2. Nonces (without one, a commitment can never be opened) and content, in
	// ONE transaction: every row of the chain except genuine erasure records,
	// each kept only while it holds exactly its record (anything else in a
	// record's place may be content). Leftovers of a stopped commit go too.
	if _, err := sec.eraseChain(chain, keep); err != nil {
		return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but deleting "+
			"content and nonces failed: %w", chain, err)
	}
	// 3. Source positions.
	if _, err := s.deleteSources(chain); err != nil {
		return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but deleting "+
			"source positions failed: %w", chain, err)
	}
	return EraseResult{Chain: chain, Events: events, ErasureEntryID: id}, nil
}

// eraseLeftovers removes what a commit that never reached the chain left
// behind: content and nonce rows, and source positions. It returns how many it
// removed.
func (s *Sink) eraseLeftovers(sec *secretsStore, chain string) (int, error) {
	n, err := sec.eraseChain(chain, nil)
	if err != nil {
		return 0, fmt.Errorf("sink: delete leftover content and nonces: %w", err)
	}
	positions, err := s.deleteSources(chain)
	if err != nil {
		return n, fmt.Errorf("sink: delete leftover source positions: %w", err)
	}
	return n + positions, nil
}

// erasureDomain prefixes the hash of an erasure record.
//
// Without it an erasure record would be checked by plain SHA-512, and a salted
// commitment IS a plain SHA-512 (of its 115-byte preimage). entry_type is not in
// the chain hash, so a writer could relabel an event as an erasure and present
// that preimage as the "record", and the events before it would pass as erased.
// With the prefix, no record can hash to a commitment.
//
// This closes the confusion without changing AleutianChain v3. A future chain
// format may bind the entry type into the chain preimage directly.
const erasureDomain = "aleutian.sink.erasure.v1:"

// erasureRecord returns the exact bytes of the erasure record for an erasure
// entry whose predecessor has global sequence throughSeq. The bytes are fixed
// (docs/sink-format.md §4): a verifier rebuilds them and compares, so there is
// no JSON parsing, and no serializer choice, anywhere in the check. The
// sequence is a decimal string, as format-spec §2.1 requires outside exports.
func erasureRecord(throughSeq int64) []byte {
	return []byte(`{"erased":"every earlier event on this chain","through_global_seq":"` +
		strconv.FormatInt(throughSeq, 10) + `"}`)
}

// erasureHash is the content_hash of an erasure entry:
// hex(SHA-512(erasureDomain ‖ record)).
func erasureHash(record []byte) string {
	h := sha512.New()
	h.Write([]byte(erasureDomain))
	h.Write(record)
	return hex.EncodeToString(h.Sum(nil))
}
