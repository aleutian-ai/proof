// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aleutian-ai/proof/internal/noncestore"
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
//     readable to its end, a content folder holding only files). If one cannot,
//     the call refuses and nothing changes: the subject is never forgotten by an
//     erasure already known to be stuck.
//  2. Forget: in ONE index transaction, delete the subject's forward rows and
//     mark each of its chains pending erasure, a marker that holds no subject.
//     From here, a new event for the subject gets a NEW chain; it can never
//     rejoin an erased history.
//  3. Complete every pending erasure, this subject's and any an earlier call
//     left: for each chain, a genuine erasure entry (unless the chain already
//     ends with one), then its nonces, source positions and content go, then its
//     index row. A chain that fails stays pending and the others go on.
//  4. Rewrite the nonce, sources and subject-index files, so the deleted values
//     are gone from the live files and not left in free pages. Every call does
//     this, so a rewrite an earlier call missed is always redone.
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
//     erasure, or anyone content or a nonce was disclosed to. Content files are
//     unlinked, not overwritten.
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
	st, ns, err := s.openFiles()
	if err != nil {
		return out, err
	}
	defer st.Close()
	nsOpen := true
	defer func() {
		if nsOpen {
			ns.Close()
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
			if err := s.checkErasable(ctx, f, st, chain); err != nil {
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
			res, err := s.eraseChain(ctx, f, st, ns, l, chain)
			if err == nil {
				if err = subj.clear(chain); err != nil {
					err = fmt.Errorf("sink: chain %s erased, but clearing its index row failed: %w", chain, err)
				}
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
	ns.Close()
	nsOpen = false
	subj.Close()
	subjOpen = false
	incomplete.Compacted = true
	for _, p := range []string{noncestore.PathFor(s.DBPath()), s.sourcesPath(), s.subjectsPath()} {
		if err := s.compact(p, s.lockTimeout); err != nil {
			incomplete.Compacted = false
			errs = append(errs, fmt.Errorf("sink: rewriting %s failed: %w; the deleted values may "+
				"still be in its free pages", filepath.Base(p), err))
		}
	}
	if len(errs) == 0 {
		return out, nil
	}
	incomplete.Err = errors.Join(errs...)
	return out, incomplete
}

// checkErasable runs, read-only, the checks eraseChain makes before it records
// anything: a valid id, a chain that can be read to its end, and a content
// folder holding only regular files.
func (s *Sink) checkErasable(ctx context.Context, f *folder, st *boltstore.Store, chain string) error {
	if !ValidChainID(chain) {
		return fmt.Errorf("sink: the index holds a chain id this sink never mints (%q)", chain)
	}
	if err := forEachEntry(ctx, st, chain, func(store.Entry) {}); err != nil {
		return err
	}
	_, err := contentFiles(f, chain)
	return err
}

// contentFiles lists a chain's content folder (none if it does not exist), and
// refuses one holding anything but regular files: such a folder cannot be
// cleared, so an erasure would fail on every retry.
func contentFiles(f *folder, chain string) ([]os.DirEntry, error) {
	dir := filepath.Join("content", chain)
	files, err := f.list(dir)
	if err != nil {
		return nil, fmt.Errorf("sink: %w; chain %s was not erased", err, chain)
	}
	for _, e := range files {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("sink: %s holds %q, which is not a regular file; remove it "+
				"by hand, then erase again. Chain %s was not erased", dir, e.Name(), chain)
		}
	}
	return files, nil
}

// eraseChain erases one chain: an erasure entry (unless the chain already ends
// with one), then its nonces, source positions and content, keeping erasure
// records. A chain with no entries has its leftovers removed instead. It does
// not compact; the caller does, once, at the end.
//
// It is idempotent, so a crash at any point is repaired by running it again.
func (s *Sink) eraseChain(ctx context.Context, f *folder, st *boltstore.Store, ns *noncestore.Store,
	l *linker.Linker, chain string) (EraseResult, error) {
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
		keep           = map[string][]byte{} // content file name → the exact erasure record it must hold
	)
	err := forEachEntry(ctx, st, chain, func(e store.Entry) {
		genuine := false
		if seen > 0 && e.EntryType == EntryTypeErasure {
			record := erasureRecord(lastSeq)
			if e.ContentHash == erasureHash(record) {
				genuine = true
				keep[e.EntryID+".json"] = record
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
		n, err := s.eraseLeftovers(f, ns, chain)
		if err != nil {
			return EraseResult{}, err
		}
		return EraseResult{Chain: chain, Leftovers: n}, nil
	}

	// Check the content folder BEFORE recording anything: a folder that cannot be
	// cleared (a symlink, a subdirectory) would fail step 3 on every retry, and
	// every retry would add another erasure entry.
	contentDir := filepath.Join("content", chain)
	if _, err := contentFiles(f, chain); err != nil {
		return EraseResult{}, err
	}

	id := lastErasureID
	var record []byte
	if !lastWasErasure {
		// 1. The erasure goes on the record first.
		if id, err = newEntryID(); err != nil {
			return EraseResult{}, err
		}
		record = erasureRecord(lastSeq)
		if err := f.mkdirAll(contentDir, 0o700); err != nil {
			return EraseResult{}, fmt.Errorf("sink: %w; chain %s was not erased", err, chain)
		}
		path := contentName(chain, id)
		if err := f.writeNew(path, record, 0o600); err != nil {
			return EraseResult{}, err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		_, err = l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
			Timestamp: now, ContentHash: erasureHash(record), IngestedAt: now}})
		if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
			_ = f.root.Remove(path)
			return EraseResult{}, fmt.Errorf("sink: record the erasure of %s: %w", chain, err)
		}
		keep[id+".json"] = record
	}

	// 2. Nonces (without one, a commitment can never be opened) and source
	// positions. Every row of the chain, including leftovers of a stopped commit.
	if _, err := ns.DeleteChain(chain); err != nil {
		return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but deleting "+
			"nonces failed: %w", chain, err)
	}
	if _, err := s.deleteSources(chain); err != nil {
		return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but deleting "+
			"source positions failed: %w", chain, err)
	}

	// 3. Content: every file in the chain's folder except genuine erasure
	// records, each kept only if it holds exactly its record (anything else in a
	// record's place may be content). Names come from this folder, never from the
	// evidence file.
	files, err := f.list(contentDir)
	if err != nil {
		return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but listing "+
			"content failed: %w", chain, err)
	}
	for _, e := range files {
		if want, ok := keep[e.Name()]; ok {
			got, _, _, rerr := f.readSmall(filepath.Join(contentDir, e.Name()), int64(len(want)))
			if rerr == nil && bytes.Equal(got, want) {
				continue
			}
		}
		if err := f.root.Remove(filepath.Join(contentDir, e.Name())); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return EraseResult{}, fmt.Errorf("sink: chain %s: the erasure is recorded but deleting "+
				"content failed: %w", chain, err)
		}
	}
	return EraseResult{Chain: chain, Events: events, ErasureEntryID: id}, nil
}

// eraseLeftovers removes what a commit that never reached the chain left
// behind: content files (and then their folder), nonces and source positions.
// It returns how many items it removed.
func (s *Sink) eraseLeftovers(f *folder, ns *noncestore.Store, chain string) (int, error) {
	dir := filepath.Join("content", chain)
	files, err := contentFiles(f, chain)
	if err != nil {
		return 0, err
	}
	n, err := ns.DeleteChain(chain)
	if err != nil {
		return 0, fmt.Errorf("sink: delete leftover nonces: %w", err)
	}
	positions, err := s.deleteSources(chain)
	if err != nil {
		return 0, fmt.Errorf("sink: delete leftover source positions: %w", err)
	}
	n += positions
	for _, e := range files {
		if err := f.root.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return n, fmt.Errorf("sink: delete leftover content: %w", err)
		}
		n++
	}
	// Empty now (or empty all along: a first commit that failed after creating
	// it). Without this, Verify would report a removed chain forever.
	if err := f.root.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return n, fmt.Errorf("sink: remove %s: %w", dir, err)
	}
	return n, nil
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
