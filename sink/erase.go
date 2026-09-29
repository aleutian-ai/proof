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

	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
)

// Erase erases every event on one chain, and records that it did.
//
// # Description
//
// In this order:
//
//  1. Commit an erasure entry to the chain (see erasureRecord). Doing this first
//     means a crash part-way leaves a chain that says "erased, but something is
//     still here: run erase again", never one that looks tampered with.
//  2. Delete every nonce of the chain, and every upstream source position
//     recorded for it. Positions would map the erased pseudonym back to its
//     upstream messages. The cost: a redelivery arriving after the erasure is
//     committed again, after the erasure entry, visibly.
//  3. Delete every content file of the chain except erasure records. Steps 2
//     and 3 also catch leftovers of a commit that stopped before its append.
//  4. Rewrite the nonce and sources files, so the deleted values are gone from
//     the live files and not merely unlinked from their B-trees: bbolt never
//     zeroes freed pages.
//
// Afterwards no event before the erasure entry can be opened from this folder,
// and the chain, including its checkpoints, still verifies: it only ever held
// commitments. Events committed to the chain later are unaffected.
//
// # Inputs
//
//   - ctx: honoured by the append
//   - chain: the chain id to erase
//
// # Outputs
//
//   - EraseResult: how many events were erased, and the erasure entry's id
//   - error: the chain id is invalid or has no entries, or a file operation
//     failed. Erase is safe to run again after a failure.
//
// # Limitations
//
//   - Reaches only the live files in this folder. Not backups, filesystem
//     snapshots or journals, SSD wear-levelled blocks, copies made before the
//     erasure, or anyone the content or a nonce was already disclosed to.
//     Content files are unlinked, not overwritten.
//   - The chain id stays: in the chain, in every checkpoint, and in folder names.
//     The erasure entry itself is a signed record that this chain was erased,
//     and when.
func (s *Sink) Erase(ctx context.Context, chain string) (EraseResult, error) {
	if _, err := ChainFor(chain); err != nil {
		return EraseResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.openFolder(false)
	if err != nil {
		return EraseResult{}, err
	}
	defer f.Close()
	if _, err := os.Lstat(s.DBPath()); errors.Is(err, os.ErrNotExist) {
		return EraseResult{}, fmt.Errorf("sink: %s: %w", s.dir, errNoSink)
	}
	st, ns, err := s.openFiles()
	if err != nil {
		return EraseResult{}, err
	}
	defer st.Close()
	nsOpen := true
	defer func() {
		if nsOpen {
			ns.Close()
		}
	}()

	// One pass, in pages, never the whole chain in memory: the tail's sequence,
	// the erasure records to keep, and the events since the last erasure (the
	// ones this erasure newly covers).
	var (
		seen    int
		lastSeq int64
		events  int
		keep    = map[string]bool{} // erasure records stay; ids used only as names to match
	)
	err = forEachEntry(ctx, st, chain, func(e store.Entry) {
		seen++
		lastSeq = e.GlobalSeq
		switch e.EntryType {
		case EntryTypeEvent:
			events++
		case EntryTypeErasure:
			keep[e.EntryID+".json"] = true
			events = 0
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
		ns.Close()
		nsOpen = false
		if err != nil {
			return EraseResult{}, err
		}
		if n == 0 {
			return EraseResult{}, fmt.Errorf("sink: chain %s has no entries and nothing to remove", chain)
		}
		if err := s.compactSecrets(); err != nil {
			return EraseResult{}, err
		}
		return EraseResult{Chain: chain, Leftovers: n}, nil
	}

	// Check the content folder BEFORE recording anything: a folder that cannot be
	// cleared (a symlink, a subdirectory) would fail step 3 on every retry, and
	// every retry would add another erasure entry.
	contentDir := filepath.Join("content", chain)
	files, err := f.list(contentDir)
	if err != nil {
		return EraseResult{}, fmt.Errorf("sink: %w; nothing was erased", err)
	}
	for _, e := range files {
		if !e.Type().IsRegular() {
			return EraseResult{}, fmt.Errorf("sink: %s holds %q, which is not a regular file; remove it "+
				"by hand, then erase again. Nothing was erased", contentDir, e.Name())
		}
	}

	// 1. The erasure goes on the record first.
	id, err := newEntryID()
	if err != nil {
		return EraseResult{}, err
	}
	record := erasureRecord(lastSeq)
	if err := f.mkdirAll(contentDir, 0o700); err != nil {
		return EraseResult{}, fmt.Errorf("sink: %w; nothing was erased", err)
	}
	path := contentName(chain, id)
	if err := f.writeNew(path, record, 0o600); err != nil {
		return EraseResult{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	l, err := linker.New(st)
	if err != nil {
		_ = f.root.Remove(path)
		return EraseResult{}, fmt.Errorf("sink: prepare the chain: %w", err)
	}
	_, err = l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
		Timestamp: now, ContentHash: erasureHash(record), IngestedAt: now}})
	if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
		_ = f.root.Remove(path)
		return EraseResult{}, fmt.Errorf("sink: record the erasure: %w; nothing was erased", err)
	}
	keep[id+".json"] = true

	// 2. Nonces (without one, a commitment can never be opened) and source
	// positions. Every row of the chain, including leftovers of a stopped commit.
	if _, err := ns.DeleteChain(chain); err != nil {
		return EraseResult{}, fmt.Errorf("sink: the erasure is recorded but deleting nonces "+
			"failed: %w; run erase again", err)
	}
	if _, err := s.deleteSources(chain); err != nil {
		return EraseResult{}, fmt.Errorf("sink: the erasure is recorded but deleting source "+
			"positions failed: %w; run erase again", err)
	}

	// 3. Content: every file in the chain's folder except erasure records. Names
	// come from this folder, never from the evidence file.
	files, err = f.list(contentDir)
	if err != nil {
		return EraseResult{}, fmt.Errorf("sink: the erasure is recorded but listing content "+
			"failed: %w; run erase again", err)
	}
	for _, e := range files {
		if keep[e.Name()] {
			continue
		}
		if err := f.root.Remove(filepath.Join(contentDir, e.Name())); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return EraseResult{}, fmt.Errorf("sink: the erasure is recorded but deleting content "+
				"failed: %w; run erase again", err)
		}
	}

	// 4. Rewrite the files the deleted values lived in. The evidence file is
	// still held, so by the lock order no other process can open these two.
	ns.Close()
	nsOpen = false
	if err := s.compactSecrets(); err != nil {
		return EraseResult{}, fmt.Errorf("sink: the erasure is recorded, but %w", err)
	}
	return EraseResult{Chain: chain, Events: events, ErasureEntryID: id}, nil
}

// compactSecrets rewrites the nonce and sources files. The caller holds the
// evidence file, so by the lock order no other process has these open.
func (s *Sink) compactSecrets() error {
	for _, p := range []string{noncestore.PathFor(s.DBPath()), s.sourcesPath()} {
		if err := compactFile(p, s.lockTimeout); err != nil {
			return fmt.Errorf("rewriting %s failed: %w; the deleted values may still be in its "+
				"free pages; run erase again", filepath.Base(p), err)
		}
	}
	return nil
}

// eraseLeftovers removes what a commit that never reached the chain left
// behind: content files (and then their folder), nonces and source positions.
// It returns how many items it removed.
func (s *Sink) eraseLeftovers(f *folder, ns *noncestore.Store, chain string) (int, error) {
	dir := filepath.Join("content", chain)
	files, err := f.list(dir)
	if err != nil {
		return 0, fmt.Errorf("sink: %w; nothing was removed", err)
	}
	for _, e := range files {
		if !e.Type().IsRegular() {
			return 0, fmt.Errorf("sink: %s holds %q, which is not a regular file; remove it by hand. "+
				"Nothing was removed", dir, e.Name())
		}
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
	if len(files) > 0 {
		// Empty now; without it Verify would keep reporting a removed chain.
		if err := f.root.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return n, fmt.Errorf("sink: remove %s: %w", dir, err)
		}
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
