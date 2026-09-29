// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"

	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/verify"
)

// openStore opens the evidence file: read-write for the verbs that append
// (Commit, Erase), read-only (shared lock, nothing created or changed) for the
// ones that only read it (Verify, Checkpoint).
func (s *Sink) openStore(readOnly bool) (*boltstore.Store, error) {
	if err := regularOrAbsent(s.DBPath()); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	opts := []boltstore.Option{boltstore.WithLockTimeout(s.lockTimeout)}
	if readOnly {
		if _, err := os.Lstat(s.DBPath()); errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("sink: %s: %w", s.dir, errNoSink)
		}
		opts = append(opts, boltstore.WithReadOnly())
	}
	st, err := boltstore.Open(s.DBPath(), opts...)
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", s.DBPath(), err))
	}
	return st, nil
}

// openFiles opens the evidence file, then the nonce file, both read-write.
// Always in that order (then the sources file, when needed), so two processes
// cannot each hold one while waiting for the other.
func (s *Sink) openFiles() (*boltstore.Store, *noncestore.Store, error) {
	st, err := s.openStore(false)
	if err != nil {
		return nil, nil, err
	}
	if err := regularOrAbsent(noncestore.PathFor(s.DBPath())); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("sink: %w", err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), s.lockTimeout)
	if err != nil {
		st.Close()
		return nil, nil, busy(fmt.Errorf("sink: %w", err))
	}
	return st, ns, nil
}

// openNoncesReadOnly opens the nonce file for reading, or returns nil when there
// is none (every event then reports as unopenable, which is the truth).
func (s *Sink) openNoncesReadOnly() (*noncestore.Store, error) {
	path := noncestore.PathFor(s.DBPath())
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	ns, err := noncestore.OpenReadOnly(path, s.lockTimeout)
	if err != nil {
		return nil, busy(fmt.Errorf("sink: %w", err))
	}
	return ns, nil
}

// toVerifyEntry is a stored entry in the form verify reads.
func toVerifyEntry(r store.Entry) verify.Entry {
	return verify.Entry{
		EntryID: r.EntryID, EntryType: r.EntryType,
		Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
		FormatVersion: r.FormatVersion, GlobalSeq: r.GlobalSeq,
		ContentHash: r.ContentHash, ChainHash: r.ChainHash,
	}
}

// deleteSources removes a chain's source positions, if a sources file exists.
// It never creates one.
func (s *Sink) deleteSources(chain string) (int, error) {
	if err := regularOrAbsent(s.sourcesPath()); err != nil {
		return 0, err
	}
	if _, err := os.Lstat(s.sourcesPath()); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	src, err := openSources(s.sourcesPath(), s.lockTimeout)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return src.deleteChain(chain)
}

// entryPage is how many entries forEachEntry reads at a time.
const entryPage = 1000

// forEachEntry calls fn for every entry of a chain, in order, reading a page at
// a time so the chain is never held in memory whole.
//
// The next page starts after the last entry's stored global_seq. That value is
// read from the file, so a crafted file could hold one that does not advance,
// and paging would never end: a page that does not move past its start is
// refused instead.
func forEachEntry(ctx context.Context, st *boltstore.Store, chain string, fn func(store.Entry)) error {
	start := int64(0)
	for {
		rows, err := st.Range(ctx, chain, start, 1<<62, entryPage)
		if err != nil {
			return fmt.Errorf("sink: read chain %s: %w", chain, err)
		}
		for _, r := range rows {
			fn(r)
		}
		if len(rows) < entryPage {
			return nil
		}
		next := rows[len(rows)-1].GlobalSeq + 1
		if next <= start {
			return fmt.Errorf("sink: chain %s: an entry's stored global_seq does not match its "+
				"position; the evidence file is corrupt or crafted", chain)
		}
		start = next
	}
}

// compactFile rewrites a bbolt file into a fresh one, so values deleted from it
// are gone from the live file rather than left in its free pages (bbolt never
// zeroes them). The copy is synced and renamed over the original, then the
// folder is synced. A crash before the rename leaves the original intact. A
// missing file is not an error: there is nothing to rewrite.
//
// It reaches the live file only: not SSD wear-levelled blocks, filesystem
// snapshots or journals, or backups.
func compactFile(path string, lockTimeout time.Duration) error {
	if err := regularOrAbsent(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dir, base := filepath.Split(path)
	if err := removeCompactLeftovers(dir, base); err != nil {
		return err
	}
	// A fresh file with an unpredictable name, created exclusively: nothing
	// planted in the folder beforehand can receive the copy.
	tf, err := os.CreateTemp(dir, base+".compact-*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	src, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout, ReadOnly: true})
	if err != nil {
		_ = os.Remove(tmp)
		return busy(err)
	}
	dst, err := bolt.Open(tmp, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		src.Close()
		_ = os.Remove(tmp)
		return err
	}
	err = bolt.Compact(dst, src, 0)
	src.Close()
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncFile(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncFile(filepath.Dir(path))
}

// removeCompactLeftovers removes the temporary copies an interrupted compaction
// of base left in dir: each is a copy of a secret file.
func removeCompactLeftovers(dir, base string) error {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".compact") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove an earlier compaction's leftover: %w", err)
			}
		}
	}
	return nil
}

// syncFile fsyncs a file or folder.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// newEntryID returns a random entry id: assigned here so a record can neither
// collide with an existing entry nor choose an id that means something.
func newEntryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sink: draw entry id: %w", err)
	}
	return "sink-" + hex.EncodeToString(b), nil
}
