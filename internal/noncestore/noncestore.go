// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package noncestore keeps the nonces of salted commitments in a local file
// beside the evidence database.
//
// # Description
//
// A salted commitment can only ever be disclosed with its nonce. When the MCP
// server makes one on an agent's behalf, the agent cannot keep it: a model has
// no durable storage, and a nonce returned into the conversation goes to the
// model provider's transcript, where the operator cannot erase it. So the server
// keeps it here instead, and returns nothing secret.
//
// The file is SEPARATE from the evidence database on purpose. The evidence is
// meant to be shared; nonces are the secret that keeps it unguessable. Erasing
// an item means deleting its nonce here (and its content wherever that lives).
//
// Deleting a key is not enough to erase it: bbolt returns the page to its free
// list and never zeroes it, so the 32 bytes stay in the file. [Forget] deletes
// and then rewrites the file ([Compact]), which is what takes them out of the
// live file.
//
// Keys are chainID ‖ 0x00 ‖ entryID. Chain ids never contain NUL (the store
// refuses them), so a key cannot be read as belonging to another chain.
package noncestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/internal/fault"
	"github.com/aleutian-ai/proof/internal/safebolt"
)

var bucket = []byte("nonces")

// ErrNotFound is returned when no nonce is stored for an entry.
var ErrNotFound = errors.New("noncestore: no nonce stored for that entry")

// ErrNoFile is returned by the functions that never create a nonce file when
// there is none at the path.
var ErrNoFile = errors.New("noncestore: there is no nonce file at that path")

// ErrCorrupt means the nonce file is not a well-formed database: truncated,
// overwritten, or not a nonce file. Every function and method here returns it
// (wrapped) instead of panicking on such a file; a Store that returned it is
// finished, and its Close abandons the file instead of closing it (the file
// lock is released; the memory map stays until the process exits).
var ErrCorrupt = fault.ErrCorrupt

// checked remembers the files Open has already checked in this process.
var checked safebolt.Checker

// Store is an open nonce file. Not safe for use by more than one process at a
// time: bbolt's file lock enforces that.
type Store struct{ db *safebolt.DB }

// PathFor names the nonce file that belongs to an evidence database.
func PathFor(dbPath string) string { return dbPath + ".nonces" }

// Open opens (creating if needed) a nonce file, waiting up to lockTimeout for
// another process to release it. The first time a process opens an existing
// file it is read through once, read-only, and refused with ErrCorrupt if it
// is damaged, before anything is written.
func Open(path string, lockTimeout time.Duration) (*Store, error) {
	opts := &bolt.Options{Timeout: lockTimeout}
	if err := checked.Once(path, opts); err != nil {
		return nil, fmt.Errorf("noncestore: open %s: %w", path, err)
	}
	db, err := safebolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, fmt.Errorf("noncestore: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("noncestore: initialise %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// OpenReadOnly opens an existing nonce file for reading only, under a shared
// lock. Nothing is created or changed. A file without the nonce bucket is
// refused rather than read.
func OpenReadOnly(path string, lockTimeout time.Duration) (*Store, error) {
	db, err := safebolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("noncestore: open %s: %w", path, err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucket) == nil {
			return errors.New("no nonces bucket: not a nonce file")
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("noncestore: open %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close releases the file. A Store that returned ErrCorrupt is abandoned, not
// closed (see ErrCorrupt), and Close then returns an error wrapping it.
func (s *Store) Close() error { return s.db.Close() }

func key(chainID, entryID string) []byte {
	k := make([]byte, 0, len(chainID)+1+len(entryID))
	k = append(k, chainID...)
	k = append(k, 0)
	return append(k, entryID...)
}

// PutBatch stores nonces for a chain's entries in one atomic transaction.
func (s *Store) PutBatch(chainID string, nonces map[string][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for id, n := range nonces {
			if err := b.Put(key(chainID, id), n); err != nil {
				return fmt.Errorf("noncestore: put %s: %w", id, err)
			}
		}
		return nil
	})
}

// PutChains stores the nonces of several chains' entries in ONE atomic
// transaction (chain → entry id → nonce), so a commit touching many chains
// syncs the file once rather than once per chain.
func (s *Store) PutChains(nonces map[string]map[string][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for chainID, byEntry := range nonces {
			for id, n := range byEntry {
				if err := b.Put(key(chainID, id), n); err != nil {
					return fmt.Errorf("noncestore: put %s: %w", id, err)
				}
			}
		}
		return nil
	})
}

// DeleteChains removes the nonces of several chains' entries (chain → entry
// ids) in ONE transaction. A nonce that is not there is not an error.
func (s *Store) DeleteChains(entryIDs map[string][]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for chainID, ids := range entryIDs {
			for _, id := range ids {
				if err := b.Delete(key(chainID, id)); err != nil {
					return fmt.Errorf("noncestore: delete %s: %w", id, err)
				}
			}
		}
		return nil
	})
}

// Get returns an entry's nonce, or ErrNotFound.
func (s *Store) Get(chainID, entryID string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucket).Get(key(chainID, entryID))
		if v == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// Delete removes an entry's nonce. Deleting a nonce that is not there is not an
// error: the outcome the caller wants — no nonce stored — already holds.
func (s *Store) Delete(chainID, entryID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Delete(key(chainID, entryID))
	})
}

// DeleteBatch removes the nonces of many entries in one chain, in one
// transaction. Erasing a whole chain entry by entry would sync the file once per
// entry. As with Delete, a nonce that is not there is not an error.
func (s *Store) DeleteBatch(chainID string, entryIDs []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for _, id := range entryIDs {
			if err := b.Delete(key(chainID, id)); err != nil {
				return fmt.Errorf("noncestore: delete %s: %w", id, err)
			}
		}
		return nil
	})
}

// DeleteChain removes every nonce stored for a chain, in one transaction,
// including nonces whose entries never reached the chain (a commit that stopped
// between storing its nonces and appending). It returns how many were removed.
func (s *Store) DeleteChain(chainID string) (int, error) {
	prefix := key(chainID, "")
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Seek(prefix) {
			if err := c.Delete(); err != nil {
				return fmt.Errorf("noncestore: delete: %w", err)
			}
			n++
		}
		return nil
	})
	return n, err
}

// Forget erases one entry's nonce from the nonce file at path: it deletes the
// key, then rewrites the file so the bytes are not left in a free page.
//
// # Description
//
// The file is never created: a path with no nonce file is [ErrNoFile], so a
// mistyped path cannot report success. An entry with no nonce stored is
// [ErrNotFound], and the file is still rewritten, so a rewrite that an earlier
// call was interrupted in is always finished.
//
// # Inputs
//
//   - path: the nonce file ([PathFor])
//   - chainID, entryID: the entry whose nonce to erase
//   - lockTimeout: how long to wait for another process to release the file
//
// # Outputs
//
//   - error: nil when a nonce was deleted and the file rewritten; ErrNoFile;
//     ErrNotFound (the file was rewritten all the same); or an I/O error
//
// # Example
//
//	err := noncestore.Forget(noncestore.PathFor(db), chain, entry, 5*time.Second)
//
// # Limitations
//
//   - Reaches the live file only: not SSD wear-levelled blocks, filesystem
//     snapshots or journals, or backups.
//
// # Assumptions
//
//   - The caller holds whatever serializes writers of this file (the evidence
//     database's lock): the rewrite replaces the file, and a writer that opened
//     the old one meanwhile would write to a file that no longer has a name.
func Forget(path, chainID, entryID string, lockTimeout time.Duration) error {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNoFile, path)
		}
		return fmt.Errorf("noncestore: %w", err)
	}
	s, err := Open(path, lockTimeout)
	if err != nil {
		return err
	}
	_, getErr := s.Get(chainID, entryID)
	if getErr == nil {
		getErr = s.Delete(chainID, entryID)
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("noncestore: close %s: %w", path, err)
	}
	if getErr != nil && !errors.Is(getErr, ErrNotFound) {
		return getErr
	}
	if err := Compact(path, lockTimeout); err != nil {
		return fmt.Errorf("noncestore: the nonce was deleted, but rewriting %s failed, so its "+
			"bytes may remain in the file; run forget again: %w", path, err)
	}
	return getErr
}

// compactSuffix marks the temporary copy a rewrite makes beside the file.
const compactSuffix = ".compact-"

// Compact rewrites the nonce file at path into a fresh file and renames it over
// the original, so deleted nonces are gone from the live file. bbolt leaves a
// deleted value in a free page and never zeroes it.
//
// # Description
//
// The copy gets an unpredictable name, created exclusively, is synced, renamed
// over the original, and the directory is synced. A crash before the rename
// leaves the original intact. Copies left by an interrupted rewrite are removed
// first: each is a copy of the nonce file. This is the sink's compaction, for
// this file.
//
// # Inputs
//
//   - path: the nonce file; it must exist
//   - lockTimeout: how long to wait for another process to release the file
//
// # Outputs
//
//   - error: nil, or why the file was not rewritten (the original is as it
//     was); ErrCorrupt (wrapped) when the file is damaged
//
// # Example
//
//	err := noncestore.Compact(noncestore.PathFor(db), 5*time.Second)
//
// # Limitations
//
//   - As [Forget]'s.
//
// # Assumptions
//
//   - As [Forget]'s.
func Compact(path string, lockTimeout time.Duration) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	leftovers, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range leftovers {
		if strings.HasPrefix(e.Name(), base+compactSuffix) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove an earlier rewrite's leftover: %w", err)
			}
		}
	}
	tf, err := os.CreateTemp(dir, base+compactSuffix+"*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	src, err := safebolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout, ReadOnly: true})
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	dst, err := safebolt.Open(tmp, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		src.Close()
		_ = os.Remove(tmp)
		return err
	}
	// A damaged original fails the copy (ErrCorrupt); it is left as it was.
	err = safebolt.Compact(dst, src)
	src.Close()
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncPath(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The fresh copy was written from a file that read cleanly, key by key.
	checked.Mark(path)
	return syncPath(dir)
}

// syncPath fsyncs a file or a directory.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
