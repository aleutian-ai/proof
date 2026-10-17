// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/internal/fault"
	"github.com/aleutian-ai/proof/internal/osfile"
	"github.com/aleutian-ai/proof/internal/safebolt"
	"github.com/aleutian-ai/proof/store"
)

// Bucket names. Bolt has no secondary indexes, so each index is its own bucket
// and all of them are written inside one transaction.
var (
	bucketEntries = []byte("entries") // chainID ‖ 0x00 ‖ BE(seq) → Entry
	// bucketByIDLegacy is the file-wide entry-id index that versions up to
	// v0.3.0 kept. It collided across chains and nothing used it, so it was
	// removed; Open deletes it from existing files.
	bucketByIDLegacy = []byte("by_id")
	bucketState      = []byte("state")  // chainID                  → State
	bucketLeases     = []byte("leases") // chainID                  → token
)

// keySep separates the chain id from the sequence number in a composite key.
//
// NUL is sound here because chain ids come from a bounded charset that excludes
// it. Without a separator, ("ab", 1) and ("a", …) could produce overlapping key
// prefixes and one chain's scan would run into another's entries.
const keySep = 0x00

// Store persists chains in a single bbolt file.
//
// # Description
//
// The default adapter. bbolt is a single-file B+tree with one writer, no
// background goroutines, and near-instant open — which matches this workload:
// the chain is inherently single-writer, and the primary deployment is a
// short-lived process that may be spawned and killed many times per session.
//
// # Key encoding — the thing to get right
//
// Entry keys are chainID ‖ 0x00 ‖ big-endian uint64 sequence. The big-endian
// part is not a preference: bbolt iterates in lexicographic byte order, so a
// decimal encoding sorts "10" before "9" and every range scan silently returns
// the wrong entries. See [github.com/aleutian-ai/proof/store] for the port-level
// statement of this requirement.
//
// # Concurrency
//
// Safe for concurrent use; bbolt serialises writers itself. That is also why the
// lease implementation is thin — see Acquire.
//
// # A damaged file
//
// bbolt panics, or faults in its memory map, on a file that is truncated or
// whose pages were overwritten. No method here lets that out: each returns an
// error wrapping [ErrCorrupt] instead, and from the first such error every
// further method on this Store returns it too, without touching the file
// again (see Close).
//
// # Limitations
//
//   - One writer at a time. Open takes an exclusive file lock (a shared one
//     with WithReadOnly), so a second process blocks rather than corrupting.
type Store struct {
	db   *safebolt.DB
	lock *os.File // a writer's hold on path + ".lock"; nil when read-only
}

var _ store.Store = (*Store)(nil)

// DefaultLockTimeout bounds how long Open waits for another process's lock.
//
// bbolt's own default is zero, which waits FOREVER. That is defensible for a
// long-running service and wrong for a command-line tool: `proof commit` against
// a database another process had open produced no output, no error and no exit
// code — it simply hung, with nothing to indicate a lock was the reason.
//
// Five seconds is long enough to ride out a concurrent short write and short
// enough that an operator does not conclude the tool is broken.
const DefaultLockTimeout = 5 * time.Second

// ErrLocked means another process holds the database's file lock.
//
// Distinct from a generic open failure so a caller can tell "wait and retry"
// from "this file is corrupt or unreadable", which call for opposite responses.
var ErrLocked = errors.New("bolt: database is locked by another process")

// ErrCorrupt means the database file is not a well-formed database:
// truncated, overwritten, or not a chain database at all.
//
// It is returned (wrapped) by [Open] when the file fails its check, and by any
// method when the storage layer panicked or faulted reading or writing it. The
// Store is then finished: every later method returns ErrCorrupt as well, and
// Close abandons the file instead of closing it. It is the same value the sink
// reports, so errors.Is matches across both.
var ErrCorrupt = fault.ErrCorrupt

// checked remembers the files Open has already checked in this process.
var checked safebolt.Checker

// config holds Open's options.
type config struct {
	lockTimeout time.Duration
	readOnly    bool
	noFollow    bool
	noCheck     bool
}

// Option configures Open.
type Option func(*config)

// WithLockTimeout sets how long Open waits for another process's lock.
//
// # Description
//
// Zero means wait indefinitely — bbolt's own default, and the behaviour before
// [DefaultLockTimeout] existed. Pass it deliberately if a caller genuinely
// prefers to block, such as a daemon that has nothing else to do.
//
// # Inputs
//
//   - d: how long to wait; 0 waits forever
//
// # Outputs
//
//   - Option: to pass to [Open]
//
// # Example
//
//	s, err := bolt.Open(path, bolt.WithLockTimeout(30*time.Second))
//
// # Limitations
//
//   - Bounds the LOCK wait only. It is not a deadline for the open itself.
//
// # Assumptions
//
//   - The caller would rather be told about contention than wait through it.
func WithLockTimeout(d time.Duration) Option {
	return func(c *config) { c.lockTimeout = d }
}

// WithReadOnly opens an existing database for reading only.
//
// # Description
//
// Takes a SHARED lock, so several readers may open the file at once, and
// changes nothing: no buckets are created, no leases cleared, no legacy index
// removed. A verifier must not modify the evidence it checks. Every write
// method on the returned Store fails.
//
// # Outputs
//
//   - Option: to pass to [Open]
//
// # Example
//
//	s, err := bolt.Open(path, bolt.WithReadOnly())
//
// # Limitations
//
//   - The file must exist. A file without the chain buckets is refused rather
//     than read, so a foreign bbolt file cannot panic a reader.
//   - Waits for a writer holding the exclusive lock, like any open.
func WithReadOnly() Option {
	return func(c *config) { c.readOnly = true }
}

// WithNoFollow refuses to open path through a symlink, or anything but a
// regular file.
//
// # Description
//
// bbolt opens its file by path and follows symlinks, so a symlink planted (or
// swapped in after a caller's own check) makes it read or write wherever the
// link points. With this option the file is opened with O_NOFOLLOW and
// O_NONBLOCK, and the OPENED handle must be a regular file: there is no window
// between a check and the open.
//
// # Outputs
//
//   - Option: to pass to [Open]
//
// # Example
//
//	s, err := bolt.Open(path, bolt.WithNoFollow())
//
// # Limitations
//
//   - Unix only (O_NOFOLLOW), like the rest of proof's file handling.
//   - Only the final path component: a symlinked parent folder is followed.
//
// # Assumptions
//
//   - The caller does not intend path to be a symlink.
func WithNoFollow() Option {
	return func(c *config) { c.noFollow = true }
}

// WithoutCheck skips the check Open makes before it first opens a file for
// writing.
//
// # Description
//
// The first time a process opens an existing file for writing, Open reads it
// through once, read-only, and refuses it with [ErrCorrupt] if it is damaged:
// a clean refusal before anything is written. The check takes time linear in
// the file (about 0.1 s per GiB once the file is in the page cache; a first
// read from disk takes as long as the disk does). Skipping it is safe: a
// damaged file is then reported by the first method that reads the damage,
// also as ErrCorrupt.
//
// # Outputs
//
//   - Option: to pass to [Open]
//
// # Example
//
//	s, err := bolt.Open(path, bolt.WithoutCheck())
//
// # Limitations
//
//   - Without the check, a write can fail part-way on a damaged file, and
//     whether its transaction reached the disk is then not known.
//
// # Assumptions
//
//   - The caller checks the file some other way, or prefers the faster open.
func WithoutCheck() Option {
	return func(c *config) { c.noCheck = true }
}

// openRegularNoFollow is os.OpenFile that never follows a symlink and refuses
// anything but a regular file, checked on the opened handle.
func openRegularNoFollow(path string, flag int, mode os.FileMode) (*os.File, error) {
	f, err := osfile.OpenNoFollow(path, flag|osfile.NonBlock, mode)
	if err != nil {
		return nil, fmt.Errorf("%w (a symlink is never followed)", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file; refusing to open it", path)
	}
	return f, nil
}

// Open opens or creates a chain database at path.
//
// # Inputs
//
//   - path: file path; created if absent, along with the buckets
//   - opts: see [WithLockTimeout]
//
// # Outputs
//
//   - *Store: ready for use; the caller must Close it
//   - error: [ErrLocked] when another process holds the file lock; an error
//     wrapping [ErrCorrupt] when the file is damaged; or if the file cannot be
//     opened or the buckets cannot be created
//
// # Example
//
//	s, err := bolt.Open("chain.db")
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
//
// # Limitations
//
//   - Waits [DefaultLockTimeout] for a contended lock and then fails. Pass
//     WithLockTimeout(0) to wait indefinitely instead.
//   - The first open of an existing file for writing reads it through once
//     (see [WithoutCheck]).
func Open(path string, opts ...Option) (*Store, error) {
	cfg := config{lockTimeout: DefaultLockTimeout}
	for _, o := range opts {
		o(&cfg)
	}

	bopts := &bolt.Options{Timeout: cfg.lockTimeout, ReadOnly: cfg.readOnly}
	if cfg.noFollow {
		bopts.OpenFile = openRegularNoFollow
	}
	locked := func(err error) error {
		if errors.Is(err, bolt.ErrTimeout) {
			return fmt.Errorf("%w: %s is held by another process (waited %s). "+
				"Only one process may hold a chain database at a time",
				ErrLocked, path, cfg.lockTimeout)
		}
		return fmt.Errorf("bolt: open %s: %w", path, err)
	}
	// A writer holds the database's lock file as well as bbolt's lock on the
	// database: a lock on the database itself cannot span CompactFile's rename
	// of a fresh copy over it, and a writer that opened the old file then would
	// lose what it wrote. A reader needs neither: what it opened is a consistent
	// file whichever one it is, so read-only use works on read-only media.
	var lock *os.File
	if !cfg.readOnly {
		var err error
		if lock, err = safebolt.LockFile(path, true, cfg.lockTimeout); err != nil {
			if errors.Is(err, safebolt.ErrLockHeld) {
				return nil, locked(bolt.ErrTimeout)
			}
			return nil, fmt.Errorf("bolt: open %s: %w", path, err)
		}
	}
	if !cfg.readOnly && !cfg.noCheck {
		// Before the first write to this file in this process: read it through.
		if err := checked.Once(path, bopts); err != nil {
			safebolt.UnlockFile(lock)
			return nil, locked(err)
		}
	}
	db, err := safebolt.Open(path, 0o600, bopts)
	if err != nil {
		safebolt.UnlockFile(lock)
		return nil, locked(err)
	}
	if cfg.readOnly {
		// Every read method dereferences these buckets. Refuse a file that lacks
		// them instead of letting the first read panic on a nil bucket.
		err := db.View(func(tx *bolt.Tx) error {
			for _, b := range [][]byte{bucketEntries, bucketState} {
				if tx.Bucket(b) == nil {
					return fmt.Errorf("no %s bucket: not a proof chain database", b)
				}
			}
			return nil
		})
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("bolt: open %s: %w", path, err)
		}
		return &Store{db: db}, nil
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketEntries, bucketState, bucketLeases} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		// Clear every stored lease. This process now holds bbolt's EXCLUSIVE file
		// lock, so no other live process can be mid-append: any lease still in
		// the file was left by a writer that died. Leaving it would block that
		// chain forever — and MCP clients routinely kill their server processes.
		//
		// Clearing is safe because nothing depends on the dead writer's progress:
		// WriteBatch is one atomic transaction, and the next append reads the
		// tail from the entries actually stored (ReadTail), never from saved state.
		// Drop the removed entry-id index from files written before it went.
		// It is derived data, so nothing is lost.
		if err := tx.DeleteBucket(bucketByIDLegacy); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return fmt.Errorf("remove legacy id index: %w", err)
		}
		if err := tx.DeleteBucket(bucketLeases); err != nil {
			return fmt.Errorf("clear stale leases: %w", err)
		}
		if _, err := tx.CreateBucket(bucketLeases); err != nil {
			return fmt.Errorf("recreate leases bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		safebolt.UnlockFile(lock)
		return nil, fmt.Errorf("bolt: initialise %s: %w", path, err)
	}
	return &Store{db: db, lock: lock}, nil
}

// Close releases the database and its file lock.
//
// After a method returned [ErrCorrupt] the file is abandoned rather than
// closed: closing it would enter the storage layer again, which may wait for
// good on a lock the failed transaction left held. The file lock is released
// and the descriptor closed, so the file can be opened again; its memory map
// stays until the process exits. Close then returns an error wrapping
// ErrCorrupt.
func (s *Store) Close() error {
	err := s.db.Close()
	safebolt.UnlockFile(s.lock)
	s.lock = nil
	return err
}

// entryKey builds chainID ‖ 0x00 ‖ big-endian uint64(seq).
func entryKey(chainID string, seq int64) []byte {
	k := make([]byte, 0, len(chainID)+1+8)
	k = append(k, chainID...)
	k = append(k, keySep)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(seq))
	return append(k, b[:]...)
}

// chainPrefix is every key belonging to a chain.
func chainPrefix(chainID string) []byte {
	p := make([]byte, 0, len(chainID)+1)
	p = append(p, chainID...)
	return append(p, keySep)
}

// WriteBatch appends entries atomically.
//
// One bolt transaction: the batch commits together or not at all.
func (s *Store) WriteBatch(ctx context.Context, entries []store.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateEntries(entries); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return putEntries(tx, entries) })
}

// validateEntries refuses entries the store could not key or read back.
func validateEntries(entries []store.Entry) error {
	for i, e := range entries {
		if e.ChainID == "" {
			return fmt.Errorf("bolt: entry %d has an empty ChainID", i)
		}
		if e.EntryID == "" && !e.Erased {
			// An erased v4 entry has no id (format-spec §2.0); every other has one.
			return fmt.Errorf("bolt: entry %d has an empty EntryID", i)
		}
		// A negative sequence would sort before every non-negative one under
		// unsigned big-endian encoding, silently corrupting range scans. Reject
		// rather than store something unreadable.
		if e.GlobalSeq < 0 {
			return fmt.Errorf("bolt: entry %d has a negative GlobalSeq (%d)", i, e.GlobalSeq)
		}
		if bytes.IndexByte([]byte(e.ChainID), keySep) >= 0 {
			return fmt.Errorf("bolt: entry %d has a ChainID containing a NUL byte", i)
		}
	}
	return nil
}

// putEntries writes validated entries inside an open write transaction.
func putEntries(tx *bolt.Tx, entries []store.Entry) error {
	be := tx.Bucket(bucketEntries)
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("encode entry %s: %w", e.EntryID, err)
		}
		key := entryKey(e.ChainID, e.GlobalSeq)

		// A write at an occupied position REPLACES it — which is how erasure
		// swaps an entry for its tombstone. Entries are keyed by chain and
		// position only, so the replaced entry's id is gone from both key and
		// value: there is no index in which it could still resolve
		// (format-spec §5.4).
		if err := be.Put(key, raw); err != nil {
			return fmt.Errorf("put entry %s: %w", e.EntryID, err)
		}
	}
	return nil
}

// ReadTail returns the highest-sequence entry's chain hash and sequence.
func (s *Store) ReadTail(ctx context.Context, chainID string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	var t store.Tail
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		t, err = tailOf(tx, chainID)
		return err
	})
	if err != nil {
		return "", 0, fmt.Errorf("bolt: read tail: %w", err)
	}
	if t.Empty {
		return "", 0, store.ErrEmptyChain
	}
	return t.Hash, t.GlobalSeq, nil
}

// tailOf reads a chain's last entry inside an open transaction.
func tailOf(tx *bolt.Tx, chainID string) (store.Tail, error) {
	c := tx.Bucket(bucketEntries).Cursor()
	prefix := chainPrefix(chainID)

	// Seek past the chain's last key, then step back — bolt has no
	// "last key with prefix" primitive.
	end := append(append([]byte(nil), prefix...), 0xFF)
	k, v := c.Seek(end)
	if k == nil {
		k, v = c.Last()
	} else {
		k, v = c.Prev()
	}
	if k == nil || !bytes.HasPrefix(k, prefix) {
		return store.Tail{ChainID: chainID, Empty: true}, nil
	}
	var e store.Entry
	if err := json.Unmarshal(v, &e); err != nil {
		return store.Tail{}, err
	}
	return store.Tail{ChainID: chainID, Hash: e.ChainHash, GlobalSeq: e.GlobalSeq, FormatVersion: e.FormatVersion}, nil
}

// Predecessor returns the entry immediately before startSeq.
func (s *Store) Predecessor(ctx context.Context, chainID string, startSeq int64) (*store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var e store.Entry
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEntries).Cursor()
		prefix := chainPrefix(chainID)

		k, v := c.Seek(entryKey(chainID, startSeq))
		if k == nil {
			k, v = c.Last()
		} else {
			k, v = c.Prev()
		}
		if k == nil || !bytes.HasPrefix(k, prefix) {
			return nil
		}
		found = true
		return json.Unmarshal(v, &e)
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: predecessor: %w", err)
	}
	if !found {
		return nil, store.ErrNotFound
	}
	return &e, nil
}

// Range returns entries in [startSeq, endSeq] ascending, up to limit.
func (s *Store) Range(ctx context.Context, chainID string, startSeq, endSeq int64, limit int) ([]store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if startSeq < 0 {
		startSeq = 0
	}
	var out []store.Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEntries).Cursor()
		prefix := chainPrefix(chainID)
		stop := entryKey(chainID, endSeq)

		for k, v := c.Seek(entryKey(chainID, startSeq)); k != nil; k, v = c.Next() {
			if !bytes.HasPrefix(k, prefix) || bytes.Compare(k, stop) > 0 {
				break
			}
			var e store.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("decode entry: %w", err)
			}
			out = append(out, e)
			if limit > 0 && len(out) == limit {
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: range: %w", err)
	}
	return out, nil
}

// Bounds returns the lowest and highest GlobalSeq present.
func (s *Store) Bounds(ctx context.Context, chainID string) (int64, int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	var min, max int64
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEntries).Cursor()
		prefix := chainPrefix(chainID)

		k, _ := c.Seek(prefix)
		if k == nil || !bytes.HasPrefix(k, prefix) {
			return nil
		}
		found = true
		min = int64(binary.BigEndian.Uint64(k[len(prefix):]))

		max = min
		for ; k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			max = int64(binary.BigEndian.Uint64(k[len(prefix):]))
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("bolt: bounds: %w", err)
	}
	if !found {
		return 0, 0, store.ErrEmptyChain
	}
	return min, max, nil
}

// Chains returns the id of every chain with at least one entry, in byte order.
//
// Not part of the store port: a caller holding one chain never needs it. It is
// for tools that keep many chains in one file and must find all of them from
// the store itself — the only record an attacker cannot quietly edit without
// breaking a chain — rather than from a folder or list kept beside it.
//
// It seeks past each chain rather than walking its entries, so its cost grows
// with the number of chains, not the number of entries.
func (s *Store) Chains(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEntries).Cursor()
		for k, _ := c.First(); k != nil; {
			i := bytes.IndexByte(k, keySep)
			if i < 0 {
				return fmt.Errorf("entry key without a chain separator (%d bytes)", len(k))
			}
			chain := string(k[:i])
			out = append(out, chain)
			// chain ‖ 0x01 sorts after every chain ‖ 0x00 ‖ seq key, and chain ids
			// never contain a NUL, so this lands on the next chain's first entry.
			k, _ = c.Seek(append([]byte(chain), keySep+1))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: chains: %w", err)
	}
	return out, nil
}

// ChainsAfter returns up to limit chain ids that sort after *after (nil
// starts at the first), in order: Chains a page at a time. A pointer, not "",
// marks the start: "" can itself be a chain id in a crafted file.
//
// # Description
//
// One seek, then a walk of at most limit chains, so a caller can release the
// file between pages and resume where it stopped.
//
// # Inputs
//
//   - ctx: checked before reading
//   - after: the last chain id of the previous page; nil for the first page
//   - limit: the most ids to return (at least 1)
//
// # Outputs
//
//   - []string: ids in order; empty when there are no more
//   - error: a read failure, or a malformed key
//
// # Example
//
//	var after *string
//	for {
//	    page, err := s.ChainsAfter(ctx, after, 256)
//	    if err != nil || len(page) == 0 {
//	        break
//	    }
//	    after = &page[len(page)-1]
//	}
//
// # Limitations
//
//   - Chains added meanwhile appear if they sort after the cursor.
//
// # Assumptions
//
//   - Chain ids contain no NUL (as everywhere in this store).
func (s *Store) ChainsAfter(ctx context.Context, after *string, limit int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, fmt.Errorf("bolt: chains after: limit %d is below 1", limit)
	}
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEntries).Cursor()
		var k []byte
		if after == nil {
			k, _ = c.First()
		} else {
			// after ‖ 0x01 sorts after every key of chain `after` itself, and
			// before any longer id it prefixes (those continue with a byte > 0x01).
			k, _ = c.Seek(append([]byte(*after), keySep+1))
		}
		for k != nil && len(out) < limit {
			i := bytes.IndexByte(k, keySep)
			if i < 0 {
				return fmt.Errorf("entry key without a chain separator (%d bytes)", len(k))
			}
			chain := string(k[:i])
			out = append(out, chain)
			k, _ = c.Seek(append([]byte(chain), keySep+1))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: chains after: %w", err)
	}
	return out, nil
}

// GetState returns the chain's head state.
func (s *Store) GetState(ctx context.Context, chainID string) (*store.State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var st store.State
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketState).Get([]byte(chainID))
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &st)
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: get state: %w", err)
	}
	if !found {
		return nil, store.ErrNotFound
	}
	return &st, nil
}

// PutState replaces the chain's head state.
func (s *Store) PutState(ctx context.Context, st *store.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("bolt: PutState called with a nil state")
	}
	return s.db.Update(func(tx *bolt.Tx) error { return putState(tx, *st) })
}

// putState writes a chain's head state inside an open write transaction.
func putState(tx *bolt.Tx, st store.State) error {
	if st.ChainID == "" {
		return fmt.Errorf("bolt: state with an empty ChainID")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("bolt: encode state: %w", err)
	}
	return tx.Bucket(bucketState).Put([]byte(st.ChainID), raw)
}

// Compile-time check: the bolt store can append to several chains atomically.
var _ store.ChainsUpdater = (*Store)(nil)

// UpdateChains appends to several chains in one bbolt write transaction.
//
// # Description
//
// Inside ONE db.Update: refuse if any chain is leased, read every chain's tail
// (in chainIDs order), call fn, then validate and write the entries and head
// states it returns. bbolt runs one write transaction at a time and holds an
// exclusive file lock, so nothing can append between the tail reads and the
// writes. Any error, fn's included, rolls the whole transaction back.
//
// # Inputs
//
//   - ctx: checked before the transaction starts
//   - chainIDs: non-empty, distinct, each a valid chain id (no NUL)
//   - fn: receives the tails in chainIDs order; returns what to write. Every
//     entry and state must belong to one of chainIDs: writing a chain whose
//     tail was not read (and whose lease was not checked) is refused.
//
// # Outputs
//
//   - error: fn's error, unchanged; store.ErrChainLeased (wrapped) when a
//     chain is leased; a validation or write error. Nothing is written on any
//     error.
//
// # Example
//
//	err := st.UpdateChains(ctx, []string{"a", "b"},
//	    func(tails []store.Tail) ([]store.Entry, []store.State, error) {
//	        return link(tails) // the caller's linking
//	    })
//
// # Limitations
//
//   - One transaction holds every chain's new entries in memory; the caller
//     bounds the batch.
//
// # Assumptions
//
//   - fn does not call back into the store (bbolt would deadlock on a nested
//     write transaction).
//   - A panic in fn is the caller's: the transaction rolls back, nothing is
//     written, the Store stays usable, and the panic then continues out of
//     UpdateChains as it was raised. It is never reported as ErrCorrupt.
func (s *Store) UpdateChains(ctx context.Context, chainIDs []string,
	fn func(tails []store.Tail) ([]store.Entry, []store.State, error)) error {
	defer fault.Rethrow()
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(chainIDs) == 0 {
		return fmt.Errorf("bolt: UpdateChains needs at least one chain")
	}
	if fn == nil {
		return fmt.Errorf("bolt: UpdateChains needs a function")
	}
	named := make(map[string]bool, len(chainIDs))
	for i, id := range chainIDs {
		if id == "" || bytes.IndexByte([]byte(id), keySep) >= 0 {
			return fmt.Errorf("bolt: chain %d has an empty id or one containing a NUL byte", i)
		}
		if named[id] {
			return fmt.Errorf("bolt: chain %q appears twice", id)
		}
		named[id] = true
	}
	var fnErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		leases := tx.Bucket(bucketLeases)
		for _, id := range chainIDs {
			if leases.Get([]byte(id)) != nil {
				return fmt.Errorf("bolt: chain %q: %w", id, store.ErrChainLeased)
			}
		}
		tails := make([]store.Tail, len(chainIDs))
		for i, id := range chainIDs {
			t, err := tailOf(tx, id)
			if err != nil {
				return fmt.Errorf("bolt: read tail of %q: %w", id, err)
			}
			tails[i] = t
		}
		var entries []store.Entry
		var states []store.State
		var err error
		// The caller's code, inside the transaction: marked, so a panic in it
		// is not taken for a damaged file.
		fault.Callback(func() { entries, states, err = fn(tails) })
		if err != nil {
			fnErr = err
			return err
		}
		if err := validateEntries(entries); err != nil {
			return err
		}
		// An append, nothing else: no overwrite of history, no gap, no head
		// that no entry produced.
		if err := store.CheckAppend(tails, entries, states); err != nil {
			return err
		}
		if err := putEntries(tx, entries); err != nil {
			return err
		}
		for _, st := range states {
			if err := putState(tx, st); err != nil {
				return err
			}
		}
		return nil
	})
	if fnErr != nil {
		return fnErr
	}
	if err != nil {
		return fmt.Errorf("bolt: update chains: %w", err)
	}
	return nil
}

// Acquire takes the append lease for a chain.
//
// # Why this is thin
//
// bbolt already serialises writers, so within one process two appends cannot
// interleave. The lease is still implemented because the CONTRACT is what
// callers rely on — a chain has one appender at a time — and because the token
// makes an accidental cross-release impossible.
//
// Stored in a bucket, but it does NOT survive a reopen: Open clears every lease,
// because holding the exclusive file lock proves no other writer is alive. A
// lease left by a crashed process used to stay held forever and block its chain.
func (s *Store) Acquire(ctx context.Context, chainID string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", false, fmt.Errorf("bolt: generate lease token: %w", err)
	}
	token := hex.EncodeToString(b[:])

	acquired := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketLeases)
		if bk.Get([]byte(chainID)) != nil {
			return nil // held; contention is not an error
		}
		acquired = true
		return bk.Put([]byte(chainID), []byte(token))
	})
	if err != nil {
		return "", false, fmt.Errorf("bolt: acquire lease: %w", err)
	}
	if !acquired {
		return "", false, nil
	}
	return token, true, nil
}

// Release returns the lease. The token must match the current holder's.
func (s *Store) Release(ctx context.Context, chainID, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketLeases)
		held := bk.Get([]byte(chainID))
		if held == nil {
			return fmt.Errorf("bolt: no lease held for chain")
		}
		if string(held) != token {
			return fmt.Errorf("bolt: lease token does not match the current holder")
		}
		return bk.Delete([]byte(chainID))
	})
}

// formatV4 is chainformat.FormatV4, named here because this package keeps its
// dependencies to bbolt (docs/decisions.md D9) and chainformat brings x/text.
const formatV4 = 4

// ErrNotV4 is returned by [Store.Erase] for an entry that is not v4. A v2 or
// v3 entry is erased by replacing it with a tombstone, which this store does
// not write: v2 and v3 are frozen (format-spec §2.6).
var ErrNotV4 = errors.New("bolt: only a v4 entry is erased in place")

// Erase erases one v4 entry in place.
//
// # Description
//
// In one transaction, the entry at globalSeq loses its EntryID, EntryType,
// ContentHash and Salt and is marked Erased; its GlobalSeq, Timestamp,
// LeafHash and ChainHash are kept, so the chain still verifies, every link
// recomputed (format-spec §5.0). Erasing an erased entry changes nothing.
//
// The removed values are still in the file's free pages until the file is
// rewritten: close the store and call [CompactFile] on its path.
//
// # Inputs
//
//   - ctx: a cancelled context aborts before the write
//   - chainID, globalSeq: the entry
//
// # Outputs
//
//   - store.Entry: the entry as it was BEFORE erasure, so the caller can
//     remove what it holds elsewhere under the old id (a nonce, the content)
//   - error: store.ErrNotFound, ErrNotV4, or a wrapped store error
//
// # Example
//
//	was, err := st.Erase(ctx, "chain-1", 7)
//	// ... st.Close(); bolt.CompactFile(path)
//
// # Limitations
//
//   - Nothing in the chain says who erased the entry, or that they were
//     allowed to (docs/verification-model.md, "Who may erase").
//
// # Assumptions
//
//   - None.
func (s *Store) Erase(ctx context.Context, chainID string, globalSeq int64) (store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return store.Entry{}, err
	}
	var was store.Entry
	err := s.db.Update(func(tx *bolt.Tx) error {
		be := tx.Bucket(bucketEntries)
		key := entryKey(chainID, globalSeq)
		raw := be.Get(key)
		if raw == nil {
			return store.ErrNotFound
		}
		if err := json.Unmarshal(raw, &was); err != nil {
			return fmt.Errorf("bolt: decode entry: %w", err)
		}
		if was.FormatVersion != formatV4 {
			return ErrNotV4
		}
		if was.Erased {
			return nil
		}
		erased := was
		erased.EntryID, erased.EntryType, erased.ContentHash, erased.Salt = "", "", "", ""
		erased.Erased = true
		return putEntries(tx, []store.Entry{erased})
	})
	if err != nil {
		return store.Entry{}, err
	}
	return was, nil
}

// CompactFile rewrites the database at path into a fresh file, so values an
// [Store.Erase] removed are gone from the live file rather than left in its
// free pages (bbolt never zeroes them).
//
// # Description
//
// The store must be closed: the copy takes the file's lock. A symlink is never
// followed. A crash part way leaves the original intact. Only the live file is
// rewritten: not SSD wear-levelled blocks, filesystem snapshots, journals or
// backups.
//
// # Inputs
//
//   - path: the database
//   - opts: WithLockTimeout is honoured; the others do not apply
//
// # Outputs
//
//   - error: ErrLocked if another process holds the file, or from the copy
//
// # Example
//
//	if err := bolt.CompactFile(path); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - As above.
//
// # Assumptions
//
//   - Nothing else writes the file meanwhile.
func CompactFile(path string, opts ...Option) error {
	cfg := config{lockTimeout: DefaultLockTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	// Held from before the copy until after the rename: see Open.
	lock, err := safebolt.LockFile(path, true, cfg.lockTimeout)
	if errors.Is(err, safebolt.ErrLockHeld) {
		return fmt.Errorf("%w: %s is held by another process", ErrLocked, path)
	}
	if err != nil {
		return fmt.Errorf("bolt: compact %s: %w", path, err)
	}
	defer safebolt.UnlockFile(lock)
	err = safebolt.CompactFile(path,
		&bolt.Options{Timeout: cfg.lockTimeout, ReadOnly: true, OpenFile: openRegularNoFollow},
		&bolt.Options{Timeout: cfg.lockTimeout, OpenFile: openRegularNoFollow})
	if errors.Is(err, bolt.ErrTimeout) {
		return fmt.Errorf("%w: %v", ErrLocked, err)
	}
	return err
}
