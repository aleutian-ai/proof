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
	"time"

	bolt "go.etcd.io/bbolt"

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
// # Limitations
//
//   - One process at a time. bbolt takes an exclusive file lock on Open, so a
//     second process blocks rather than corrupting.
type Store struct {
	db *bolt.DB
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

// config holds Open's options.
type config struct {
	lockTimeout time.Duration
	readOnly    bool
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
//   - error: [ErrLocked] when another process holds the file lock, or if the
//     file cannot be opened or the buckets cannot be created
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
func Open(path string, opts ...Option) (*Store, error) {
	cfg := config{lockTimeout: DefaultLockTimeout}
	for _, o := range opts {
		o(&cfg)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: cfg.lockTimeout, ReadOnly: cfg.readOnly})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: %s is held by another process (waited %s). "+
				"Only one process may hold a chain database at a time",
				ErrLocked, path, cfg.lockTimeout)
		}
		return nil, fmt.Errorf("bolt: open %s: %w", path, err)
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
		return nil, fmt.Errorf("bolt: initialise %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close releases the database and its file lock.
func (s *Store) Close() error { return s.db.Close() }

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
	for i, e := range entries {
		if e.ChainID == "" {
			return fmt.Errorf("bolt: entry %d has an empty ChainID", i)
		}
		if e.EntryID == "" {
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

	return s.db.Update(func(tx *bolt.Tx) error {
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
	})
}

// ReadTail returns the highest-sequence entry's chain hash and sequence.
func (s *Store) ReadTail(ctx context.Context, chainID string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	var e store.Entry
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
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
			return nil
		}
		found = true
		return json.Unmarshal(v, &e)
	})
	if err != nil {
		return "", 0, fmt.Errorf("bolt: read tail: %w", err)
	}
	if !found {
		return "", 0, store.ErrEmptyChain
	}
	return e.ChainHash, e.GlobalSeq, nil
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
	if st.ChainID == "" {
		return fmt.Errorf("bolt: PutState called with an empty ChainID")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("bolt: encode state: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketState).Put([]byte(st.ChainID), raw)
	})
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
