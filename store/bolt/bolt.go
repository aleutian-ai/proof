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
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/store"
)

// Bucket names. Bolt has no secondary indexes, so each index is its own bucket
// and all of them are written inside one transaction.
var (
	bucketEntries = []byte("entries") // chainID ‖ 0x00 ‖ BE(seq) → Entry
	bucketByID    = []byte("by_id")   // entryID                  → chainID ‖ 0x00 ‖ BE(seq)
	bucketState   = []byte("state")   // chainID                  → State
	bucketLeases  = []byte("leases")  // chainID                  → token
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

// Open opens or creates a chain database at path.
//
// # Inputs
//
//   - path: file path; created if absent, along with the buckets
//
// # Outputs
//
//   - *Store: ready for use; the caller must Close it
//   - error: if the file cannot be opened or the buckets cannot be created
//
// # Example
//
//	s, err := bolt.Open("chain.db")
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("bolt: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketEntries, bucketByID, bucketState, bucketLeases} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
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
// All index buckets are updated inside ONE bolt transaction, so an entry and its
// id index commit together or not at all. A partially applied batch would leave
// an entry that ByID cannot find.
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
		bi := tx.Bucket(bucketByID)
		for _, e := range entries {
			raw, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("encode entry %s: %w", e.EntryID, err)
			}
			key := entryKey(e.ChainID, e.GlobalSeq)

			// A write at an occupied position REPLACES it. If the replacement
			// carries a different id — which erasure does, swapping entry_* for
			// tomb_* — the old id must be dropped from the index.
			//
			// Leaving it would let anyone holding the original id look it up and
			// receive the tombstone, confirming that THAT specific entry was
			// erased. The tombstone's content hash is random precisely to prevent
			// that correlation, so a dangling id would undo the design.
			if existing := be.Get(key); existing != nil {
				var prior store.Entry
				if err := json.Unmarshal(existing, &prior); err != nil {
					return fmt.Errorf("decode entry being replaced at seq %d: %w", e.GlobalSeq, err)
				}
				if prior.EntryID != e.EntryID {
					if err := bi.Delete([]byte(prior.EntryID)); err != nil {
						return fmt.Errorf("drop stale id %s: %w", prior.EntryID, err)
					}
				}
			}

			if err := be.Put(key, raw); err != nil {
				return fmt.Errorf("put entry %s: %w", e.EntryID, err)
			}
			if err := bi.Put([]byte(e.EntryID), key); err != nil {
				return fmt.Errorf("index entry %s: %w", e.EntryID, err)
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

// ByID returns the entry with the given id.
func (s *Store) ByID(ctx context.Context, entryID string) (*store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var e store.Entry
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		key := tx.Bucket(bucketByID).Get([]byte(entryID))
		if key == nil {
			return nil
		}
		raw := tx.Bucket(bucketEntries).Get(key)
		if raw == nil {
			// The id index points at a missing entry: the two buckets are written
			// in one transaction, so this means the file was damaged externally.
			return fmt.Errorf("id index points at a missing entry (database may be corrupt)")
		}
		found = true
		return json.Unmarshal(raw, &e)
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: by id: %w", err)
	}
	if !found {
		return nil, store.ErrNotFound
	}
	return &e, nil
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
// Persisted in a bucket rather than held in memory so the lease survives a
// reopen; a process that crashes mid-append leaves the lease held, which is the
// safe direction to fail.
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
