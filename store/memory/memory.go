// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aleutian-ai/proof/store"
)

// Store keeps a chain entirely in memory.
//
// # Description
//
// A first-class adapter, not a test double. Verifying a chain handed over on
// stdin should not create a file, and a short-lived process has no reason to
// touch disk at all.
//
// It is also the reference the conformance suite was written against, so an
// adapter that disagrees with this one disagrees with the suite.
//
// # Concurrency
//
// Safe for concurrent use. A single mutex guards everything — the workload is a
// handful of operations per append, so finer locking would add failure modes
// without buying throughput.
//
// # Limitations
//
//   - Not durable. Contents are lost when the process exits.
//   - Holds every entry in memory; unsuitable for chains larger than RAM.
type Store struct {
	mu sync.Mutex

	// entries is chainID → entries, kept sorted ascending by GlobalSeq.
	//
	// A slice rather than a map keyed by sequence: Range and Bounds are the hot
	// reads and both want order, so the ordering is maintained on write where it
	// is paid for once.
	entries map[string][]store.Entry

	// state is chainID → head state.
	state map[string]store.State

	// leases is chainID → the token of the current holder.
	leases map[string]string
}

// compile-time proof that this satisfies the whole port.
var _ store.Store = (*Store)(nil)

// New returns an empty in-memory store.
//
// # Example
//
//	s := memory.New()
//	if err := s.WriteBatch(ctx, entries); err != nil {
//	    return err
//	}
func New() *Store {
	return &Store{
		entries: make(map[string][]store.Entry),
		state:   make(map[string]store.State),
		leases:  make(map[string]string),
	}
}

// WriteBatch appends entries, keeping each chain ordered by GlobalSeq.
//
// # Description
//
// Atomic: the batch is validated and applied under one lock, so a caller never
// observes a half-written batch.
//
// # Outputs
//
//   - error: if an entry carries an empty ChainID or EntryID. Linkage and hash
//     correctness are NOT checked — that is chainformat's job, and a store that
//     second-guessed it would be a second implementation of the rules.
func (s *Store) WriteBatch(ctx context.Context, entries []store.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, e := range entries {
		if e.ChainID == "" {
			return fmt.Errorf("memory: entry %d has an empty ChainID", i)
		}
		if e.EntryID == "" {
			return fmt.Errorf("memory: entry %d has an empty EntryID", i)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertLocked(entries)
	return nil
}

// upsertLocked writes entries; the caller holds s.mu.
func (s *Store) upsertLocked(entries []store.Entry) {
	for _, e := range entries {
		// UPSERT by (ChainID, GlobalSeq). Appending unconditionally would leave
		// two rows at one position after an erasure rewrites an entry in place,
		// and a verifier walking both would report a break on an intact chain.
		// bbolt gets this for free from Put; here it is explicit.
		replaced := false
		for i := range s.entries[e.ChainID] {
			if s.entries[e.ChainID][i].GlobalSeq == e.GlobalSeq {
				s.entries[e.ChainID][i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			s.entries[e.ChainID] = append(s.entries[e.ChainID], e)
		}
	}
	for chainID := range s.entries {
		sort.Slice(s.entries[chainID], func(i, j int) bool {
			return s.entries[chainID][i].GlobalSeq < s.entries[chainID][j].GlobalSeq
		})
	}
}

// compile-time proof that this store can append to several chains atomically.
var _ store.ChainsUpdater = (*Store)(nil)

// UpdateChains appends to several chains atomically, under the store's mutex.
//
// # Description
//
// Under s.mu: refuse if any chain is leased, read every chain's tail (in
// chainIDs order), call fn, validate everything it returns, and only then
// write it. Validation runs before the first write, so a bad entry or state
// leaves the store untouched: all or nothing, like the bolt store's single
// transaction.
//
// # Inputs
//
//   - ctx: checked before starting
//   - chainIDs: non-empty and distinct
//   - fn: receives the tails in chainIDs order; every entry and state it
//     returns must belong to one of chainIDs
//
// # Outputs
//
//   - error: fn's error, unchanged; store.ErrChainLeased (wrapped); a
//     validation error. Nothing is written on any error.
//
// # Example
//
//	err := s.UpdateChains(ctx, []string{"a", "b"}, link)
//
// # Limitations
//
//   - Holds the store's mutex while fn runs.
//
// # Assumptions
//
//   - fn does not call back into the store (s.mu is not re-entrant).
func (s *Store) UpdateChains(ctx context.Context, chainIDs []string,
	fn func(tails []store.Tail) ([]store.Entry, []store.State, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(chainIDs) == 0 {
		return fmt.Errorf("memory: UpdateChains needs at least one chain")
	}
	if fn == nil {
		return fmt.Errorf("memory: UpdateChains needs a function")
	}
	named := make(map[string]bool, len(chainIDs))
	for i, id := range chainIDs {
		// NUL is refused as the bolt store refuses it (its keys would collide),
		// so the two adapters accept the same inputs.
		if id == "" || strings.IndexByte(id, 0) >= 0 {
			return fmt.Errorf("memory: chain %d has an empty id or one containing a NUL byte", i)
		}
		if named[id] {
			return fmt.Errorf("memory: chain %q appears twice", id)
		}
		named[id] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range chainIDs {
		if _, held := s.leases[id]; held {
			return fmt.Errorf("memory: chain %q: %w", id, store.ErrChainLeased)
		}
	}
	tails := make([]store.Tail, len(chainIDs))
	for i, id := range chainIDs {
		es := s.entries[id]
		if len(es) == 0 {
			tails[i] = store.Tail{ChainID: id, Empty: true}
			continue
		}
		last := es[len(es)-1]
		tails[i] = store.Tail{ChainID: id, Hash: last.ChainHash, GlobalSeq: last.GlobalSeq}
	}
	entries, states, err := fn(tails)
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.ChainID == "" || e.EntryID == "" {
			return fmt.Errorf("memory: entry %d has an empty ChainID or EntryID", i)
		}
	}
	// An append, nothing else: no overwrite of history, no gap, no head that
	// no entry produced.
	if err := store.CheckAppend(tails, entries, states); err != nil {
		return err
	}
	s.upsertLocked(entries)
	for _, st := range states {
		s.state[st.ChainID] = st
	}
	return nil
}

// ReadTail returns the highest-sequence entry's chain hash and sequence.
func (s *Store) ReadTail(ctx context.Context, chainID string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	es := s.entries[chainID]
	if len(es) == 0 {
		return "", 0, store.ErrEmptyChain
	}
	last := es[len(es)-1]
	return last.ChainHash, last.GlobalSeq, nil
}

// Predecessor returns the entry immediately before startSeq.
func (s *Store) Predecessor(ctx context.Context, chainID string, startSeq int64) (*store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	es := s.entries[chainID]
	var best *store.Entry
	for i := range es {
		if es[i].GlobalSeq < startSeq {
			e := es[i]
			best = &e
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	return best, nil
}

// Range returns entries in [startSeq, endSeq] ascending, up to limit.
func (s *Store) Range(ctx context.Context, chainID string, startSeq, endSeq int64, limit int) ([]store.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []store.Entry
	for _, e := range s.entries[chainID] {
		if e.GlobalSeq < startSeq || e.GlobalSeq > endSeq {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

// Bounds returns the lowest and highest GlobalSeq present.
func (s *Store) Bounds(ctx context.Context, chainID string) (int64, int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	es := s.entries[chainID]
	if len(es) == 0 {
		return 0, 0, store.ErrEmptyChain
	}
	return es[0].GlobalSeq, es[len(es)-1].GlobalSeq, nil
}

// GetState returns the chain's head state.
func (s *Store) GetState(ctx context.Context, chainID string) (*store.State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.state[chainID]
	if !ok {
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
		return fmt.Errorf("memory: PutState called with a nil state")
	}
	if st.ChainID == "" {
		return fmt.Errorf("memory: PutState called with an empty ChainID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[st.ChainID] = *st
	return nil
}

// Acquire takes the append lease for a chain.
//
// Returns acquired=false with a nil error when the lease is held: contention is
// an expected outcome, not a failure.
func (s *Store) Acquire(ctx context.Context, chainID string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, held := s.leases[chainID]; held {
		return "", false, nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", false, fmt.Errorf("memory: generate lease token: %w", err)
	}
	token := hex.EncodeToString(b[:])
	s.leases[chainID] = token
	return token, true, nil
}

// Release returns the lease.
//
// The token must match the current holder's, so a caller that has already lost
// the lease cannot release someone else's.
func (s *Store) Release(ctx context.Context, chainID, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	held, ok := s.leases[chainID]
	if !ok {
		return fmt.Errorf("memory: no lease held for chain")
	}
	if held != token {
		return fmt.Errorf("memory: lease token does not match the current holder")
	}
	delete(s.leases, chainID)
	return nil
}
