// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// ErrChainBusy is returned when another appender holds the chain's lease.
//
// Contention is an expected outcome rather than a failure: a chain has one
// appender at a time by design. Callers should retry, not treat it as corruption.
var ErrChainBusy = errors.New("linker: chain is busy, another append holds the lease")

// Input is an entry awaiting linkage.
//
// It carries only what the linker cannot derive. Position (run id, sequence
// number, global sequence), linkage (previous hash), and the resulting chain hash
// are all assigned by [Linker.Append].
//
// Note what this type does NOT have. There is no field for a run id, a sequence
// number, or a chain hash, so "the linker never accepts a caller-supplied
// position" is enforced by the type rather than by a validation rule someone can
// relax later. Adding any of those fields would undo that guarantee.
type Input struct {
	// EntryID uniquely identifies this entry. Required, and unique within the
	// batch — duplicates make the batch's order undefined.
	EntryID string

	// EntryType classifies the entry. "tombstone" marks an erased entry; see
	// chainformat.IsTombstone.
	EntryType string

	// Timestamp is the event time. It is hash CONTENT and never an ordering
	// input — see sortInputs. Stored and hashed at the precision given, so pass
	// the original value rather than one reconstructed from milliseconds.
	Timestamp time.Time

	// ContentHash commits to the entry's content: 128 lowercase hex characters,
	// or a tombstone content hash.
	ContentHash string

	// IngestedAt is arrival time, and the ordering authority for this batch.
	// Required and non-zero.
	IngestedAt time.Time
}

// Result reports what one Append did.
type Result struct {
	// RunID is the batch identifier the linker minted for this call. It is bound
	// into every hash in the batch, so it is part of the artefact: an export that
	// loses it cannot be re-linked into the same chain.
	RunID string

	// Appended is the number of entries written.
	Appended int

	// FirstSeq and LastSeq are the global sequence numbers assigned to the first
	// and last entries of the batch.
	FirstSeq int64
	LastSeq  int64

	// HeadHash is the chain hash of the last entry — what the next append links
	// from.
	HeadHash string
}

// Linker assigns chain positions and computes linking hashes.
//
// Construct one with [New]. A Linker is safe for concurrent use.
type Linker struct {
	store store.Store
	now   func() time.Time
	runID func() (string, error)
}

// Option configures a Linker.
type Option func(*Linker)

// WithClock replaces the clock used for state timestamps.
//
// Intended for tests. The clock never affects a chain hash — entry timestamps
// come from the caller — so a fake clock cannot change what a chain attests.
func WithClock(now func() time.Time) Option {
	return func(l *Linker) { l.now = now }
}

// WithRunIDFunc replaces run id generation.
//
// Intended for tests that need reproducible hashes. Production code must not use
// this to make run ids predictable: a run id is a hash input, and a predictable
// one lets an attacker who controls content precompute a target hash.
func WithRunIDFunc(fn func() (string, error)) Option {
	return func(l *Linker) { l.runID = fn }
}

// New returns a Linker that appends to s.
//
// # Description
//
// The Linker holds the store for the lifetime of its use; it does not close it.
// Closing the store remains the caller's responsibility.
//
// # Inputs
//
//   - s: the store to append to. Must be non-nil.
//   - opts: optional overrides, for tests
//
// # Outputs
//
//   - *Linker: ready to use
//   - error: if s is nil
//
// # Example
//
//	st, err := bolt.Open("chain.db")
//	if err != nil {
//	    return err
//	}
//	defer st.Close()
//	l, err := linker.New(st)
func New(s store.Store, opts ...Option) (*Linker, error) {
	if s == nil {
		return nil, errors.New("linker: store must not be nil")
	}
	l := &Linker{store: s, now: func() time.Time { return time.Now().UTC() }, runID: newRunID}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Append links a batch of entries onto a chain and writes them atomically.
//
// # Description
//
// One call is one run. The linker mints a run id, sorts the batch by arrival,
// assigns each entry a batch-local sequence number and a chain-wide global
// sequence, and computes each chain hash over the previous entry's hash. The
// batch is then written in a single transaction and the chain's head state
// updated.
//
// The run id and the batch-local sequence number are both bound into the chain
// hash, so the grouping of entries into Append calls changes the hashes produced.
// Appending A and B together is not equivalent to appending A then B. See the
// package documentation.
//
// The chain's lease is held for the whole operation. If another appender holds
// it, Append returns [ErrChainBusy] without writing.
//
// # Inputs
//
//   - ctx: cancelled contexts abort before any write
//   - chainID: the chain to append to. Must be non-empty.
//   - inputs: the entries to link. Must be non-empty. Each must carry a unique
//     EntryID, a non-zero IngestedAt, and a valid ContentHash. inputs is not
//     mutated; the batch is sorted on a copy.
//
// # Outputs
//
//   - Result: the run id, the sequence range assigned, and the new head hash
//   - error: [ErrChainBusy] under contention, [ErrPositionSupplied] if an input
//     carries a linker-assigned field, a validation error naming the offending
//     entry, or a wrapped store error
//
// # Example
//
//	res, err := l.Append(ctx, "chain-1", []linker.Input{{
//	    EntryID:     "e1",
//	    Timestamp:   eventTime,
//	    ContentHash: contentHash,
//	    IngestedAt:  arrivalTime,
//	}})
//	if errors.Is(err, linker.ErrChainBusy) {
//	    // another appender holds the chain; retry
//	}
//
// # Limitations
//
//   - The whole batch is held in memory and written as one transaction. A batch
//     large enough to matter should be split by the caller — but note that
//     splitting changes the hashes, because each call is its own run.
//   - No cross-batch deduplication. An EntryID already present in the chain is
//     not detected here; the store's write semantics govern that case.
//
// # Assumptions
//
//   - The store's WriteBatch is atomic, as the port requires. A store that
//     cannot provide atomicity can leave a head that no stored entry produced.
func (l *Linker) Append(ctx context.Context, chainID string, inputs []Input) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if chainID == "" {
		return Result{}, errors.New("linker: chain id must not be empty")
	}
	if len(inputs) == 0 {
		return Result{}, errors.New("linker: batch must not be empty")
	}
	if _, err := validateBatchOrdering(inputs); err != nil {
		return Result{}, fmt.Errorf("linker: %w", err)
	}

	// Copy before sorting: mutating the caller's slice would reorder a batch the
	// caller may still be holding for its own bookkeeping.
	batch := make([]Input, len(inputs))
	copy(batch, inputs)
	sortInputs(batch)

	runID, err := l.runID()
	if err != nil {
		return Result{}, fmt.Errorf("linker: generate run id: %w", err)
	}

	token, acquired, err := l.store.Acquire(ctx, chainID)
	if err != nil {
		return Result{}, fmt.Errorf("linker: acquire chain lease: %w", err)
	}
	if !acquired {
		return Result{}, ErrChainBusy
	}
	defer func() {
		// Release on every path. A lease left held blocks the chain for every
		// future appender, which is worse than any error this could mask, so the
		// release error is deliberately not allowed to overwrite a real failure.
		_ = l.store.Release(context.WithoutCancel(ctx), chainID, token)
	}()

	previousHash, nextGlobalSeq, err := l.continuation(ctx, chainID)
	if err != nil {
		return Result{}, err
	}

	entries := make([]store.Entry, len(batch))
	for i := range batch {
		seqNum := int64(i)
		chainHash, hashErr := chainformat.ComputeChainHash(
			previousHash, runID, seqNum, batch[i].Timestamp, batch[i].ContentHash)
		if hashErr != nil {
			return Result{}, fmt.Errorf(
				"linker: entry %q at batch index %d: %w", batch[i].EntryID, i, hashErr)
		}
		entries[i] = store.Entry{
			ChainID:      chainID,
			EntryID:      batch[i].EntryID,
			EntryType:    batch[i].EntryType,
			GlobalSeq:    nextGlobalSeq + seqNum,
			RunID:        runID,
			SequenceNum:  seqNum,
			Timestamp:    batch[i].Timestamp,
			ContentHash:  batch[i].ContentHash,
			PreviousHash: previousHash,
			ChainHash:    chainHash,
		}
		previousHash = chainHash
	}

	if err := l.store.WriteBatch(ctx, entries); err != nil {
		return Result{}, fmt.Errorf("linker: write batch: %w", err)
	}

	last := entries[len(entries)-1]
	if err := l.store.PutState(ctx, &store.State{
		ChainID:    chainID,
		HeadSeq:    last.GlobalSeq,
		HeadHash:   last.ChainHash,
		ComputedAt: l.now(),
	}); err != nil {
		// The entries are durably written at this point. A stale head is
		// recoverable — the next append reads the tail from the chain itself —
		// so this is reported rather than treated as a failed append.
		return Result{}, fmt.Errorf("linker: entries written but head state not updated: %w", err)
	}

	return Result{
		RunID:    runID,
		Appended: len(entries),
		FirstSeq: entries[0].GlobalSeq,
		LastSeq:  last.GlobalSeq,
		HeadHash: last.ChainHash,
	}, nil
}

// continuation reads where the next entry links from.
//
// # Description
//
// The chain itself is the authority, not the stored head state. State is a cache
// that lets a reader find the head without walking; if it disagrees with the
// chain, the chain wins. Reading the tail directly means a stale or missing state
// row costs a read rather than producing a fork.
//
// # Outputs
//
//   - string: the hash to link from, empty for a genesis entry
//   - int64: the global sequence to assign to the first entry of the batch
//   - error: a wrapped store error; an empty chain is not an error
func (l *Linker) continuation(ctx context.Context, chainID string) (string, int64, error) {
	chainHash, globalSeq, err := l.store.ReadTail(ctx, chainID)
	if errors.Is(err, store.ErrEmptyChain) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("linker: read chain tail: %w", err)
	}
	return chainHash, globalSeq + 1, nil
}

// newRunID returns a fresh run id: 32 hex characters from crypto/rand.
//
// # Description
//
// Hex rather than a UUID because the run id is a hash input and this package
// holds a zero-dependency line; a UUID library would buy formatting and nothing
// else. Hex also cannot contain the '|' separator that the chain hash preimage
// uses, which the format's delimiter-safety rule requires.
//
// The value must be unpredictable, not merely unique. It is bound into every
// chain hash in the batch, so a predictable run id would let an attacker who
// controls entry content precompute a target hash.
func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
