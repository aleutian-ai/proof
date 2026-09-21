// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Callers distinguish "there is nothing here" from "the storage
// layer failed" with errors.Is; conflating the two turns an empty chain into an
// outage and a real outage into an empty result.
var (
	// ErrNotFound is returned when a lookup finds no matching entry.
	ErrNotFound = errors.New("store: entry not found")

	// ErrEmptyChain is returned by ReadTail and Bounds for a chain with no
	// entries. It is a normal condition — every chain starts empty — and is
	// distinct from ErrNotFound, which means a specific thing was missing.
	ErrEmptyChain = errors.New("store: chain is empty")
)

// Entry is one row of a chain: the hashed content plus its linkage fields.
//
// # Description
//
// This is deliberately narrow. It carries what the chain needs to verify itself
// and nothing about the interaction the entry describes — no payload, no
// identifiers, no metadata. Payloads live outside the store; what is committed
// to here is a hash.
//
// # Timestamp precision
//
// Timestamp is hash INPUT: [github.com/aleutian-ai/proof/chainformat.ComputeChainHash]
// formats it to microseconds and includes it in the preimage. An adapter that
// persists it with less than microsecond precision will produce entries whose
// hashes cannot be reproduced after a round-trip — and the failure surfaces much
// later, as an unverifiable chain rather than as a storage error.
//
// **Adapters MUST persist Timestamp losslessly to at least microsecond
// precision.** The conformance suite asserts it.
//
// # Assumptions
//
//   - ContentHash is 128 lowercase hex, or a tombstone content hash. The store
//     does not validate this; chainformat does.
//   - Entries are immutable once written, except for erasure, which replaces
//     ContentHash with a tombstone value and leaves ChainHash untouched.
type Entry struct {
	// ChainID identifies the chain this entry belongs to. Chains are independent:
	// sequence numbers and linkage never cross between them.
	ChainID string

	// EntryID uniquely identifies this entry across all chains.
	EntryID string

	// EntryType classifies the entry. "tombstone" marks an erased entry; see
	// chainformat.IsTombstone.
	EntryType string

	// GlobalSeq is the entry's chain-wide position, assigned at append.
	//
	// NOT bound into the chain hash — ordering is protected by the previous-hash
	// linkage. GlobalSeq exists so gaps are detectable and so a range can be
	// requested without walking the chain.
	GlobalSeq int64

	// RunID identifies the batch that linked this entry. Bound into the hash.
	RunID string

	// SequenceNum is the entry's position WITHIN its run, not chain-wide. Bound
	// into the hash. Distinct from GlobalSeq; conflating them changes the hash.
	SequenceNum int64

	// Timestamp is hash input. See the precision requirement above.
	Timestamp time.Time

	// ContentHash commits to the entry's content, or is a tombstone value if the
	// content was erased.
	ContentHash string

	// PreviousHash is the preceding entry's ChainHash; empty for the first entry.
	PreviousHash string

	// ChainHash is this entry's hash over the preimage including PreviousHash.
	//
	// For a tombstone this is the ORIGINAL entry's hash, retained through the
	// erasure — it is NOT reproducible from the fields of a tombstoned row. See
	// the chainformat package documentation.
	ChainHash string
}

// State is a chain's head: enough to append without walking the whole chain.
type State struct {
	// ChainID identifies the chain.
	ChainID string

	// HeadSeq is the GlobalSeq of the most recent entry.
	HeadSeq int64

	// HeadHash is the ChainHash of the most recent entry — what the next entry
	// links from.
	HeadHash string

	// ComputedAt records when this state was written. Descriptive only; the
	// linkage is the authority on ordering, never this value.
	ComputedAt time.Time
}

// TailReader reads a chain's head without loading the chain.
type TailReader interface {
	// ReadTail returns the most recent entry's chain hash and global sequence.
	//
	// Returns ErrEmptyChain if the chain has no entries — a normal condition for
	// a chain that has not been written to yet.
	ReadTail(ctx context.Context, chainID string) (chainHash string, globalSeq int64, err error)
}

// Writer appends entries to a chain.
type Writer interface {
	// WriteBatch appends entries atomically.
	//
	// Atomic means all-or-nothing: a partially written batch would leave a chain
	// whose head does not match its last entry, and a subsequent append would
	// link from a hash that no stored entry produced. Adapters that cannot
	// provide atomicity must say so in their documentation.
	//
	// Entries must be in ascending GlobalSeq order and must already carry their
	// computed ChainHash — the store links nothing and validates nothing.
	WriteBatch(ctx context.Context, entries []Entry) error
}

// Reader retrieves entries.
type Reader interface {
	// ByID returns the entry with the given id, or ErrNotFound.
	ByID(ctx context.Context, entryID string) (*Entry, error)

	// Predecessor returns the entry immediately before startSeq in the chain.
	//
	// Returns ErrNotFound when startSeq is the first entry — a verifier starting
	// mid-chain needs the predecessor's hash to link from, and its absence is
	// meaningful rather than an error condition.
	Predecessor(ctx context.Context, chainID string, startSeq int64) (*Entry, error)

	// Range returns entries with GlobalSeq in [startSeq, endSeq], ascending, up
	// to limit. A limit of 0 means no limit.
	//
	// Ascending order is part of the contract, not an implementation detail:
	// verification links each entry to the one before it, so an out-of-order
	// result would report breaks on an intact chain.
	Range(ctx context.Context, chainID string, startSeq, endSeq int64, limit int) ([]Entry, error)

	// Bounds returns the lowest and highest GlobalSeq present.
	//
	// Returns ErrEmptyChain for a chain with no entries.
	Bounds(ctx context.Context, chainID string) (minSeq, maxSeq int64, err error)
}

// StateReader reads a chain's stored head state.
type StateReader interface {
	// GetState returns the chain's head state, or ErrNotFound if none has been
	// written.
	GetState(ctx context.Context, chainID string) (*State, error)
}

// StateWriter records a chain's head state.
type StateWriter interface {
	// PutState replaces the chain's head state.
	PutState(ctx context.Context, state *State) error
}

// Lease serialises appends to a single chain.
//
// # Description
//
// The chain is inherently single-writer: two appenders reading the same tail
// would both link from it and produce two entries claiming the same predecessor.
// A lease makes that impossible.
//
// # A note on embedded stores
//
// For a single-writer embedded store the lease is close to a formality — the
// database already serialises writers — and an implementation may be a few lines
// over a transaction or a file lock. It is in the port because the CONTRACT is
// what matters: a chain has one appender at a time. An adapter that cannot
// enforce that must document the fact rather than quietly satisfy the interface.
type Lease interface {
	// Acquire attempts to take the append lease for a chain.
	//
	// Returns acquired=false with a nil error when the lease is already held —
	// contention is an expected outcome, not a failure.
	Acquire(ctx context.Context, chainID string) (token string, acquired bool, err error)

	// Release returns the lease. The token must match the one from Acquire, so a
	// holder that has already lost the lease cannot release someone else's.
	Release(ctx context.Context, chainID, token string) error
}

// Store is every capability in one interface, for adapters that provide them all.
//
// Callers should depend on the narrowest interface they need — a verifier wants
// Reader, not Store. Interface segregation here is not style: it is what lets a
// read-only consumer be handed something that structurally cannot write.
type Store interface {
	TailReader
	Writer
	Reader
	StateReader
	StateWriter
	Lease
}
