// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package linker assigns positions in a chain and computes the hashes that bind
// them.
//
// # Description
//
// A chain entry's hash covers the previous entry's hash, so the order entries
// are linked in is part of what the chain attests. This package is the authority
// on that order. It takes unlinked entries, sorts them by arrival, assigns each a
// position, computes the linking hashes, and writes the batch atomically.
//
// # It originates; it does not import
//
// The linker ASSIGNS positions. It never accepts them. An entry arriving with a
// run_id, sequence number, or chain hash already set is rejected rather than
// honoured — a linker that takes its output as input is not a linker.
//
// Loading an already-linked chain into a store (replication, migration, restoring
// an export) is a different operation: verify the hashes that are there, then
// write them unchanged. That path does not go through this package.
//
// # Batching is part of the artefact
//
// The chain hash binds run_id and the batch-local sequence number, so the same
// entries in the same order produce DIFFERENT hashes depending on how they were
// grouped into Append calls:
//
//	Append(A, B)        →  A: run1/seq0    B: run1/seq1
//	Append(A); Append(B) →  A: run1/seq0    B: run2/seq0   ← B's hash differs
//
// One Append call is one run. This is not an implementation detail that could be
// changed later: it means a chain cannot be reconstructed from its entries alone,
// and re-linking an exported chain will not reproduce it. Preserve exports, not
// the inputs that produced them.
//
// # Ordering authority
//
// Entries are ordered by IngestedAt (arrival), never by Timestamp (the event).
// The event timestamp is hash CONTENT and never an ordering input. A backdated or
// late-delivered entry must take its place in arrival order; ordering by event
// time lets a caller choose its own position in the chain, which is the property
// the chain exists to deny.
//
// # Concurrency
//
// Append holds the chain's store lease for the duration of the write. Two
// appenders reading the same tail would both link from it and produce two entries
// claiming the same predecessor; the lease makes that impossible. Contention
// returns [ErrChainBusy] rather than blocking.
//
// A Linker is safe for concurrent use by multiple goroutines.
package linker
