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
// The linker ASSIGNS positions. It never accepts them. [Input] carries no
// position fields at all, so this is enforced by the type rather than by a
// check — a linker that takes its output as input is not a linker.
//
// Loading an already-linked chain into a store (replication, migration, restoring
// an export) is a different operation: verify the hashes that are there, then
// write them unchanged. That path does not go through this package.
//
// # Format v3 is the default, and batching no longer changes the hashes
//
// v3 binds the entry's CHAIN-WIDE position (global_seq). The same entries in the
// same order produce the same chain, however they were grouped:
//
//	Append(A, B)   ≡   Append(A); Append(B)
//
// That is what makes a v3 chain reconstructible from its own entries.
//
// **v2 was not like this**, and a linker built with [WithFormatV2] still is not.
// v2 binds run_id and a BATCH-LOCAL sequence number, where one Append call is one
// run:
//
//	Append(A, B)         →  A: run1/seq0    B: run1/seq1
//	Append(A); Append(B) →  A: run1/seq0    B: run2/seq0   ← B's hash differs
//
// Under v2 the batch boundaries are part of the artefact and are recorded
// nowhere, so a chain cannot be rebuilt from its entries and re-linking an export
// will not reproduce it. Preserve v2 exports, not the inputs that produced them.
//
// Use [WithFormatV2] only to produce bytes a verifier released before v3 will
// accept. Existing v2 chains are never rewritten and verify as v2 forever. See
// the module's docs/decisions.md D15.
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
//
// # Limitations
//
//   - Originates only. It cannot ingest an already-linked chain; see above.
//   - Orders a batch by IngestedAt, which is REQUIRED on every input and is not
//     persisted — it decides position and is then discarded, so a caller that
//     needs it afterwards must keep it themselves.
//   - Appends to one chain at a time, by design. The lease is what stops two
//     appenders linking from the same tail.
//
// # Assumptions
//
//   - The store writes a batch atomically. A partially written batch leaves a
//     head that no stored entry produced, and the next append links from a hash
//     that does not exist.
//   - Content hashes arrive already computed and validated; this package links
//     entries and does not inspect what they contain.
package linker
