// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package store defines the persistence port for a chain.
//
// # Description
//
// The chain needs remarkably little from storage: append at a monotonically
// increasing key, read the tail, scan an ordered range, and read or write a
// small amount of head state. There are no joins, no aggregation, and no
// queries — a hash chain is the most key-value-shaped workload there is.
//
// The interfaces here are that whole requirement. Adapters implement them; the
// chain logic never learns which one it is talking to.
//
// # Limitations
//
//   - The store LINKS NOTHING and VALIDATES NOTHING. Entries must arrive with
//     their chain hashes already computed, in ascending order; that is the
//     linker's job, and an adapter that tried to help would become a second
//     authority on chain order.
//   - [Writer.WriteBatch] must be atomic. A partially written batch leaves a
//     head no stored entry produced, and the next append links from a hash that
//     does not exist. An adapter that cannot guarantee this must say so.
//   - A [Lease] is part of the port even where the engine already serialises
//     writers, because the CONTRACT is what matters: one appender per chain at a
//     time. An adapter that cannot enforce it must document that rather than
//     quietly satisfying the interface.
//
// # Assumptions
//
//   - Timestamps round-trip losslessly to at least microsecond precision. The
//     timestamp is hash INPUT, so an adapter that truncates it produces entries
//     whose hashes cannot be reproduced after a reload — surfacing much later as
//     an unverifiable chain rather than as a storage error.
//   - Keys sort in the same order numerically and lexicographically. Adapters
//     over byte-ordered stores MUST encode sequence numbers as fixed-width
//     big-endian; decimal or little-endian encodings sort wrong and corrupt
//     every range scan.
//   - A single writer appends to a given chain at a time.
package store
