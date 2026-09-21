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
// # Assumptions
//
//   - Keys sort in the same order numerically and lexicographically. Adapters
//     over byte-ordered stores MUST encode sequence numbers as fixed-width
//     big-endian; decimal or little-endian encodings sort wrong and corrupt
//     every range scan.
//   - A single writer appends to a given chain at a time.
package store
