// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package merkle implements Merkle trees, inclusion and consistency proofs.
//
// # Description
//
// A Merkle root commits to a whole set of entries in one hash, so a verifier
// can confirm that a single entry belongs to a committed set without being
// given the set. Consistency proofs show that a later root extends an earlier
// one rather than replacing it — which is what rules out a silent rewrite of
// already-published history.
//
// The construction is the RFC 9162 (Certificate Transparency 2.0) binary Merkle
// Tree Hash with SHA-512 substituted for SHA-256, matching the rest of this
// module. The tree is built over each entry's leaf content hash, in global_seq
// order.
//
// # Limitations
//
//   - A root commits to a SET in an order. It says nothing about whether that
//     set is complete, or about who produced it — that is what an anchor's
//     signature is for.
//   - SHA-512 is fixed; the construction carries no algorithm identifier.
//   - The whole-tree reference builds every node, so it is O(n) in time and
//     memory. The incremental frontier exists for chains too large for that.
//
// # Assumptions
//
//   - Leaf and interior hashes are domain-separated — 0x00 for leaves, 0x01 for
//     interior nodes — so a leaf can never be reinterpreted as an interior node.
//     That is the RFC's second-preimage defence and it is retained despite the
//     SHA-512 substitution.
//   - Leaves arrive in global_seq order. A different order is a different tree
//     and therefore a different root.
package merkle
