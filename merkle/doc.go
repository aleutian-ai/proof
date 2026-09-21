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
// # Assumptions
//
//   - Leaf and interior hashes are domain-separated, so a leaf can never be
//     reinterpreted as an interior node (the classic second-preimage attack
//     on naive Merkle constructions).
package merkle
