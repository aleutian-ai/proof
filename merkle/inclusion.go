// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"crypto/subtle"
	"fmt"
)

// InclusionProof computes the RFC 9162 §2.1.3 audit path for the leaf at index m.
//
// # Description
//
// Returns the ordered list of sibling hashes needed to recompute the tree root from the
// leaf at index m, bottom-up (proof[0] is the leaf's immediate sibling; the last element
// is the sibling nearest the root). Verified offline via VerifyInclusion.
//
// # Inputs
//
//   - m: zero-based leaf index; MUST be in [0, len(leaves)).
//   - leaves: ordered leaf data (raw content_hash bytes), global_seq order.
//
// # Outputs
//
//   - [][]byte: the audit path (length ceil(log2(n)); empty for a single-leaf tree).
//   - error: if m is out of range or leaves is empty.
//
// # Assumptions
//
//   - leaves is the same ordered set the signed root was computed over.
func InclusionProof(m int, leaves [][]byte) ([][]byte, error) {
	n := len(leaves)
	if n == 0 {
		return nil, fmt.Errorf("merkle: inclusion proof over an empty tree")
	}
	if m < 0 || m >= n {
		return nil, fmt.Errorf("merkle: inclusion index %d out of range [0,%d)", m, n)
	}
	return inclusionPath(m, leaves), nil
}

// inclusionPath is the RFC 9162 §2.1.3 PATH recursion. The sibling at each level is
// appended AFTER the sub-path, so the returned slice is bottom-up.
func inclusionPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), RootFromLeaves(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), RootFromLeaves(leaves[:k]))
}

// VerifyInclusion verifies an RFC 9162 inclusion proof offline.
//
// # Description
//
// Recomputes the tree root by folding leafHash up through the proof using the same
// (index, treeSize) subtree structure the proof was generated with, then compares
// (constant-time) to the trusted root. The root MUST come from a signature-verified
// anchor (ADR 003 D8) — this function does not fetch or trust it.
//
// # Inputs
//
//   - leafHash: the leaf's Merkle hash (LeafHash(content_hash)).
//   - m: the leaf's zero-based index.
//   - treeSize: the tree size the root commits to.
//   - proof: the audit path from InclusionProof.
//   - root: the trusted (signature-verified) tree root.
//
// # Outputs
//
//   - bool: true iff the proof folds to root for (leafHash, m, treeSize).
func VerifyInclusion(leafHash []byte, m, treeSize int, proof [][]byte, root []byte) bool {
	if m < 0 || m >= treeSize || treeSize <= 0 {
		return false
	}
	computed, ok := rootFromInclusion(leafHash, m, treeSize, proof)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(computed, root) == 1
}

// rootFromInclusion mirrors inclusionPath: at each level the sibling is the LAST proof
// element; recurse into the (m,n) subtree with the remaining prefix. Returns ok=false on
// any structural mismatch (wrong proof length for the tree shape).
func rootFromInclusion(leafHash []byte, m, n int, proof [][]byte) ([]byte, bool) {
	if n == 1 {
		if len(proof) != 0 {
			return nil, false
		}
		return leafHash, true
	}
	if len(proof) == 0 {
		return nil, false
	}
	sibling := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		left, ok := rootFromInclusion(leafHash, m, k, rest)
		if !ok {
			return nil, false
		}
		return NodeHash(left, sibling), true
	}
	right, ok := rootFromInclusion(leafHash, m-k, n-k, rest)
	if !ok {
		return nil, false
	}
	return NodeHash(sibling, right), true
}
