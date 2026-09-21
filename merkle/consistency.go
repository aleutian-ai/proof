// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"crypto/subtle"
	"fmt"
)

// ConsistencyProof computes the RFC 9162 §2.1.4 consistency proof that the tree of the
// first m leaves is an append-only prefix of the full tree.
//
// # Description
//
// Proves tree-size m is consistent with tree-size n=len(leaves) (m <= n): no truncation,
// no fork between the two sizes. Empty proof when m==0 (empty tree is a prefix of
// anything) or m==n (identical trees). Verified offline via VerifyConsistency.
//
// # Inputs
//
//   - m: the earlier tree size; MUST be in [0, len(leaves)].
//   - leaves: the full ordered leaf set (global_seq order).
//
// # Outputs
//
//   - [][]byte: the consistency proof (O(log n) nodes; empty for m==0 or m==n).
//   - error: if m is out of range.
func ConsistencyProof(m int, leaves [][]byte) ([][]byte, error) {
	n := len(leaves)
	if m < 0 || m > n {
		return nil, fmt.Errorf("merkle: consistency m=%d out of range [0,%d]", m, n)
	}
	if m == 0 || m == n {
		return [][]byte{}, nil
	}
	return subProof(m, leaves, true), nil
}

// subProof is the RFC 9162 §2.1.4 SUBPROOF recursion. The `b` flag marks whether the
// size-m subtree root is already known to the verifier (true along the old tree's left
// spine). The node hash at each level is appended last (bottom-up), like inclusionPath.
func subProof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{RootFromLeaves(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subProof(m, leaves[:k], b), RootFromLeaves(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), RootFromLeaves(leaves[:k]))
}

// VerifyConsistency verifies an RFC 9162 consistency proof offline (RFC 9162 §2.1.4.2 /
// the certificate-transparency reference algorithm).
//
// # Description
//
// Reconstructs BOTH the old root (size m) and the new root (size n) from the proof and
// requires them to match rootA and rootB respectively — proving rootB's tree is an
// append-only extension of rootA's. Both roots MUST come from signature-verified anchors
// (ADR 003 D8). Compares constant-time.
//
// # Inputs
//
//   - m, n: the earlier and later tree sizes (m <= n).
//   - rootA: the signature-verified root at size m.
//   - rootB: the signature-verified root at size n.
//   - proof: the proof from ConsistencyProof.
//
// # Outputs
//
//   - bool: true iff rootB is a consistent append-only extension of rootA.
func VerifyConsistency(m, n int, rootA, rootB []byte, proof [][]byte) bool {
	if m < 0 || n < 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && subtle.ConstantTimeCompare(rootA, rootB) == 1
	}
	if m == 0 {
		// The empty tree is a prefix of any tree; the proof carries no nodes and rootA
		// must be the empty-tree hash.
		return len(proof) == 0 && subtle.ConstantTimeCompare(rootA, EmptyRoot()) == 1
	}
	if len(proof) == 0 {
		return false
	}

	// Reference reconstruction: walk the position of leaf (m-1) up toward the root of the
	// size-n tree, replaying the proof to rebuild both roots.
	node := m - 1
	lastNode := n - 1
	for node%2 == 1 { // climb while `node` is a right child
		node /= 2
		lastNode /= 2
	}

	var hash1, hash2 []byte
	idx := 0
	if node > 0 {
		// m is not a power of two: the first proof node seeds both reconstructions.
		hash1 = proof[0]
		hash2 = proof[0]
		idx = 1
	} else {
		// m is a power of two: the old root itself is the first known node.
		hash1 = rootA
		hash2 = rootA
	}

	for ; idx < len(proof); idx++ {
		if lastNode == 0 {
			return false // proof longer than the new tree's height allows
		}
		p := proof[idx]
		if node%2 == 1 || node == lastNode {
			// `node` is a right child (or the last node at this level): p is the left sibling.
			hash1 = NodeHash(p, hash1)
			hash2 = NodeHash(p, hash2)
			for node%2 == 0 && node != 0 { // climb the left spine
				node /= 2
				lastNode /= 2
			}
		} else {
			// `node` is a left child in the new tree only: p is its right sibling.
			hash2 = NodeHash(hash2, p)
		}
		node /= 2
		lastNode /= 2
	}

	return subtle.ConstantTimeCompare(hash1, rootA) == 1 &&
		subtle.ConstantTimeCompare(hash2, rootB) == 1
}
