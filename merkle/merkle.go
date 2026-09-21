// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package merkle implements the RFC 9162 (Certificate Transparency 2.0) binary
// Merkle Tree Hash, adapted to SHA-512 per ADR 003
// (docs/designs/adrs/003_merkle_tree_commitment.md).
//
// The tree is built over ordered leaf data (the v3 leaf content_hash of each entry,
// in global_seq order). Domain-separation bytes — 0x00 for leaves, 0x01 for interior
// nodes — are the RFC's second-preimage defense (a leaf hash can never be reinterpreted
// as an interior node) and are retained despite the SHA-512 substitution.
//
// This file is the pure whole-tree reference (RootFromLeaves is O(n)); inclusion
// proofs (02c), consistency proofs (02d), and the incremental frontier (02e) build on
// LeafHash/NodeHash and are cross-checked against RootFromLeaves.
package merkle

import "crypto/sha512"

const (
	// leafPrefix is the RFC 9162 leaf domain-separation byte.
	leafPrefix byte = 0x00
	// nodePrefix is the RFC 9162 interior-node domain-separation byte.
	nodePrefix byte = 0x01

	// HashSize is the SHA-512 output size in bytes.
	HashSize = sha512.Size
)

// LeafHash computes the RFC 9162 leaf hash for one leaf's data.
//
// # Description
//
// MTH({d}) = SHA-512(0x00 ‖ d). The 0x00 domain byte separates leaves from interior
// nodes (0x01), preventing second-preimage confusion between the two.
//
// # Inputs
//
//   - data: the leaf's opaque bytes — for the audit chain this is the entry's 64-byte
//     raw v3 content_hash (decoded from its hex column), NOT the hex string.
//
// # Outputs
//
//   - []byte: the 64-byte SHA-512 leaf hash.
//
// # Example
//
//	lh := merkle.LeafHash(rawContentHash)
//
// # Assumptions
//
//   - data is already the caller's canonical leaf commitment; this function never
//     re-canonicalizes.
func LeafHash(data []byte) []byte {
	h := sha512.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash computes the RFC 9162 interior-node hash from its two child hashes.
//
// # Description
//
// SHA-512(0x01 ‖ left ‖ right). Both children are fixed-width (64-byte) SHA-512
// outputs, so the concatenation parses unambiguously (the split is always at byte
// offset 1+64); this is the RFC's structural-unambiguity argument, unchanged at 64 bytes.
//
// # Inputs
//
//   - left, right: the 64-byte child node hashes.
//
// # Outputs
//
//   - []byte: the 64-byte interior-node hash.
//
// # Assumptions
//
//   - left and right are each exactly HashSize bytes (outputs of LeafHash/NodeHash).
func NodeHash(left, right []byte) []byte {
	h := sha512.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyRoot returns the RFC 9162 hash of an empty tree.
//
// # Description
//
// MTH({}) = SHA-512(""). Distinct from any single-leaf hash (which has a non-empty,
// 0x00-prefixed preimage), so an empty tree is never confused with a one-leaf tree.
//
// # Outputs
//
//   - []byte: the 64-byte SHA-512 hash of the empty string.
func EmptyRoot() []byte {
	sum := sha512.Sum512(nil)
	return sum[:]
}

// RootFromLeaves computes the RFC 9162 Merkle Tree Hash over ordered leaf data.
//
// # Description
//
// The whole-tree reference (O(n)). Each element is hashed as a leaf; the tree is built
// per RFC 9162 §2.1 with the largest-power-of-two split and odd-node promotion (the odd
// last node is carried up unchanged, NOT duplicated). Returns EmptyRoot() for no leaves.
//
// # Inputs
//
//   - leaves: ordered leaf data (raw content_hash bytes), in global_seq order.
//
// # Outputs
//
//   - []byte: the 64-byte tree root hash.
//
// # Example
//
//	root := merkle.RootFromLeaves([][]byte{ch0, ch1, ch2})
//
// # Limitations
//
//   - O(n) in the number of leaves; inclusion/consistency proofs and the incremental
//     frontier avoid re-walking the whole set.
//
// # Assumptions
//
//   - Ordering is the caller's responsibility (global_seq); this function does not sort.
func RootFromLeaves(leaves [][]byte) []byte {
	n := len(leaves)
	switch {
	case n == 0:
		return EmptyRoot()
	case n == 1:
		return LeafHash(leaves[0])
	default:
		k := largestPowerOfTwoLessThan(n)
		left := RootFromLeaves(leaves[:k])
		right := RootFromLeaves(leaves[k:])
		return NodeHash(left, right)
	}
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n.
//
// # Description
//
// The RFC 9162 §2.1 split point k: k is a power of two, and k < n <= 2k. This is the
// historically bug-prone step (ceil(n/2) is WRONG); pinned by n=5 and n=7 test vectors.
//
// # Inputs
//
//   - n: the number of leaves in the (sub)tree; MUST be > 1.
//
// # Outputs
//
//   - int: the split index k (1 <= k < n).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
