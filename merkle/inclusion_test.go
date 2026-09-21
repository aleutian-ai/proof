// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"testing"
)

// TestInclusion_RoundTrip_AllIndices: for every tree size 1..N and every leaf index,
// a generated proof verifies against the tree root, and its length is ceil(log2(n)).
func TestInclusion_RoundTrip_AllIndices(t *testing.T) {
	t.Parallel()
	const N = 33
	for n := 1; n <= N; n++ {
		d := leaves(n)
		root := RootFromLeaves(d)
		for m := 0; m < n; m++ {
			proof, err := InclusionProof(m, d)
			if err != nil {
				t.Fatalf("n=%d m=%d: proof err: %v", n, m, err)
			}
			if !VerifyInclusion(LeafHash(d[m]), m, n, proof, root) {
				t.Fatalf("n=%d m=%d: proof did not verify", n, m)
			}
			// RFC-9162 audit paths are BOUNDED by ceil(log2(n)) — not exactly that:
			// a leaf in a shallow position (e.g. the lone last leaf of a non-power-of-two
			// tree) has a shorter path.
			if bound := ceilLog2(n); len(proof) > bound {
				t.Errorf("n=%d m=%d: proof len %d exceeds bound %d", n, m, len(proof), bound)
			}
		}
	}
}

func TestInclusion_OutOfRange(t *testing.T) {
	t.Parallel()
	d := leaves(4)
	if _, err := InclusionProof(4, d); err == nil {
		t.Error("index == n should error")
	}
	if _, err := InclusionProof(-1, d); err == nil {
		t.Error("negative index should error")
	}
	if _, err := InclusionProof(0, nil); err == nil {
		t.Error("empty tree should error")
	}
}

func TestInclusion_Negatives(t *testing.T) {
	t.Parallel()
	d := leaves(7)
	root := RootFromLeaves(d)
	m := 3
	proof, _ := InclusionProof(m, d)

	// Tampered leaf → fails.
	if VerifyInclusion(LeafHash([]byte{0xFF}), m, 7, proof, root) {
		t.Error("tampered leaf must not verify")
	}
	// Wrong index → fails.
	if VerifyInclusion(LeafHash(d[m]), m+1, 7, proof, root) {
		t.Error("wrong index must not verify")
	}
	// Tampered sibling → fails.
	bad := make([][]byte, len(proof))
	copy(bad, proof)
	bad[0] = LeafHash([]byte{0xAB})
	if VerifyInclusion(LeafHash(d[m]), m, 7, bad, root) {
		t.Error("tampered sibling must not verify")
	}
	// Wrong proof length → fails (structural).
	if VerifyInclusion(LeafHash(d[m]), m, 7, proof[:len(proof)-1], root) {
		t.Error("short proof must not verify")
	}
	if VerifyInclusion(LeafHash(d[m]), m, 7, append(append([][]byte{}, proof...), EmptyRoot()), root) {
		t.Error("over-long proof must not verify")
	}
	// Wrong root → fails.
	if VerifyInclusion(LeafHash(d[m]), m, 7, proof, EmptyRoot()) {
		t.Error("wrong root must not verify")
	}
}

func ceilLog2(n int) int {
	l := 0
	for (1 << l) < n {
		l++
	}
	return l
}
