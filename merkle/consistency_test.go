// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"testing"
)

// TestConsistency_RoundTrip_AllPairs exhaustively verifies that for every 0 <= m <= n <= N,
// a generated consistency proof verifies the size-m tree against the size-n tree. This is
// the oracle that pins the RFC power-of-two split (the classic consistency-proof bug site),
// including m a power of two and m at odd/even positions.
func TestConsistency_RoundTrip_AllPairs(t *testing.T) {
	t.Parallel()
	const N = 24
	full := leaves(N)
	for n := 0; n <= N; n++ {
		rootB := RootFromLeaves(full[:n])
		for m := 0; m <= n; m++ {
			rootA := RootFromLeaves(full[:m])
			proof, err := ConsistencyProof(m, full[:n])
			if err != nil {
				t.Fatalf("m=%d n=%d: gen err: %v", m, n, err)
			}
			if !VerifyConsistency(m, n, rootA, rootB, proof) {
				t.Fatalf("m=%d n=%d: consistent proof did not verify (proof len %d)", m, n, len(proof))
			}
		}
	}
}

func TestConsistency_OutOfRange(t *testing.T) {
	t.Parallel()
	d := leaves(4)
	if _, err := ConsistencyProof(5, d); err == nil {
		t.Error("m > n should error")
	}
	if _, err := ConsistencyProof(-1, d); err == nil {
		t.Error("negative m should error")
	}
}

// TestConsistency_Negatives: a forked/truncated later tree must fail consistency against
// the genuine earlier root.
func TestConsistency_Negatives(t *testing.T) {
	t.Parallel()
	full := leaves(16)
	m, n := 5, 11
	rootA := RootFromLeaves(full[:m])
	rootB := RootFromLeaves(full[:n])
	proof, _ := ConsistencyProof(m, full[:n])

	// Genuine proof verifies.
	if !VerifyConsistency(m, n, rootA, rootB, proof) {
		t.Fatal("setup: genuine proof should verify")
	}
	// Forked later tree (change a leaf < m, i.e. inside the shared prefix) → rootB differs
	// AND the old prefix no longer matches rootA. Consistency must fail.
	forked := leaves(11)
	forked[2] = []byte{0xFF}
	if VerifyConsistency(m, n, rootA, RootFromLeaves(forked), proof) {
		t.Error("forked prefix must not verify")
	}
	// Wrong rootA (truncation to a different earlier size) → fails.
	if VerifyConsistency(m, n, RootFromLeaves(full[:m-1]), rootB, proof) {
		t.Error("wrong earlier root must not verify")
	}
	// Tampered proof node → fails.
	if len(proof) > 0 {
		bad := append([][]byte{}, proof...)
		bad[0] = LeafHash([]byte{0xAB})
		if VerifyConsistency(m, n, rootA, rootB, bad) {
			t.Error("tampered proof node must not verify")
		}
	}
	// m == n identical trees: empty proof, equal roots.
	if !VerifyConsistency(7, 7, RootFromLeaves(full[:7]), RootFromLeaves(full[:7]), [][]byte{}) {
		t.Error("m==n identical should verify with empty proof")
	}
	if VerifyConsistency(7, 7, RootFromLeaves(full[:7]), RootFromLeaves(full[:6]), [][]byte{}) {
		t.Error("m==n with differing roots must not verify")
	}
	// m == 0: empty prefix, rootA must be EmptyRoot.
	if !VerifyConsistency(0, 9, EmptyRoot(), RootFromLeaves(full[:9]), [][]byte{}) {
		t.Error("m==0 with EmptyRoot should verify")
	}
	if VerifyConsistency(0, 9, RootFromLeaves(full[:1]), RootFromLeaves(full[:9]), [][]byte{}) {
		t.Error("m==0 with non-empty rootA must not verify")
	}
}
