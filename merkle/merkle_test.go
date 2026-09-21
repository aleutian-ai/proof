// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte{byte(i)} // distinct 1-byte leaf data
	}
	return out
}

func TestHashSize(t *testing.T) {
	t.Parallel()
	if HashSize != 64 {
		t.Fatalf("HashSize = %d, want 64 (SHA-512)", HashSize)
	}
	if len(LeafHash([]byte("x"))) != 64 || len(NodeHash(EmptyRoot(), EmptyRoot())) != 64 {
		t.Fatal("leaf/node hashes must be 64 bytes")
	}
}

func TestEmptyRoot_IsSHA512OfEmpty(t *testing.T) {
	t.Parallel()
	want := sha512.Sum512(nil)
	if !bytes.Equal(RootFromLeaves(nil), want[:]) {
		t.Error("empty tree root must equal SHA-512(\"\")")
	}
	if !bytes.Equal(RootFromLeaves([][]byte{}), want[:]) {
		t.Error("empty-slice tree root must equal SHA-512(\"\")")
	}
}

func TestDomainSeparation_LeafNeverEqualsNode(t *testing.T) {
	t.Parallel()
	// A single-leaf tree (0x00-prefixed) must never equal a two-leaf node (0x01-prefixed).
	l := LeafHash([]byte{0x00})
	n := NodeHash(LeafHash([]byte{0x00}), LeafHash([]byte{0x01}))
	if bytes.Equal(l, n) {
		t.Fatal("leaf hash collided with node hash — domain separation broken")
	}
	// Empty root (SHA-512 of empty) must differ from the single-leaf hash.
	if bytes.Equal(EmptyRoot(), LeafHash(nil)) {
		t.Fatal("empty root collided with single-leaf hash")
	}
}

// TestRootFromLeaves_MatchesRFC9162Structure builds the expected root manually from
// LeafHash/NodeHash per RFC 9162 §2.1 (largest-power-of-two split, odd-node promotion)
// and asserts RootFromLeaves reproduces it — pinning the split/promotion logic.
func TestRootFromLeaves_MatchesRFC9162Structure(t *testing.T) {
	t.Parallel()
	d := leaves(7)
	L := func(i int) []byte { return LeafHash(d[i]) }

	// n=1: just the leaf.
	if !bytes.Equal(RootFromLeaves(d[:1]), L(0)) {
		t.Error("n=1 root wrong")
	}
	// n=2: node(L0,L1).
	if !bytes.Equal(RootFromLeaves(d[:2]), NodeHash(L(0), L(1))) {
		t.Error("n=2 root wrong")
	}
	// n=3 (k=2): node(node(L0,L1), L2) — odd node promoted.
	want3 := NodeHash(NodeHash(L(0), L(1)), L(2))
	if !bytes.Equal(RootFromLeaves(d[:3]), want3) {
		t.Error("n=3 root wrong (promotion)")
	}
	// n=5 (k=4): node( node(node(L0,L1),node(L2,L3)), L4 ).
	left4 := NodeHash(NodeHash(L(0), L(1)), NodeHash(L(2), L(3)))
	want5 := NodeHash(left4, L(4))
	if !bytes.Equal(RootFromLeaves(d[:5]), want5) {
		t.Error("n=5 root wrong (k=4 split + promotion)")
	}
	// n=7 (k=4): node( left4 , node(node(L4,L5),L6) ).
	right3 := NodeHash(NodeHash(L(4), L(5)), L(6))
	want7 := NodeHash(left4, right3)
	if !bytes.Equal(RootFromLeaves(d[:7]), want7) {
		t.Error("n=7 root wrong (k=4 split + right-subtree promotion)")
	}
}

func TestLargestPowerOfTwoLessThan(t *testing.T) {
	t.Parallel()
	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	for n, want := range cases {
		if got := largestPowerOfTwoLessThan(n); got != want {
			t.Errorf("largestPowerOfTwoLessThan(%d) = %d, want %d", n, got, want)
		}
	}
}

// TestRootFromLeaves_Deterministic: same leaves → same root; changing one leaf changes it.
func TestRootFromLeaves_Deterministic(t *testing.T) {
	t.Parallel()
	d := leaves(6)
	r1 := RootFromLeaves(d)
	r2 := RootFromLeaves(leaves(6))
	if !bytes.Equal(r1, r2) {
		t.Error("root not deterministic")
	}
	d[3] = []byte{0xFF}
	if bytes.Equal(RootFromLeaves(d), r1) {
		t.Error("changing a leaf must change the root")
	}
}
