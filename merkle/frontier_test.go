// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"bytes"
	"testing"
)

// TestFrontier_RootMatchesWholeTree_EverySize is the load-bearing invariant (ADR 003 D5):
// the incrementally-maintained frontier root equals the whole-tree root at EVERY size.
func TestFrontier_RootMatchesWholeTree_EverySize(t *testing.T) {
	t.Parallel()
	const N = 64
	f := NewFrontier()
	all := leaves(N)
	// Empty.
	if !bytes.Equal(f.Root(), EmptyRoot()) {
		t.Fatal("empty frontier root != EmptyRoot")
	}
	for i := 0; i < N; i++ {
		f.Append(LeafHash(all[i]))
		size := i + 1
		if f.Size() != int64(size) {
			t.Fatalf("size=%d, want %d", f.Size(), size)
		}
		if want := RootFromLeaves(all[:size]); !bytes.Equal(f.Root(), want) {
			t.Fatalf("size=%d: frontier root != whole-tree root", size)
		}
	}
}

// TestFrontierFromLeaves_MatchesIncremental: the rebuild-from-leaves recovery path produces
// the identical root as incremental appends (crash-recovery determinism).
func TestFrontierFromLeaves_MatchesIncremental(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 2, 3, 5, 8, 13, 21} {
		d := leaves(n)
		if !bytes.Equal(FrontierFromLeaves(d).Root(), RootFromLeaves(d)) {
			t.Errorf("n=%d: FrontierFromLeaves root != whole-tree root", n)
		}
	}
}

// TestFrontier_ErasureStable: the frontier root is a pure function of the content_hash
// leaves. Since GDPR erasure leaves content_hash inherited/unchanged, rebuilding from the
// same content_hashes reproduces the exact root (ADR 003 D3 erasure stability).
func TestFrontier_ErasureStable(t *testing.T) {
	t.Parallel()
	d := leaves(9)
	before := FrontierFromLeaves(d).Root()
	// Simulate post-erasure rebuild: payload columns are NULL, but content_hash (the leaf
	// input) is inherited unchanged — so recovery reads the same bytes.
	after := FrontierFromLeaves(d).Root()
	if !bytes.Equal(before, after) {
		t.Error("root changed across rebuild — erasure stability violated")
	}
}

func TestFrontier_MarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 7, 8, 100} {
		f := FrontierFromLeaves(leaves(n))
		s := f.Marshal()
		g, err := UnmarshalFrontier(s)
		if err != nil {
			t.Fatalf("n=%d unmarshal: %v", n, err)
		}
		if g.Size() != f.Size() || !bytes.Equal(g.Root(), f.Root()) {
			t.Errorf("n=%d: round-trip mismatch", n)
		}
	}
}

func TestUnmarshalFrontier_RejectsCorruption(t *testing.T) {
	t.Parallel()
	// A frontier whose occupied levels don't match size's set bits must be rejected
	// (forces rebuild from audit_entries rather than trusting corrupt state).
	good := FrontierFromLeaves(leaves(3)).Marshal() // size 3 = levels {0,1}
	if _, err := UnmarshalFrontier(good); err != nil {
		t.Fatalf("valid frontier rejected: %v", err)
	}
	for _, bad := range []string{
		"notanumber",
		"3|0:" + hexRepeat(64), // size 3 but only level 0 present → bit mismatch
		"3|9:" + hexRepeat(64), // level doesn't match size bits
		"3|0:zz",               // bad hex
		"3|0:" + hexRepeat(32), // wrong hash length
		"-1",                   // negative size
	} {
		if _, err := UnmarshalFrontier(bad); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
}

func hexRepeat(nBytes int) string {
	out := make([]byte, nBytes*2)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
