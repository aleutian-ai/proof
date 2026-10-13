// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

// TestVerifyInclusion_HugeTreeSizeReturns: a tree_size above 2^62 gets an
// answer. It once sent the Merkle split into an endless loop, so one tool call
// pinned a CPU core for the life of the server.
func TestVerifyInclusion_HugeTreeSizeReturns(t *testing.T) {
	hash := strings.Repeat("ab", 64)
	done := make(chan verifyInclusionOut, 1)
	go func() {
		_, out, _ := verifyInclusion(context.Background(), nil, verifyInclusionIn{
			LeafContentHash: hash, LeafIndex: 0, TreeSize: math.MaxInt,
			ProofHex: []string{hash}, RootHex: hash,
		})
		done <- out
	}()
	select {
	case out := <-done:
		if out.Included {
			t.Fatal("a one-node proof was accepted for a tree of math.MaxInt leaves")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("verify_inclusion did not return for tree_size = math.MaxInt")
	}
}

// TestVerifyInclusion_RefusesAnOverlongProof: a proof longer than any tree's
// height is refused before it is decoded.
func TestVerifyInclusion_RefusesAnOverlongProof(t *testing.T) {
	hash := strings.Repeat("ab", 64)
	proof := make([]string, maxInclusionProofNodes+1)
	for i := range proof {
		proof[i] = hash
	}
	_, _, err := verifyInclusion(context.Background(), nil, verifyInclusionIn{
		LeafContentHash: hash, LeafIndex: 0, TreeSize: 8, ProofHex: proof, RootHex: hash,
	})
	if err == nil {
		t.Fatal("a 64-node proof was accepted")
	}
}

// TestVerifyInclusion_SchemaDeclaresTheBounds: the limits are in the tool's
// input schema, so the SDK refuses an oversized call before the handler runs
// and a model is told them up front.
func TestVerifyInclusion_SchemaDeclaresTheBounds(t *testing.T) {
	hash := strings.Repeat("ab", 64)
	args := func(proofLen int, overrides map[string]any) map[string]any {
		proof := make([]string, proofLen)
		for i := range proof {
			proof[i] = hash
		}
		m := map[string]any{
			"leaf_content_hash": hash, "leaf_index": 0, "tree_size": 8,
			"proof_hex": proof, "root_hex": hash,
		}
		for k, v := range overrides {
			m[k] = v
		}
		return m
	}

	cs := connect(t)
	if got := callErr(t, cs, "verify_inclusion", args(maxInclusionProofNodes, nil)); got != "" {
		t.Fatalf("a proof of exactly %d nodes was refused: %s", maxInclusionProofNodes, got)
	}
	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{"a proof of 64 nodes", args(maxInclusionProofNodes+1, nil), "maxItems"},
		{"an overlong proof node", args(1, map[string]any{"proof_hex": []string{hash + "ab"}}), "maxLength"},
		{"an overlong leaf hash", args(1, map[string]any{"leaf_content_hash": hash + "ab"}), "maxLength"},
		{"an overlong root", args(1, map[string]any{"root_hex": hash + "ab"}), "maxLength"},
		{"a negative leaf index", args(1, map[string]any{"leaf_index": -1}), "minimum"},
		{"a negative tree size", args(1, map[string]any{"tree_size": -1}), "minimum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := callErr(t, cs, "verify_inclusion", tc.args); !strings.Contains(got, tc.wantErr) {
				t.Errorf("got %q, want a schema error containing %q", got, tc.wantErr)
			}
		})
	}
}
