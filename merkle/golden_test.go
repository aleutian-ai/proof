// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

// The cross-language Merkle vectors, fixtures/testdata/merkle_golden.json.
//
// scripts/spec-vectors.py writes that file, computing every root and proof in
// Python from RFC 9162 and docs/format-spec.md §7. This package only reads it:
// it rebuilds the same tree with its own code and requires the two to agree.
// There is no way to regenerate the file from here, because a vector written by
// the code it checks shows only that the code agrees with itself.

type merkleGoldenInclusion struct {
	Index    int      `json:"index"`
	TreeSize int      `json:"tree_size"`
	LeafHash string   `json:"leaf_hash"`
	Path     []string `json:"path"`
}

type merkleGoldenConsistency struct {
	M          int      `json:"m"`
	N          int      `json:"n"`
	FirstRoot  string   `json:"first_root"`
	SecondRoot string   `json:"second_root"`
	Proof      []string `json:"proof"`
}

type merkleGolden struct {
	Hash        string                    `json:"hash"`
	Note        string                    `json:"note"`
	Leaves      []string                  `json:"leaves"` // content_hash hex, 128 chars each
	Root        string                    `json:"root"`
	Inclusion   []merkleGoldenInclusion   `json:"inclusion"`
	Consistency []merkleGoldenConsistency `json:"consistency"`
}

// goldenLeafHex derives leaf i's content_hash deterministically + language-reproducibly:
// SHA-512(uint64 big-endian i), as 128-char hex.
func goldenLeafHex(i int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	s := sha512.Sum512(b[:])
	return hex.EncodeToString(s[:])
}

// buildGolden computes, with this package, everything the vector file states:
// the same 13 leaves, the root, and the same inclusion and consistency proofs.
func buildGolden(t *testing.T) merkleGolden {
	t.Helper()
	const N = 13
	leavesHex := make([]string, N)
	data := make([][]byte, N)
	for i := 0; i < N; i++ {
		leavesHex[i] = goldenLeafHex(i)
		data[i], _ = hex.DecodeString(leavesHex[i])
	}
	g := merkleGolden{
		Hash:   "SHA-512",
		Note:   "RFC 9162 Merkle tree, SHA-512, leaf=0x00, node=0x01; leaves are content_hash hex; ADR 003.",
		Leaves: leavesHex,
		Root:   hex.EncodeToString(RootFromLeaves(data)),
	}
	for _, idx := range []int{0, 1, 4, 7, 12} {
		proof, err := InclusionProof(idx, data)
		if err != nil {
			t.Fatalf("inclusion gen %d: %v", idx, err)
		}
		g.Inclusion = append(g.Inclusion, merkleGoldenInclusion{
			Index: idx, TreeSize: N, LeafHash: hex.EncodeToString(LeafHash(data[idx])), Path: toHex(proof),
		})
	}
	// Boundary shapes for cross-language coverage: n=1 single,
	// n=8 power-of-two, m=0 empty prefix, m==n identical — each pins those roots across
	// Go/Python/JS via the consistency verify path.
	for _, mn := range [][2]int{
		{0, 13}, {1, 13}, {5, 13}, {8, 13}, {4, 8}, {13, 13},
		{0, 1}, {1, 8}, {2, 8}, {8, 8},
	} {
		m, n := mn[0], mn[1]
		proof, err := ConsistencyProof(m, data[:n])
		if err != nil {
			t.Fatalf("consistency gen %d,%d: %v", m, n, err)
		}
		g.Consistency = append(g.Consistency, merkleGoldenConsistency{
			M: m, N: n,
			FirstRoot:  hex.EncodeToString(RootFromLeaves(data[:m])),
			SecondRoot: hex.EncodeToString(RootFromLeaves(data[:n])),
			Proof:      toHex(proof),
		})
	}
	return g
}

func toHex(nodes [][]byte) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = hex.EncodeToString(n)
	}
	return out
}

// TestMerkleGolden checks this package against the shared vector file: what it
// computes must equal what the file states, and the file's proofs must verify.
func TestMerkleGolden(t *testing.T) {
	g := buildGolden(t)

	// Read the EMBEDDED bytes, not the file. Consumers receive these bytes through
	// the module system, so verifying them is verifying what actually ships; a
	// file-based read could pass against an on-disk copy that never reached a build.
	raw := fixtures.MerkleGolden()
	if len(raw) == 0 {
		t.Fatal("embedded merkle golden is empty")
	}
	var onDisk merkleGolden
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	// This package must compute what the file states, AND the file's proofs
	// must verify through the verifiers.
	if onDisk.Root != g.Root {
		t.Fatalf("root differs from the vector file: file=%s computed=%s", onDisk.Root, g.Root)
	}
	if !reflect.DeepEqual(onDisk, g) {
		t.Fatal("this package's leaves or proofs differ from the vector file; the file is " +
			"written by scripts/spec-vectors.py and is not regenerated from Go")
	}
	for _, inc := range onDisk.Inclusion {
		lh, _ := hex.DecodeString(inc.LeafHash)
		root, _ := hex.DecodeString(onDisk.Root)
		if !VerifyInclusion(lh, inc.Index, inc.TreeSize, fromHex(inc.Path), root) {
			t.Errorf("golden inclusion idx=%d failed to verify", inc.Index)
		}
	}
	for _, c := range onDisk.Consistency {
		ra, _ := hex.DecodeString(c.FirstRoot)
		rb, _ := hex.DecodeString(c.SecondRoot)
		if !VerifyConsistency(c.M, c.N, ra, rb, fromHex(c.Proof)) {
			t.Errorf("golden consistency m=%d n=%d failed to verify", c.M, c.N)
		}
	}
}

func fromHex(hs []string) [][]byte {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i], _ = hex.DecodeString(h)
	}
	return out
}
