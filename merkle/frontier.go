// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Frontier is the compact RFC 9162 Merkle frontier (chainlinker_modernization_02e): the
// O(log n) perfect-subtree roots on a tree's right edge. It lets the root be maintained
// incrementally (Append is amortized O(1)) instead of recomputing from all leaves, and it
// serializes compactly for persistence alongside chain_states.
//
// The frontier is NOT independently trusted: the anchor generator re-derives the root from
// audit_entries before signing (ADR 003 D6), and the frontier is fully recoverable from
// audit_entries by FrontierFromLeaves. It is an accelerator, never the source of truth.
//
// Not safe for concurrent use; callers serialize appends per tenant (single-writer).
type Frontier struct {
	// levels[i] holds the perfect-subtree root covering 2^i leaves, or nil if the i-th
	// bit of size is 0. levels[0] is the smallest (size-1) subtree.
	levels [][]byte
	size   int64
}

// NewFrontier returns an empty frontier.
func NewFrontier() *Frontier { return &Frontier{} }

// Size returns the number of leaves appended so far.
func (f *Frontier) Size() int64 { return f.size }

// Append incorporates one leaf HASH (i.e. LeafHash(content_hash)) into the frontier,
// carrying up through completed perfect subtrees (RFC 9162 structure).
//
// # Inputs
//
//   - leafHash: the 64-byte Merkle leaf hash (LeafHash output), NOT raw content_hash.
func (f *Frontier) Append(leafHash []byte) {
	carry := append([]byte(nil), leafHash...) // copy — never alias caller memory
	lvl := 0
	for lvl < len(f.levels) && f.levels[lvl] != nil {
		carry = NodeHash(f.levels[lvl], carry)
		f.levels[lvl] = nil
		lvl++
	}
	if lvl == len(f.levels) {
		f.levels = append(f.levels, nil)
	}
	f.levels[lvl] = carry
	f.size++
}

// Root returns the current Merkle tree root over all appended leaves.
//
// # Description
//
// Folds the occupied perfect-subtree roots smallest-to-largest — `NodeHash(larger, acc)`
// — which reproduces RFC 9162 MTH for any (possibly non-perfect) tree size. Returns
// EmptyRoot() for size 0.
func (f *Frontier) Root() []byte {
	if f.size == 0 {
		return EmptyRoot()
	}
	var acc []byte
	for lvl := 0; lvl < len(f.levels); lvl++ {
		if f.levels[lvl] == nil {
			continue
		}
		if acc == nil {
			acc = f.levels[lvl]
		} else {
			acc = NodeHash(f.levels[lvl], acc)
		}
	}
	return acc
}

// FrontierFromLeaves deterministically rebuilds a frontier from ordered leaf DATA
// (raw content_hash bytes in global_seq order) — the crash-recovery / from-audit_entries
// path (ADR 003 D5). Each datum is leaf-hashed then appended.
//
// # Assumptions
//
//   - leaves are the INHERITED content_hash values (unchanged by GDPR erasure), read in
//     global_seq order; the resulting root is therefore erasure-stable (ADR 003 D3).
func FrontierFromLeaves(leaves [][]byte) *Frontier {
	f := NewFrontier()
	for _, d := range leaves {
		f.Append(LeafHash(d))
	}
	return f
}

// Marshal serializes the frontier for persistence beside chain_states. Format is a single
// deterministic line: "size|lvl:hexhash|lvl:hexhash|..." (only occupied levels, ascending).
// Deterministic so two equal frontiers serialize identically.
func (f *Frontier) Marshal() string {
	var b strings.Builder
	b.WriteString(strconv.FormatInt(f.size, 10))
	for lvl := 0; lvl < len(f.levels); lvl++ {
		if f.levels[lvl] == nil {
			continue
		}
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(lvl))
		b.WriteByte(':')
		b.WriteString(hex.EncodeToString(f.levels[lvl]))
	}
	return b.String()
}

// UnmarshalFrontier parses Marshal output. Validates that the occupied levels match the
// popcount/bit positions of size (a corrupt persisted frontier is rejected, forcing a
// rebuild from audit_entries rather than trusting bad state).
func UnmarshalFrontier(s string) (*Frontier, error) {
	parts := strings.Split(s, "|")
	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("merkle: frontier size parse: %q", parts[0])
	}
	f := &Frontier{size: size}
	for _, p := range parts[1:] {
		lh := strings.SplitN(p, ":", 2)
		if len(lh) != 2 {
			return nil, fmt.Errorf("merkle: frontier node parse: %q", p)
		}
		lvl, err := strconv.Atoi(lh[0])
		if err != nil || lvl < 0 {
			return nil, fmt.Errorf("merkle: frontier level parse: %q", lh[0])
		}
		hb, err := hex.DecodeString(lh[1])
		if err != nil || len(hb) != HashSize {
			return nil, fmt.Errorf("merkle: frontier node hash at level %d must be %d bytes", lvl, HashSize)
		}
		for lvl >= len(f.levels) {
			f.levels = append(f.levels, nil)
		}
		if f.levels[lvl] != nil {
			return nil, fmt.Errorf("merkle: frontier duplicate level %d", lvl)
		}
		f.levels[lvl] = hb
	}
	// Integrity: the set of occupied levels MUST equal the set bits of size.
	var reconstructed int64
	for lvl := 0; lvl < len(f.levels); lvl++ {
		if f.levels[lvl] != nil {
			reconstructed |= 1 << uint(lvl)
		}
	}
	if reconstructed != size {
		return nil, fmt.Errorf("merkle: frontier occupied levels %b do not match size bits %b", reconstructed, size)
	}
	return f, nil
}
