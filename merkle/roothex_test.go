// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

func h64(seed byte) string {
	b := sha512.Sum512([]byte{seed})
	return hex.EncodeToString(b[:]) // 128-char hex, decodes to 64 bytes
}

func TestRootHex_MatchesRawTree(t *testing.T) {
	t.Parallel()
	hexes := []string{h64(1), h64(2), h64(3), h64(4), h64(5)}
	got, err := RootHex(hexes)
	if err != nil {
		t.Fatalf("RootHex: %v", err)
	}
	raw := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, _ := hex.DecodeString(h)
		raw[i] = b
	}
	want := hex.EncodeToString(RootFromLeaves(raw))
	if got != want {
		t.Errorf("RootHex mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestRootHex_Empty(t *testing.T) {
	t.Parallel()
	got, err := RootHex(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(EmptyRoot()) {
		t.Error("empty RootHex must equal hex(EmptyRoot)")
	}
}

// TestRootHex_HexDecodeDiscipline: the ADR-pinned failure modes — bad hex and
// wrong-length content_hash — must be hard errors, not silently truncated (the JS
// Buffer.from footgun the crypto review flagged).
func TestRootHex_HexDecodeDiscipline(t *testing.T) {
	t.Parallel()
	if _, err := RootHex([]string{"nothex!!"}); err == nil {
		t.Error("non-hex leaf must error")
	}
	if _, err := RootHex([]string{"abcd"}); err == nil {
		t.Error("short (2-byte) content_hash must error — not a 64-byte leaf")
	}
	// A valid 64-byte hex plus one bad → whole call errors.
	if _, err := RootHex([]string{h64(1), "zz"}); err == nil {
		t.Error("any malformed leaf must fail the whole computation")
	}
}
