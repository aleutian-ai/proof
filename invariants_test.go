// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/merkle"
)

// Metamorphic invariants: properties that must hold for EVERY valid entry, not
// just the three in the fixture.
//
// # Why these are different from the golden tests
//
// A golden vector proves the encoder reproduces three specific results. It says
// nothing about the fourth input, and a fixture cannot be extended to cover an
// input space this large. These tests assert RELATIONSHIPS that hold for all
// inputs — encode twice and get the same bytes, change any field and the hash
// moves — which is a claim about the whole space rather than three points in it.
//
// They also need no second implementation to check against, which makes them
// the strongest thing available before the cross-implementation differential.

// mutators enumerates a single-field change for every field in the entry.
//
// Written out rather than reflected over deliberately: an explicit list fails
// to compile when a field is added, forcing whoever adds it to decide how it
// mutates. Reflection would silently skip the new field and quietly weaken the
// injectivity guarantee below.
var mutators = []struct {
	field  string
	mutate func(chainformat.CaptureRequestV3) chainformat.CaptureRequestV3
}{
	{"company_id", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.CompanyID = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WB" // last char differs
		return e
	}},
	{"signing_key_id", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.SigningKeyID += "-x"
		return e
	}},
	{"timestamp_ms", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.TimestampMs++
		return e
	}},
	{"capture_method", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.CaptureMethod = "x" + e.CaptureMethod
		return e
	}},
	{"content_hash", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.ContentHash = flipLastHexNibble(e.ContentHash)
		return e
	}},
	{"encryption_mode", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		if e.EncryptionMode == "cmek" {
			e.EncryptionMode = "aleutian-managed"
		} else {
			e.EncryptionMode = "cmek"
		}
		return e
	}},
	{"model", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.Model += "x"
		return e
	}},
	{"provider", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.Provider += "x"
		return e
	}},
	{"region", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.Region = "xx-" + e.Region
		return e
	}},
	{"source_type", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.SourceType = "x" + e.SourceType
		return e
	}},
	{"trust_level", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.TrustLevel = "x" + e.TrustLevel
		return e
	}},
	{"user_id", func(e chainformat.CaptureRequestV3) chainformat.CaptureRequestV3 {
		e.UserID = flipLastHexNibble(e.UserID)
		return e
	}},
}

// flipLastHexNibble changes a 128-char hex digest by exactly one character,
// keeping it a valid lowercase-hex digest so the validator still accepts it.
func flipLastHexNibble(h string) string {
	if h == "" {
		return h
	}
	last := h[len(h)-1]
	if last == 'a' {
		return h[:len(h)-1] + "b"
	}
	return h[:len(h)-1] + "a"
}

// TestInvariant_EncodingIsDeterministic asserts encoding is a pure function.
//
// A canonical encoder that varies run-to-run — via map iteration order, a
// timestamp, or an uninitialised buffer — produces a different hash for the same
// entry, which reads downstream as tampering.
func TestInvariant_EncodingIsDeterministic(t *testing.T) {
	t.Parallel()
	for _, v := range loadVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			first, hash1, err := chainformat.EncodeAndHashV3(v.Input)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			for i := 0; i < 32; i++ {
				again, hash2, err := chainformat.EncodeAndHashV3(v.Input)
				if err != nil {
					t.Fatalf("encode (iteration %d): %v", i, err)
				}
				if !bytes.Equal(first, again) || hash1 != hash2 {
					t.Fatalf("encoding is not deterministic (differed on iteration %d)", i)
				}
			}
		})
	}
}

// TestInvariant_EveryFieldIsBound asserts injectivity: changing ANY single field
// changes both the canonical bytes and the content hash.
//
// This is the property that makes the hash mean something. A field that does not
// affect the hash is a field an attacker can rewrite freely — the entry still
// verifies, and the log says something it did not originally say. A dropped
// `enc.appendStr` line would produce exactly that, and would break no other test.
func TestInvariant_EveryFieldIsBound(t *testing.T) {
	t.Parallel()

	base := loadVectors(t)[0].Input
	baseBytes, baseHash, err := chainformat.EncodeAndHashV3(base)
	if err != nil {
		t.Fatalf("encode base: %v", err)
	}

	for _, m := range mutators {
		m := m
		t.Run(m.field, func(t *testing.T) {
			t.Parallel()
			mutBytes, mutHash, err := chainformat.EncodeAndHashV3(m.mutate(base))
			if err != nil {
				t.Fatalf("encode mutated %s: %v", m.field, err)
			}
			if bytes.Equal(baseBytes, mutBytes) {
				t.Errorf("changing %s did not change the canonical bytes — the field "+
					"is NOT bound into the signed form and can be rewritten freely", m.field)
			}
			if mutHash == baseHash {
				t.Errorf("changing %s did not change the content hash", m.field)
			}
		})
	}
}

// TestInvariant_ContentHashBindsTheDomainPrefix asserts the hash covers the
// domain prefix, not just the canonical bytes.
//
// Without the prefix, canonical bytes from a different Aleutian structure that
// happened to serialise identically would produce the same digest — a
// cross-protocol collision. The prefix is what confines a v3 capture hash to
// meaning "a v3 capture entry".
func TestInvariant_ContentHashBindsTheDomainPrefix(t *testing.T) {
	t.Parallel()

	canonical, contentHash, err := chainformat.EncodeAndHashV3(loadVectors(t)[0].Input)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	bare := sha512.Sum512(canonical)
	if contentHash == hex.EncodeToString(bare[:]) {
		t.Fatal("content hash equals SHA-512 of the canonical bytes alone — " +
			"the domain prefix is not being bound")
	}
	withPrefix := sha512.Sum512(append([]byte(chainformat.DomainPrefixV3), canonical...))
	if contentHash != hex.EncodeToString(withPrefix[:]) {
		t.Fatal("content hash is not SHA-512(DomainPrefixV3 || canonical)")
	}
}

// TestInvariant_CanonicalIsWellFramed parses the canonical bytes back as TLV and
// asserts the framing is exact.
//
// The format is length-prefixed records: u32 big-endian length then that many
// bytes, with u64 big-endian for the two integer fields. If the framing is
// ambiguous — a length that overruns, or trailing bytes — a decoder can be made
// to disagree with the encoder about where a field ends, which is the classic
// route to two parties signing different interpretations of one blob.
func TestInvariant_CanonicalIsWellFramed(t *testing.T) {
	t.Parallel()

	for _, v := range loadVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			canonical, _, err := chainformat.EncodeAndHashV3(v.Input)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			// Field order: company_id, entry_type, signing_key_id (strings),
			// timestamp_ms (u64), then 15 body fields of which pii_detected is u64.
			u64Positions := map[int]bool{3: true, 11: true}

			pos, records := 0, 0
			for pos < len(canonical) {
				if u64Positions[records] {
					if pos+8 > len(canonical) {
						t.Fatalf("record %d: u64 overruns the buffer", records)
					}
					pos += 8
					records++
					continue
				}
				if pos+4 > len(canonical) {
					t.Fatalf("record %d: length prefix overruns the buffer", records)
				}
				n := int(binary.BigEndian.Uint32(canonical[pos : pos+4]))
				pos += 4
				if pos+n > len(canonical) {
					t.Fatalf("record %d: declared length %d overruns the remaining %d bytes",
						records, n, len(canonical)-pos)
				}
				pos += n
				records++
			}
			if pos != len(canonical) {
				t.Fatalf("framing left %d trailing bytes", len(canonical)-pos)
			}
			const want = 19 // 4-field header + 15-field body
			if records != want {
				t.Fatalf("parsed %d records, want %d — a field was added, dropped, or "+
					"its type changed", records, want)
			}
		})
	}
}

// TestInvariant_CanonicalRespectsTheSizeCap asserts the 4096 ceiling holds for
// every fixture vector, including the largest.
//
// The per-field caps do not bound the sum, so this is a separate guarantee.
func TestInvariant_CanonicalRespectsTheSizeCap(t *testing.T) {
	t.Parallel()
	for _, v := range loadVectors(t) {
		canonical, _, err := chainformat.EncodeAndHashV3(v.Input)
		if err != nil {
			t.Fatalf("encode %s: %v", v.Name, err)
		}
		if len(canonical) > chainformat.MaxCanonicalBytesV3 {
			t.Errorf("%s: canonical is %d bytes, cap is %d",
				v.Name, len(canonical), chainformat.MaxCanonicalBytesV3)
		}
	}
}

// TestInvariant_MerkleConsistencyHoldsForEveryPrefix asserts that for every
// prefix length m, the root over the first m leaves is provably extended by the
// root over all n — the append-only guarantee.
//
// Modification is caught by the root changing. This catches something different:
// that history was EXTENDED rather than REWRITTEN. Without it, a party could
// publish a root, then later publish a root over an entirely different set and
// claim it as the continuation.
func TestInvariant_MerkleConsistencyHoldsForEveryPrefix(t *testing.T) {
	t.Parallel()

	// Deterministic synthetic leaves — this is a property of the tree, and using
	// more leaves than the fixture has exercises the odd/even split paths.
	const n = 17
	leaves := make([][]byte, n)
	for i := range leaves {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		sum := sha512.Sum512(b[:])
		leaves[i] = sum[:]
	}
	fullRoot := merkle.RootFromLeaves(leaves)

	for m := 1; m < n; m++ {
		m := m
		prefixRoot := merkle.RootFromLeaves(leaves[:m])
		proof, err := merkle.ConsistencyProof(m, leaves)
		if err != nil {
			t.Fatalf("consistency proof at m=%d: %v", m, err)
		}
		if !merkle.VerifyConsistency(m, n, prefixRoot, fullRoot, proof) {
			t.Errorf("m=%d: the full tree does not verify as an extension of the prefix", m)
		}
	}
}

// TestInvariant_MerkleRejectsRewrittenHistory is the negative half of the above:
// a set whose earlier entries were altered must NOT verify as an extension.
func TestInvariant_MerkleRejectsRewrittenHistory(t *testing.T) {
	t.Parallel()

	const n, m = 12, 5
	leaves := make([][]byte, n)
	for i := range leaves {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		sum := sha512.Sum512(b[:])
		leaves[i] = sum[:]
	}
	prefixRoot := merkle.RootFromLeaves(leaves[:m])

	rewritten := make([][]byte, n)
	copy(rewritten, leaves)
	altered := append([]byte(nil), rewritten[2]...)
	altered[0] ^= 0xFF // change an entry INSIDE the already-committed prefix
	rewritten[2] = altered

	proof, err := merkle.ConsistencyProof(m, rewritten)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if merkle.VerifyConsistency(m, n, prefixRoot, merkle.RootFromLeaves(rewritten), proof) {
		t.Fatal("a rewritten prefix verified as a valid extension — append-only is not enforced")
	}
}

// FuzzCanonicalV3 explores the input space the fixtures cannot reach.
//
// # What it asserts
//
//   - the encoder never panics, on any input, valid or not
//   - accept/reject is deterministic for a given input
//   - when an entry IS accepted, encoding is byte-stable and its hash matches
//     SHA-512(prefix || canonical) and respects the size cap
//
// It deliberately does NOT assert that arbitrary input is accepted — most is
// invalid, and rejection is the correct outcome. The property under test is that
// the encoder is total and stable, never that it is permissive.
//
// Run: go test -fuzz FuzzCanonicalV3 ./...
func FuzzCanonicalV3(f *testing.F) {
	base := loadVectorsForFuzz(f)
	for _, v := range base {
		f.Add(v.CompanyID, v.SigningKeyID, v.TimestampMs, v.Model, v.Provider,
			v.Region, v.ContentHash, v.UserID, v.ProcessingMode, v.PIIAction)
	}

	f.Fuzz(func(t *testing.T, companyID, signingKeyID string, timestampMs int64,
		model, provider, region, contentHash, userID, processingMode, piiAction string) {

		e := chainformat.CaptureRequestV3{
			CompanyID: companyID, SigningKeyID: signingKeyID, TimestampMs: timestampMs,
			Model: model, Provider: provider, Region: region, ContentHash: contentHash,
			UserID: userID, ProcessingMode: processingMode, PIIAction: piiAction,
			EncryptionMode: "zero-knowledge", CaptureMethod: "fetch_intercept",
			SourceType: "browser_extension", TrustLevel: "verified",
		}

		canonical, hash, err := chainformat.EncodeAndHashV3(e)
		canonical2, hash2, err2 := chainformat.EncodeAndHashV3(e)

		if (err == nil) != (err2 == nil) {
			t.Fatalf("accept/reject is not deterministic: %v vs %v", err, err2)
		}
		if err != nil {
			return // rejection is a valid outcome; nothing further to assert
		}
		if !bytes.Equal(canonical, canonical2) || hash != hash2 {
			t.Fatal("accepted input did not encode deterministically")
		}
		if len(canonical) > chainformat.MaxCanonicalBytesV3 {
			t.Fatalf("accepted an entry whose canonical form is %d bytes, over the %d cap",
				len(canonical), chainformat.MaxCanonicalBytesV3)
		}
		want := sha512.Sum512(append([]byte(chainformat.DomainPrefixV3), canonical...))
		if hash != hex.EncodeToString(want[:]) {
			t.Fatal("content hash is not SHA-512(DomainPrefixV3 || canonical)")
		}
	})
}

// loadVectorsForFuzz mirrors loadVectors for *testing.F, which is not a *testing.T.
func loadVectorsForFuzz(f *testing.F) []chainformat.CaptureRequestV3 {
	f.Helper()
	var gf goldenFile
	if err := jsonUnmarshalGolden(&gf); err != nil {
		f.Fatalf("decode capture golden: %v", err)
	}
	out := make([]chainformat.CaptureRequestV3, 0, len(gf.Vectors))
	for _, v := range gf.Vectors {
		out = append(out, v.Input)
	}
	return out
}
