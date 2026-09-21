// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validV3 returns a well-formed v3 anchor.
func validV3() Anchor {
	return Anchor{
		Version:          3,
		AnchorID:         "anchor_01234567-8901-2345-6789-012345678901",
		CompanyID:        "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		ChainHash:        strings.Repeat("a", 128),
		Range:            EntryRange{StartEntryID: "ent_a", EndEntryID: "ent_z"},
		EntryCount:       100,
		SigningKeyID:     "aleutian-ml-dsa-65-2026-v1",
		CreatedAtMs:      1715789432000,
		PreviousAnchorID: SeedAnchorID,
		Signature:        "SIGNATURE_MUST_NOT_APPEAR_IN_CANONICAL_BYTES",
	}
}

func validV4() Anchor {
	a := validV3()
	a.Version = 4
	a.VerifiedThrough = 100
	return a
}

func validV5() Anchor {
	a := validV4()
	a.Version = 5
	a.RootHash = strings.Repeat("b", 128)
	a.TreeSize = 100
	return a
}

// =============================================================================
// The cross-language contract
// =============================================================================

type canonicalVectorFile struct {
	Vectors []struct {
		Name           string          `json:"name"`
		Anchor         json.RawMessage `json:"anchor"`
		CanonicalBytes string          `json:"canonical_bytes"`
	} `json:"vectors"`
}

// TestCanonicalize_MatchesCrossLanguageVectors is the contract that matters.
//
// This fixture is the shared byte contract between the Go, Python and JavaScript
// verifiers. If this package's output drifts from it, an anchor signed by the
// producer stops verifying in at least one language — silently, as a signature
// mismatch that looks like tampering.
func TestCanonicalize_MatchesCrossLanguageVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "testdata", "anchor_v4_canonical_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f canonicalVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("fixture contains no vectors — a silently empty contract is worse than none")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var a Anchor
			if err := json.Unmarshal(v.Anchor, &a); err != nil {
				t.Fatalf("parse anchor input: %v", err)
			}
			got, err := Canonicalize(a)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != v.CanonicalBytes {
				t.Errorf("canonical bytes differ from the cross-language fixture:\n got: %s\nwant: %s",
					got, v.CanonicalBytes)
			}
		})
	}
}

// TestCanonicalize_FixtureCoversBothVersions guards the fixture itself.
//
// A fixture that only exercised v4 would let a v3 regression through while
// still looking like cross-language coverage.
func TestCanonicalize_FixtureCoversBothVersions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "testdata", "anchor_v4_canonical_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f canonicalVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	seen := map[int]bool{}
	for _, v := range f.Vectors {
		var a Anchor
		if err := json.Unmarshal(v.Anchor, &a); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		seen[a.Version] = true
	}
	for _, want := range []int{3, 4} {
		if !seen[want] {
			t.Errorf("fixture has no v%d vector; cross-language coverage is incomplete", want)
		}
	}
}

// =============================================================================
// Version dispatch
// =============================================================================

// TestCanonicalize_DispatchesByDeclaredVersionNotFieldPresence is the
// downgrade-oracle guard.
//
// A v4 anchor whose verified_through happens to be zero must STILL canonicalize
// as v4 — including the field. If dispatch inferred the version from field
// presence, an attacker able to influence that field could choose the weaker
// canonical form, and a signature made over v4 bytes would be checked against v3
// bytes.
func TestCanonicalize_DispatchesByDeclaredVersionNotFieldPresence(t *testing.T) {
	a := validV4()
	a.VerifiedThrough = 0 // the value that makes v3 and v4 look alike

	got, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !strings.Contains(string(got), `"verified_through":0`) {
		t.Errorf("a v4 anchor with verified_through=0 must still emit the field:\n%s", got)
	}
	if !strings.Contains(string(got), `"version":4`) {
		t.Errorf("declared version must be preserved:\n%s", got)
	}
}

// TestCanonicalize_V3ExcludesVerifiedThrough pins the v3/v4 boundary.
func TestCanonicalize_V3ExcludesVerifiedThrough(t *testing.T) {
	got, err := Canonicalize(validV3())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if strings.Contains(string(got), "verified_through") {
		t.Errorf("v3 canonical form must not contain verified_through:\n%s", got)
	}
}

// TestCanonicalize_V5FieldOrder pins the two non-adjacent insertions.
//
// root_hash sorts between range and signing_key_id; tree_size between
// signing_key_id and verified_through. Getting either wrong produces bytes that
// look plausible and verify nowhere.
func TestCanonicalize_V5FieldOrder(t *testing.T) {
	got, err := Canonicalize(validV5())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	s := string(got)
	order := []string{
		`"range":`, `"root_hash":`, `"signing_key_id":`, `"tree_size":`,
		`"verified_through":`, `"version":`,
	}
	prev := -1
	for _, key := range order {
		at := strings.Index(s, key)
		if at < 0 {
			t.Fatalf("v5 canonical form is missing %s:\n%s", key, s)
		}
		if at < prev {
			t.Errorf("v5 key %s is out of alphabetical order:\n%s", key, s)
		}
		prev = at
	}
}

// TestCanonicalize_UnsupportedVersionIsAnError pins that we never guess.
func TestCanonicalize_UnsupportedVersionIsAnError(t *testing.T) {
	for _, v := range []int{0, -1, 6, 99} {
		a := validV3()
		a.Version = v
		if _, err := Canonicalize(a); err == nil {
			t.Errorf("version %d must be rejected, not canonicalized as a guess", v)
		}
	}
}

// TestCanonicalize_ExcludesSignature pins that the signature never signs itself.
func TestCanonicalize_ExcludesSignature(t *testing.T) {
	for _, a := range []Anchor{validV3(), validV4(), validV5()} {
		got, err := Canonicalize(a)
		if err != nil {
			t.Fatalf("v%d: %v", a.Version, err)
		}
		if strings.Contains(string(got), "SIGNATURE_MUST_NOT_APPEAR") {
			t.Errorf("v%d canonical form contains the signature:\n%s", a.Version, got)
		}
	}
}

// TestCanonicalize_IsStable pins that repeat calls produce identical bytes.
func TestCanonicalize_IsStable(t *testing.T) {
	for _, a := range []Anchor{validV3(), validV4(), validV5()} {
		first, err := Canonicalize(a)
		if err != nil {
			t.Fatalf("v%d: %v", a.Version, err)
		}
		for i := 0; i < 8; i++ {
			again, err := Canonicalize(a)
			if err != nil {
				t.Fatalf("v%d iteration %d: %v", a.Version, i, err)
			}
			if string(again) != string(first) {
				t.Fatalf("v%d canonicalization is not stable across calls", a.Version)
			}
		}
	}
}

// TestCanonicalize_HTMLEscapingMatchesTheProducer is a silent-divergence guard.
//
// encoding/json escapes <, > and & by default. The producer and the published
// SDK both rely on that default. Switching to a json.Encoder with
// SetEscapeHTML(false) — a natural-looking "cleanup" — would change the bytes
// for any field containing those characters, and every affected signature would
// stop verifying.
func TestCanonicalize_HTMLEscapingMatchesTheProducer(t *testing.T) {
	a := validV3()
	a.CompanyID = "comp_<&>"

	got, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !strings.Contains(string(got), `\u003c`) {
		t.Errorf("HTML escaping must stay ON to match the producer:\n%s", got)
	}
}

// =============================================================================
// Version invariants
// =============================================================================

func TestValidateVersionInvariants(t *testing.T) {
	v3WithClaim := validV3()
	v3WithClaim.VerifiedThrough = 5

	v4NoClaim := validV4()
	v4NoClaim.VerifiedThrough = 0

	v5NoRoot := validV5()
	v5NoRoot.RootHash = ""

	v5NoTree := validV5()
	v5NoTree.TreeSize = 0

	tests := []struct {
		name    string
		anchor  Anchor
		wantErr bool
	}{
		{"valid v3", validV3(), false},
		{"valid v4", validV4(), false},
		{"valid v5", validV5(), false},
		{"v3 declaring verified_through", v3WithClaim, true},
		{"v4 claiming nothing", v4NoClaim, true},
		{"v5 without root_hash", v5NoRoot, true},
		{"v5 without tree_size", v5NoTree, true},
		{"unsupported version", Anchor{Version: 9}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVersionInvariants(tc.anchor)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}
