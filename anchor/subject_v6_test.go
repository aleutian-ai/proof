// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/mldsa"
)

// validV6 is v4's anchor at the version that renamed the field.
func validV6() Anchor {
	a := validV4()
	a.Version = SubjectVersion
	return a
}

// TestCanonicalV6_GoldenVector pins the v6 canonical bytes.
//
// The subject MOVES: it sorted third as "company_id" and sorts eighth as
// "subject". That reordering is the entire reason v6 exists rather than being
// an edit to v4, and this vector is what makes an accidental change loud.
func TestCanonicalV6_GoldenVector(t *testing.T) {
	got, err := Canonicalize(validV6())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(got) != goldenV6Canonical {
		t.Errorf("v6 canonical bytes changed:\n got  %s\n want %s", got, goldenV6Canonical)
	}
}

// goldenV6Canonical is the exact byte string a v6 anchor signs over. A verifier
// in another language must reproduce it character for character.
//
// Unlike the leaf rename's golden hash — which came from the PRE-rename code,
// because there the claim was that nothing changed — this value is produced by
// this implementation. v6 is a NEW format: there is nothing older to check it
// against, and no other implementation emits it yet. So it pins the bytes
// against future drift; it does not establish cross-language agreement. That
// only arrives when a second implementation reproduces it (see the SDK
// follow-on).
const goldenV6Canonical = `{"anchor_id":"anchor_01234567-8901-2345-6789-012345678901","chain_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at_ms":1715789432000,"entry_count":100,"previous_anchor_id":"anchor_00000000-0000-0000-0000-000000000000","range":{"end_entry_id":"ent_z","start_entry_id":"ent_a"},"signing_key_id":"aleutian-ml-dsa-65-2026-v1","subject":"comp_01HZX9K2M3N4P5Q6R7S8T9V0WA","verified_through":100,"version":6}`

// TestCanonicalV6_KeyOrderIsAlphabetical: the canonical form's whole premise is
// that any language emitting sorted-key compact JSON produces identical bytes.
func TestCanonicalV6_KeyOrderIsAlphabetical(t *testing.T) {
	got, err := Canonicalize(validV6())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := []string{
		"anchor_id", "chain_hash", "created_at_ms", "entry_count",
		"previous_anchor_id", "range", "signing_key_id", "subject",
		"verified_through", "version",
	}
	prev := -1
	for _, key := range want {
		at := strings.Index(string(got), `"`+key+`":`)
		if at < 0 {
			t.Fatalf("v6 canonical form is missing %q:\n%s", key, got)
		}
		if at <= prev {
			t.Errorf("%q is out of alphabetical order:\n%s", key, got)
		}
		prev = at
	}
	if strings.Contains(string(got), "company_id") {
		t.Errorf("v6 still carries the legacy key:\n%s", got)
	}
	if strings.Contains(string(got), "root_hash") || strings.Contains(string(got), "tree_size") {
		t.Errorf("v6 is built on the v4 layout and must not carry Merkle fields:\n%s", got)
	}
}

// TestCanonicalV3toV5_StillSayCompanyID is the compatibility promise. These
// bytes are what existing anchors were signed over; renaming a Go field must
// not touch them, or every anchor ever issued becomes unverifiable.
func TestCanonicalV3toV5_StillSayCompanyID(t *testing.T) {
	for _, a := range []Anchor{validV3(), validV4(), validV5()} {
		got, err := Canonicalize(a)
		if err != nil {
			t.Fatalf("v%d: canonicalize: %v", a.Version, err)
		}
		if !strings.Contains(string(got), `"company_id":`) {
			t.Errorf("v%d lost the company_id key:\n%s", a.Version, got)
		}
		if strings.Contains(string(got), `"subject":`) {
			t.Errorf("v%d gained a subject key:\n%s", a.Version, got)
		}
	}
}

// TestV6_VerifiesAndV5StillDoesNot is the trap this ticket exists to close.
//
// The version guard was written as `>= MerkleVersion` to exclude v5, which
// silently excluded every version above it as well. A v6 anchor would have
// verified nowhere.
func TestV6_VerifiesAndV5StillDoesNot(t *testing.T) {
	t.Run("v6 is not refused as unsupported", func(t *testing.T) {
		a := validV6()
		// An empty key ring: the call must fail on the KEY, not on the version.
		ring, err := NewKeyRing(TrustSelf, map[string][]byte{})
		if err != nil {
			t.Fatalf("key ring: %v", err)
		}
		_, err = VerifySignature(a, ring)
		if err == nil {
			t.Fatal("expected a key lookup failure")
		}
		if strings.Contains(err.Error(), "no cross-language test vectors") {
			t.Error("v6 was refused by the Merkle guard; the check is still open-ended")
		}
	})

	t.Run("v5 is still refused", func(t *testing.T) {
		ring, err := NewKeyRing(TrustSelf, map[string][]byte{})
		if err != nil {
			t.Fatalf("key ring: %v", err)
		}
		if _, err := VerifySignature(validV5(), ring); err == nil ||
			!strings.Contains(err.Error(), "no cross-language test vectors") {
			t.Errorf("v5 must remain unverifiable, got %v", err)
		}
	})
}

// TestV6_Invariants: the subject is in the signed bytes so an anchor cannot be
// replayed onto another chain. An empty one removes that protection.
func TestV6_Invariants(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Anchor)
		wantErr string
	}{
		{"valid", func(*Anchor) {}, ""},
		{"empty subject", func(a *Anchor) { a.Subject = "" }, "non-empty subject"},
		{"zero verified_through", func(a *Anchor) { a.VerifiedThrough = 0 }, "verified_through"},
		{"carries a Merkle root", func(a *Anchor) { a.RootHash = strings.Repeat("a", 128) }, "root_hash"},
		{"carries a tree size", func(a *Anchor) { a.TreeSize = 5 }, "tree_size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validV6()
			tc.mutate(&a)
			err := ValidateVersionInvariants(a)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	// v3..v5 never required a non-empty company_id, and tightening that now
	// would flip historical anchors from passing to broken.
	for _, a := range []Anchor{validV3(), validV4(), validV5()} {
		a.Subject = ""
		if err := ValidateVersionInvariants(a); err != nil {
			t.Errorf("v%d with an empty subject must still validate: %v", a.Version, err)
		}
	}
}

// TestAnchorJSON_KeyFollowsTheVersion: the wire key is part of what was signed,
// so re-serializing a v4 anchor under the new key would produce a file no
// existing verifier or SDK could check.
func TestAnchorJSON_KeyFollowsTheVersion(t *testing.T) {
	cases := []struct {
		anchor  Anchor
		wantKey string
		notKey  string
	}{
		{validV3(), `"company_id":`, `"subject":`},
		{validV4(), `"company_id":`, `"subject":`},
		{validV5(), `"company_id":`, `"subject":`},
		{validV6(), `"subject":`, `"company_id":`},
	}
	for _, tc := range cases {
		raw, err := json.Marshal(tc.anchor)
		if err != nil {
			t.Fatalf("v%d: marshal: %v", tc.anchor.Version, err)
		}
		if !strings.Contains(string(raw), tc.wantKey) {
			t.Errorf("v%d does not carry %s:\n%s", tc.anchor.Version, tc.wantKey, raw)
		}
		if strings.Contains(string(raw), tc.notKey) {
			t.Errorf("v%d carries %s:\n%s", tc.anchor.Version, tc.notKey, raw)
		}
	}
}

// TestAnchorJSON_RoundTrip: marshal then unmarshal must preserve every field,
// for both spellings.
func TestAnchorJSON_RoundTrip(t *testing.T) {
	for _, want := range []Anchor{validV3(), validV4(), validV5(), validV6()} {
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("v%d: marshal: %v", want.Version, err)
		}
		var got Anchor
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("v%d: unmarshal: %v", want.Version, err)
		}
		if got != want {
			t.Errorf("v%d did not round-trip:\n got  %+v\n want %+v", want.Version, got, want)
		}

		// The canonical bytes must survive the trip too — that is what a
		// signature covers.
		a, err := Canonicalize(want)
		if err != nil {
			t.Fatalf("v%d: canonicalize: %v", want.Version, err)
		}
		b, err := Canonicalize(got)
		if err != nil {
			t.Fatalf("v%d: canonicalize round-tripped: %v", want.Version, err)
		}
		if string(a) != string(b) {
			t.Errorf("v%d: canonical bytes changed across a JSON round trip", want.Version)
		}
	}
}

// TestAnchorJSON_ReadsEitherSpelling: a reader meets both for as long as any
// v4 anchor exists, which is forever — anchors are not rewritten.
func TestAnchorJSON_ReadsEitherSpelling(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"legacy key", `{"version":4,"company_id":"acme-prod"}`},
		{"new key", `{"version":6,"subject":"acme-prod"}`},
		{"both, matching", `{"version":6,"subject":"acme-prod","company_id":"acme-prod"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a Anchor
			if err := json.Unmarshal([]byte(tc.body), &a); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if a.Subject != "acme-prod" {
				t.Errorf("subject = %q", a.Subject)
			}
		})
	}
}

// TestAnchorJSON_ConflictingSpellingsRefused: canonicalizing either reading
// would produce bytes the signature does not cover, so there is no safe
// precedence rule.
func TestAnchorJSON_ConflictingSpellingsRefused(t *testing.T) {
	var a Anchor
	err := json.Unmarshal([]byte(`{"version":6,"subject":"one","company_id":"two"}`), &a)
	if err == nil {
		t.Fatal("an anchor carrying two different subjects was accepted")
	}
	if !strings.Contains(err.Error(), "company_id") {
		t.Errorf("the error does not name the conflict: %v", err)
	}
}

// TestV6_SignedAnchorVerifies is the end-to-end claim: a v6 anchor signed with
// a real ML-DSA-65 key verifies, and every tamper is caught.
//
// TestV6_VerifiesAndV5StillDoesNot only establishes that v6 gets PAST the
// version guard. This one establishes that it actually works.
func TestV6_SignedAnchorVerifies(t *testing.T) {
	seed := make([]byte, mldsa.MLDSA65.SeedSize())
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	a := validV6()
	canonical, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, err := mldsa.Sign(mldsa.MLDSA65, seed, canonical)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	ring, err := NewKeyRing(TrustProvided, map[string][]byte{a.SigningKeyID: pub})
	if err != nil {
		t.Fatalf("key ring: %v", err)
	}

	trust, err := VerifySignature(a, ring)
	if err != nil {
		t.Fatalf("a correctly signed v6 anchor did not verify: %v", err)
	}
	if trust != TrustProvided {
		t.Errorf("trust = %q, want %q", trust, TrustProvided)
	}

	// Every field is inside the signed bytes. Changing any of them must break
	// the signature — especially the subject, which is the replay protection.
	tampers := []struct {
		name   string
		mutate func(*Anchor)
	}{
		{"subject", func(x *Anchor) { x.Subject = "someone-else" }},
		{"entry count", func(x *Anchor) { x.EntryCount = 99 }},
		{"range end", func(x *Anchor) { x.Range.EndEntryID = "ent_y" }},
		{"chain hash", func(x *Anchor) { x.ChainHash = strings.Repeat("b", 128) }},
		{"verified through", func(x *Anchor) { x.VerifiedThrough = 99 }},
		{"previous anchor", func(x *Anchor) { x.PreviousAnchorID = "anchor_other" }},
	}
	for _, tc := range tampers {
		t.Run("tampered "+tc.name, func(t *testing.T) {
			bad := a
			tc.mutate(&bad)
			if _, err := VerifySignature(bad, ring); err == nil {
				t.Errorf("a v6 anchor with an altered %s verified", tc.name)
			}
		})
	}

	// A v6 anchor re-signed as v4 must not verify either: the version is in the
	// signed bytes precisely so a reader cannot be steered to a different
	// canonical form.
	downgraded := a
	downgraded.Version = 4
	if _, err := VerifySignature(downgraded, ring); err == nil {
		t.Error("a v6 anchor relabelled as v4 verified")
	}
}
