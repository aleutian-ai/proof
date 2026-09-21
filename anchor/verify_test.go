// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// signAnchor produces a real ML-DSA-65 signature over an anchor's canonical bytes.
func signAnchor(t *testing.T, a Anchor) (Anchor, []byte) {
	t.Helper()

	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	canonical, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(priv, canonical, nil, false, sig)

	a.Signature = base64.StdEncoding.EncodeToString(sig)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return a, pubBytes
}

func ringFor(t *testing.T, trust Trust, keyID string, pub []byte) *KeyRing {
	t.Helper()
	r, err := NewKeyRing(trust, map[string][]byte{keyID: pub})
	if err != nil {
		t.Fatalf("new key ring: %v", err)
	}
	return r
}

// TestVerifySignature_RoundTrip is the happy path with a real signature.
func TestVerifySignature_RoundTrip(t *testing.T) {
	signed, pub := signAnchor(t, validV4())
	ring := ringFor(t, TrustPlatform, signed.SigningKeyID, pub)

	trust, err := VerifySignature(signed, ring)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if trust != TrustPlatform {
		t.Errorf("trust = %q, want %q", trust, TrustPlatform)
	}
}

// TestVerifySignature_TamperedFieldFails pins that every canonical field is
// actually covered by the signature.
//
// A field left out of the canonical form would be silently unprotected — the
// anchor would verify while that field said anything at all.
func TestVerifySignature_TamperedFieldFails(t *testing.T) {
	signed, pub := signAnchor(t, validV4())
	ring := ringFor(t, TrustPlatform, signed.SigningKeyID, pub)

	mutations := map[string]func(*Anchor){
		"anchor_id":          func(a *Anchor) { a.AnchorID = "anchor_other" },
		"chain_hash":         func(a *Anchor) { a.ChainHash = strings.Repeat("c", 128) },
		"company_id":         func(a *Anchor) { a.CompanyID = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WB" },
		"created_at_ms":      func(a *Anchor) { a.CreatedAtMs++ },
		"entry_count":        func(a *Anchor) { a.EntryCount++ },
		"previous_anchor_id": func(a *Anchor) { a.PreviousAnchorID = "anchor_other" },
		"range.start":        func(a *Anchor) { a.Range.StartEntryID = "ent_other" },
		"range.end":          func(a *Anchor) { a.Range.EndEntryID = "ent_other" },
		"signing_key_id":     func(a *Anchor) { a.SigningKeyID = "other-key" },
		"verified_through":   func(a *Anchor) { a.VerifiedThrough++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			mutate(&tampered)

			_, err := VerifySignature(tampered, ring)
			if err == nil {
				t.Fatalf("tampering with %s did not invalidate the signature — "+
					"that field is not covered by the canonical form", name)
			}
		})
	}
}

// TestVerifySignature_TrustLevelIsReportedNotAssumed pins that the SAME valid
// signature yields different claims depending on where the key came from.
//
// This is the commercial and honesty boundary: a self-signed anchor must never
// be reported as equivalent to a platform-anchored one.
func TestVerifySignature_TrustLevelIsReportedNotAssumed(t *testing.T) {
	signed, pub := signAnchor(t, validV4())

	for _, want := range []Trust{TrustPlatform, TrustProvided, TrustSelf} {
		got, err := VerifySignature(signed, ringFor(t, want, signed.SigningKeyID, pub))
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if got != want {
			t.Errorf("trust = %q, want %q", got, want)
		}
	}

	// And the three must not describe themselves identically.
	seen := map[string]Trust{}
	for _, t2 := range []Trust{TrustPlatform, TrustProvided, TrustSelf} {
		claim := t2.Establishes()
		if prev, dup := seen[claim]; dup {
			t.Errorf("%q and %q make the same claim: %q", prev, t2, claim)
		}
		seen[claim] = t2
	}
}

// TestVerifySignature_UnknownKeyIsItsOwnError pins that "I don't know this
// signer" is distinguishable from "this signature is wrong". Collapsing them
// makes a missing trust root look like an attack.
func TestVerifySignature_UnknownKeyIsItsOwnError(t *testing.T) {
	signed, pub := signAnchor(t, validV4())
	ring := ringFor(t, TrustPlatform, "some-other-key-id", pub)

	_, err := VerifySignature(signed, ring)
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("want ErrUnknownKeyID, got %v", err)
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Error("an unknown key must not be reported as an invalid signature")
	}
}

// TestVerifySignature_MalformedSignaturesRejectedBeforeCrypto covers the
// length and encoding guards.
func TestVerifySignature_MalformedSignaturesRejectedBeforeCrypto(t *testing.T) {
	signed, pub := signAnchor(t, validV4())
	ring := ringFor(t, TrustPlatform, signed.SigningKeyID, pub)

	tests := map[string]string{
		"not base64":  "!!!!not base64!!!!",
		"empty":       "",
		"too short":   base64.StdEncoding.EncodeToString(make([]byte, SignatureSize-1)),
		"too long":    base64.StdEncoding.EncodeToString(make([]byte, SignatureSize+1)),
		"all zeroes":  base64.StdEncoding.EncodeToString(make([]byte, SignatureSize)),
		"truncated64": signed.Signature[:64],
	}
	for name, sig := range tests {
		t.Run(name, func(t *testing.T) {
			a := signed
			a.Signature = sig
			_, err := VerifySignature(a, ring)
			if err == nil {
				t.Fatal("malformed signature accepted")
			}
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("want ErrInvalidSignature, got %v", err)
			}
			// Wrong-length input must be rejected by OUR guard, naming the
			// length — not passed through to the crypto library to reject.
			// Asserting only "it errored" let a mutation deleting the length
			// check survive, because circl rejects them too, just later.
			decoded, decErr := base64.StdEncoding.DecodeString(sig)
			if decErr == nil && len(decoded) != SignatureSize {
				if !strings.Contains(err.Error(), "want 3309") {
					t.Errorf("a wrong-length signature must be rejected before the "+
						"crypto library sees it, with the length named; got: %v", err)
				}
			}
		})
	}
}

// TestVerifySignature_V5IsRefused pins that v5 canonicalizes but does not verify.
//
// v5 has no cross-language vectors: no SDK implements it, no producer emits it.
// Verifying would assert byte-agreement with implementations that do not exist.
func TestVerifySignature_V5IsRefused(t *testing.T) {
	signed, pub := signAnchor(t, validV5())
	ring := ringFor(t, TrustPlatform, signed.SigningKeyID, pub)

	// It must canonicalize — the format is implemented.
	if _, err := Canonicalize(signed); err != nil {
		t.Fatalf("v5 must still canonicalize: %v", err)
	}

	_, err := VerifySignature(signed, ring)
	if !errors.Is(err, ErrVerificationUnsupported) {
		t.Fatalf("v5 verification must be explicitly refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "cross-language") {
		t.Errorf("the refusal must say WHY, not just that it is unsupported: %v", err)
	}
}

// TestVerifySignature_VersionInvariantsCheckedBeforeCanonicalization is the
// downgrade guard.
//
// A v4 anchor with verified_through=0 is malformed. If canonicalization ran
// first it would produce v4 bytes and fail as a signature mismatch — which reads
// as tampering rather than as a malformed anchor.
func TestVerifySignature_VersionInvariantsCheckedBeforeCanonicalization(t *testing.T) {
	signed, pub := signAnchor(t, validV4())
	ring := ringFor(t, TrustPlatform, signed.SigningKeyID, pub)

	bad := signed
	bad.VerifiedThrough = 0

	_, err := VerifySignature(bad, ring)
	if err == nil {
		t.Fatal("a v4 anchor with verified_through=0 must be rejected")
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Errorf("a malformed anchor must not be reported as a signature failure: %v", err)
	}
}

// TestVerifySignature_NilKeySourceIsAnError pins fail-closed on a missing source.
func TestVerifySignature_NilKeySourceIsAnError(t *testing.T) {
	signed, _ := signAnchor(t, validV4())
	if _, err := VerifySignature(signed, nil); err == nil {
		t.Fatal("a nil key source must be an error, never a pass")
	}
}

// TestKeyRing_RejectsWrongSizedKeys pins the constructor guard.
func TestKeyRing_RejectsWrongSizedKeys(t *testing.T) {
	if _, err := NewKeyRing(TrustPlatform, map[string][]byte{"k": make([]byte, 32)}); err == nil {
		t.Error("a 32-byte key is not ML-DSA-65 and must be rejected")
	}
	if _, err := NewKeyRing("nonsense", map[string][]byte{}); err == nil {
		t.Error("an unrecognised trust level must be rejected")
	}
}

// TestKeyRing_DefensivelyCopies pins that a caller cannot mutate the ring after
// construction, which would change what later verifications accept.
func TestKeyRing_DefensivelyCopies(t *testing.T) {
	signed, pub := signAnchor(t, validV4())

	input := map[string][]byte{signed.SigningKeyID: pub}
	ring, err := NewKeyRing(TrustPlatform, input)
	if err != nil {
		t.Fatalf("new key ring: %v", err)
	}

	// Corrupt the caller's copy after construction.
	for i := range input[signed.SigningKeyID] {
		input[signed.SigningKeyID][i] = 0
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Fatalf("mutating the caller's map changed the ring: %v", err)
	}

	// And the key handed back must not be the ring's own storage.
	got, _, err := ring.PublicKey(signed.SigningKeyID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i] = 0
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Fatalf("mutating a returned key changed the ring: %v", err)
	}
}
