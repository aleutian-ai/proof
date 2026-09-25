// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/mldsa"
)

// --- C1: the ordering bug ---------------------------------------------------

// TestSignAnchor_OrderingCannotBeGotWrong is the regression test for the
// CRITICAL found in review: the documented sequence was
//
//	canonical := Canonicalize(a)      // signing_key_id is still ""
//	sig, keyID := SignCanonical(...)
//	a.SigningKeyID = keyID            // ← changes bytes that were already signed
//
// which produced an anchor that could never verify, failing at audit time with
// a generic "invalid signature" and nothing pointing at the cause.
//
// SignAnchor exists so the pieces are never handed over separately.
func TestSignAnchor_OrderingCannotBeGotWrong(t *testing.T) {
	s := newTestSigner(t)

	a := validV6()
	a.SigningKeyID = "" // the caller has NOT set it; this is the trap
	a.Signature = ""

	signed, err := SignAnchor(context.Background(), s, a)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	if signed.SigningKeyID != s.KeyID() {
		t.Errorf("SigningKeyID = %q, want the derived %q", signed.SigningKeyID, s.KeyID())
	}

	ring, err := NewKeyRing(TrustSelf, map[string][]byte{signed.SigningKeyID: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Fatalf("an anchor produced by SignAnchor did not verify: %v", err)
	}
}

// TestSignCanonical_RefusesAnEmptyKeyIDInTheBytes closes the same hole at the
// lower level, for callers who assemble the pieces themselves.
func TestSignCanonical_RefusesAnEmptyKeyIDInTheBytes(t *testing.T) {
	s := newTestSigner(t)

	a := validV6()
	a.SigningKeyID = "" // canonicalizes to "signing_key_id":""
	canonical, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	_, _, err = SignCanonical(context.Background(), s, canonical)
	if !errors.Is(err, ErrKeyIDMissing) {
		t.Fatalf("SignCanonical returned %v, want ErrKeyIDMissing", err)
	}
	// The refusal must tell the caller what to use, or they will guess.
	if !strings.Contains(err.Error(), s.KeyID()) {
		t.Errorf("the refusal does not offer the derived key id: %v", err)
	}
}

// --- SignAnchor behaviour ---------------------------------------------------

// TestAnchor_HasNoReferenceFields is what actually protects the
// "SignAnchor does not mutate its input" guarantee.
//
// Today that guarantee is free: Anchor is entirely value-typed, so Go's pass-by
// -value semantics make mutation impossible and the test below cannot fail. It
// stops being free the moment someone adds a slice, map or pointer field —
// SignAnchor's `out := a` would then share backing storage with the caller's
// anchor, and a caller reusing a template across subjects would carry one
// subject's data into the next.
//
// A mutation test proved the point: making SignAnchor scribble on its parameter
// survived, because it cannot affect the caller. So this is the real guard.
func TestAnchor_HasNoReferenceFields(t *testing.T) {
	var check func(t reflect.Type, path string)
	check = func(rt reflect.Type, path string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			where := path + "." + f.Name
			switch f.Type.Kind() {
			case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Chan, reflect.Func, reflect.UnsafePointer:
				t.Errorf("%s is %s: Anchor is copied by value in SignAnchor, so a "+
					"reference-typed field would share storage with the caller. Either "+
					"deep-copy it there or keep Anchor value-typed.", where, f.Type.Kind())
			case reflect.Struct:
				check(f.Type, where)
			}
		}
	}
	check(reflect.TypeOf(Anchor{}), "Anchor")
}

// TestSignAnchor_DoesNotMutateItsInput: a project-wide rule. See
// TestAnchor_HasNoReferenceFields for what actually enforces it.
func TestSignAnchor_DoesNotMutateItsInput(t *testing.T) {
	s := newTestSigner(t)

	a := validV6()
	a.SigningKeyID = ""
	a.Signature = ""
	before := a

	if _, err := SignAnchor(context.Background(), s, a); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	if a != before {
		t.Error("SignAnchor mutated the anchor it was given")
	}
}

// TestSignAnchor_RefusesWhatThisPackageWillNotVerify. Signing a v5 anchor, or
// one failing its version invariants, produces bytes VerifySignature rejects —
// a worthless artefact this package should never emit.
func TestSignAnchor_RefusesWhatThisPackageWillNotVerify(t *testing.T) {
	s := newTestSigner(t)

	// A FULLY VALID v5, so the refusal is the v5 rule itself and not an
	// invariant failure standing in for it. SignAnchor checks invariants before
	// version support, matching VerifySignature's order exactly.
	t.Run("a valid v5 is still refused", func(t *testing.T) {
		a := validV5()
		a.SigningKeyID = ""
		if err := ValidateVersionInvariants(a); err != nil {
			t.Fatalf("the fixture is not a valid v5, so this test would prove nothing: %v", err)
		}
		if _, err := SignAnchor(context.Background(), s, a); !errors.Is(err, ErrVerificationUnsupported) {
			t.Errorf("SignAnchor on a valid v5 returned %v, want ErrVerificationUnsupported", err)
		}
	})

	t.Run("a v6 without a subject is refused", func(t *testing.T) {
		a := validV6()
		a.Subject = "" // v6 requires one; it is the replay protection
		a.SigningKeyID = ""
		if _, err := SignAnchor(context.Background(), s, a); err == nil {
			t.Error("SignAnchor signed a v6 anchor with no subject")
		}
	})

	t.Run("an unknown version is refused", func(t *testing.T) {
		a := validV6()
		a.Version = MaxVersion + 1
		a.SigningKeyID = ""
		if _, err := SignAnchor(context.Background(), s, a); err == nil {
			t.Error("SignAnchor signed an anchor of an unknown version")
		}
	})
}

// TestSignAnchor_KeepsACallerAssignedKeyID covers the KMS and registry case:
// those keys carry assigned labels, not content-derived hex, and re-labelling
// them would make the anchor unresolvable against the trust store that holds
// them.
func TestSignAnchor_KeepsACallerAssignedKeyID(t *testing.T) {
	s := newTestSigner(t)

	const registryLabel = "aleutian-anchor-2026-01-v2"
	a := validV6()
	a.SigningKeyID = registryLabel

	signed, err := SignAnchor(context.Background(), s, a)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	if signed.SigningKeyID != registryLabel {
		t.Fatalf("SigningKeyID = %q, want the caller's %q", signed.SigningKeyID, registryLabel)
	}

	// It must still verify — under the label, since that is what was signed.
	ring, err := NewKeyRing(TrustProvided, map[string][]byte{registryLabel: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Errorf("an anchor signed under a registry label did not verify: %v", err)
	}
}

// TestSignAnchor_ReplacesAnExistingSignature: re-signing must be well defined,
// not a function of what the anchor happened to carry.
func TestSignAnchor_ReplacesAnExistingSignature(t *testing.T) {
	s := newTestSigner(t)

	a := validV6()
	a.SigningKeyID = ""
	a.Signature = base64.StdEncoding.EncodeToString(make([]byte, SignatureSize))

	signed, err := SignAnchor(context.Background(), s, a)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	if signed.Signature == a.Signature {
		t.Error("the stale signature survived")
	}
	ring, err := NewKeyRing(TrustSelf, map[string][]byte{signed.SigningKeyID: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Errorf("the re-signed anchor did not verify: %v", err)
	}
}

// TestSignAnchor_RejectsAPreHashingSigner end to end: the hazard survives the
// move to the anchor-level API.
func TestSignAnchor_RejectsAPreHashingSigner(t *testing.T) {
	foreign, err := FromCryptoSigner(preHashingSigner{seed: testSeed(t)})
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	a := validV6()
	a.SigningKeyID = ""
	if _, err := SignAnchor(context.Background(), foreign, a); !errors.Is(err, ErrSignerProducedBadSignature) {
		t.Errorf("SignAnchor returned %v, want ErrSignerProducedBadSignature", err)
	}
}

// TestSignCanonical_BoundsItsInput: canonical bytes are caller-supplied in an
// OSS library, and signing traverses them twice — once to sign, once for the
// mandatory self-verification — while each signature also expands a fresh
// private key. An anchor's canonical form is small, so the ceiling costs
// nothing and an unbounded slice is not something to accept politely.
func TestSignCanonical_BoundsItsInput(t *testing.T) {
	s := newTestSigner(t)

	// A LITERAL, not the constant. The cases below are sized from
	// maxCanonicalSize, so they move with it and cannot detect a change to the
	// bound itself — a mutation shrinking it survived exactly that way. This
	// line pins the documented value; changing the limit is a deliberate act
	// that should update the README and this assertion together.
	if maxCanonicalSize != 1<<20 {
		t.Errorf("maxCanonicalSize is %d, want 1 MiB (1<<20); the documented bound changed",
			maxCanonicalSize)
	}

	oversized := make([]byte, maxCanonicalSize+1)
	// Fill with something that is not the empty-key-id pattern, so the refusal
	// under test is the size bound and not the earlier guard.
	for i := range oversized {
		oversized[i] = 'x'
	}

	_, _, err := SignCanonical(context.Background(), s, oversized)
	if err == nil {
		t.Fatal("an oversized canonical input was signed")
	}
	if !strings.Contains(err.Error(), "exceeding") {
		t.Errorf("error %q does not report the size bound", err)
	}

	// The boundary itself must be accepted, or the bound is off by one.
	atLimit := make([]byte, maxCanonicalSize)
	for i := range atLimit {
		atLimit[i] = 'x'
	}
	if _, _, err := SignCanonical(context.Background(), s, atLimit); err != nil {
		t.Errorf("a canonical input exactly at the limit was refused: %v", err)
	}
}

// --- KeyIDOf ----------------------------------------------------------------

// TestKeyIDOf_MatchesTheConcreteSigner: the shared derivation and the concrete
// type's cached value must agree, or _35b and the CLI would disagree about a
// key's identity.
func TestKeyIDOf_MatchesTheConcreteSigner(t *testing.T) {
	s := newTestSigner(t)
	keyID, pub, err := KeyIDOf(s)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if keyID != s.KeyID() {
		t.Errorf("KeyIDOf = %q, MLDSA65Signer.KeyID() = %q", keyID, s.KeyID())
	}
	if len(pub) != PublicKeySize {
		t.Errorf("public key is %d bytes, want %d", len(pub), PublicKeySize)
	}
}

// TestKeyIDOf_CallsPublicExactlyOnce: for a KMS-backed signer each call may be a
// network round trip, and two calls could straddle a key rotation.
func TestKeyIDOf_CallsPublicExactlyOnce(t *testing.T) {
	c := &countingSigner{inner: newTestSigner(t)}
	if _, _, err := KeyIDOf(c); err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if c.publicCalls != 1 {
		t.Errorf("Public() was called %d times, want exactly 1", c.publicCalls)
	}
}

// TestKeyIDOf_RefusesUnusableSigners.
func TestKeyIDOf_RefusesUnusableSigners(t *testing.T) {
	cases := []struct {
		name    string
		signer  ContextSigner
		wantErr string
	}{
		{"nil interface", nil, "required"},
		{"typed nil", (*nilContextSigner)(nil), "required"},
		{"wrong algorithm", mustAdapt(t, wrongAlgorithmSigner{}), "different algorithm"},
		{"unreadable public key", mustAdapt(t, opaquePublicKeySigner{}), "BinaryMarshaler"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := KeyIDOf(tc.signer)
			if err == nil {
				t.Fatal("expected a refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// --- the interface itself ---------------------------------------------------

// TestContextSigner_DoesNotRequireCryptoSigner is the point of narrowing the
// interface: a Cloud KMS or PKCS#11 implementer must not have to write a Sign
// method whose rand and opts are meaningless and which this package never calls.
//
// minimalSigner deliberately has NO crypto.Signer Sign method. That this
// compiles and works IS the assertion.
func TestContextSigner_DoesNotRequireCryptoSigner(t *testing.T) {
	var s ContextSigner = minimalSigner{seed: testSeed(t)}

	if _, ok := s.(crypto.Signer); ok {
		t.Fatal("minimalSigner accidentally satisfies crypto.Signer; this test proves nothing")
	}

	a := validV6()
	a.SigningKeyID = ""
	signed, err := SignAnchor(context.Background(), s, a)
	if err != nil {
		t.Fatalf("a signer that is NOT a crypto.Signer was refused: %v", err)
	}
	ring, err := NewKeyRing(TrustSelf, map[string][]byte{signed.SigningKeyID: minimalPub(t)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(signed, ring); err != nil {
		t.Errorf("its anchor did not verify: %v", err)
	}
}

// TestFromCryptoSigner_PassesANonNilRand. Passing nil is what stdlib ECDSA
// dereferences and panics on, and this adapter's whole purpose is accepting
// signers written outside this module.
func TestFromCryptoSigner_PassesANonNilRand(t *testing.T) {
	spy := &randSpy{inner: newTestSigner(t)}
	cs, err := FromCryptoSigner(spy)
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	if _, err := cs.SignContext(context.Background(), []byte("message")); err != nil {
		t.Fatalf("SignContext: %v", err)
	}
	if !spy.sawRand {
		t.Error("the adapter passed a nil io.Reader; a foreign signer that reads it would panic")
	}
}

// TestFromCryptoSigner_RefusesATypedNil: `var p *myKMSSigner` after a failed
// init is a non-nil interface holding a nil pointer, which a plain == nil check
// misses. Without this the nil surfaces later as a panic inside this package.
func TestFromCryptoSigner_RefusesATypedNil(t *testing.T) {
	var p *nilCryptoSigner
	if _, err := FromCryptoSigner(p); err == nil {
		t.Error("a typed-nil crypto.Signer was accepted; it would panic later")
	}
}

// TestFromCryptoSigner_DoesNotReExposeSign: the adapter must satisfy
// ContextSigner and nothing else, so a caller cannot route past it with
// arbitrary SignerOpts.
func TestFromCryptoSigner_DoesNotReExposeSign(t *testing.T) {
	cs, err := FromCryptoSigner(newTestSigner(t))
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	if _, ok := cs.(crypto.Signer); ok {
		t.Error("the adapter re-exposes crypto.Signer, letting callers bypass it")
	}
}

// --- nil-receiver safety ----------------------------------------------------

// TestPublicKey_NilIsSafe: Equal is documented to return false for a mismatch,
// and a nil key of the right type is exactly what an uninitialised field gives.
func TestPublicKey_NilIsSafe(t *testing.T) {
	var nilKey *PublicKey
	real := newTestSigner(t).Public().(*PublicKey)

	if real.Equal(nilKey) {
		t.Error("a real key compared equal to a nil key")
	}
	if nilKey.Equal(real) {
		t.Error("a nil key compared equal to a real key")
	}
	if _, err := nilKey.MarshalBinary(); err == nil {
		t.Error("MarshalBinary on a nil key returned no error")
	}
}

// --- test doubles -----------------------------------------------------------

// minimalSigner implements ContextSigner and NOTHING else — no crypto.Signer
// Sign method. It stands for a KMS or PKCS#11 implementation.
type minimalSigner struct{ seed []byte }

func (m minimalSigner) Public() crypto.PublicKey {
	pub, _ := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, m.seed)
	return &PublicKey{raw: pub}
}

func (m minimalSigner) SignContext(_ context.Context, msg []byte) ([]byte, error) {
	return mldsa.Sign(mldsa.MLDSA65, m.seed, msg)
}

func minimalPub(t *testing.T) []byte {
	t.Helper()
	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, testSeed(t))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return pub
}

// countingSigner records how many times Public() was called.
type countingSigner struct {
	inner       ContextSigner
	publicCalls int
}

func (c *countingSigner) Public() crypto.PublicKey {
	c.publicCalls++
	return c.inner.Public()
}
func (c *countingSigner) SignContext(ctx context.Context, msg []byte) ([]byte, error) {
	return c.inner.SignContext(ctx, msg)
}

// randSpy records whether the adapter handed it a usable io.Reader.
type randSpy struct {
	inner   crypto.Signer
	sawRand bool
}

func (r *randSpy) Public() crypto.PublicKey { return r.inner.Public() }
func (r *randSpy) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.sawRand = rand != nil
	return r.inner.Sign(rand, msg, opts)
}

// nilCryptoSigner and nilContextSigner exist only to be typed nils.
type nilCryptoSigner struct{}

func (*nilCryptoSigner) Public() crypto.PublicKey { return nil }
func (*nilCryptoSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

type nilContextSigner struct{}

func (*nilContextSigner) Public() crypto.PublicKey { return nil }
func (*nilContextSigner) SignContext(context.Context, []byte) ([]byte, error) {
	return nil, nil
}

// mustAdapt wraps a crypto.Signer or fails the test.
func mustAdapt(t *testing.T, s crypto.Signer) ContextSigner {
	t.Helper()
	cs, err := FromCryptoSigner(s)
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	return cs
}
