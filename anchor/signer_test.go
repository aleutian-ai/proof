// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// testSeed returns a deterministic ML-DSA-65 seed. Fixed, so a failure is
// reproducible rather than a once-in-a-run surprise.
func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, mldsa.MLDSA65.SeedSize())
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	return seed
}

// newTestSigner builds a signer and closes it when the test ends.
func newTestSigner(t *testing.T) *MLDSA65Signer {
	t.Helper()
	s, err := NewMLDSA65Signer(testSeed(t))
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// allZero reports whether every byte is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// mustMarshal returns a key's bytes or fails the test.
func mustMarshal(t *testing.T, p *PublicKey) []byte {
	t.Helper()
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return b
}

// pubBytes extracts raw key bytes the way SignCanonical does.
func pubBytes(t *testing.T, s crypto.Signer) []byte {
	t.Helper()
	m, ok := s.Public().(encoding.BinaryMarshaler)
	if !ok {
		t.Fatalf("public key %T does not implement encoding.BinaryMarshaler", s.Public())
	}
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return b
}

// TestNewMLDSA65Signer_RefusesWrongSeedSize: a short seed would otherwise be
// padded or silently reinterpreted by a lower layer, producing a key nobody
// intended.
//
// The message is asserted, not merely the refusal. The mldsa package rejects a
// wrong-sized seed on its own, so a check here that only asserted "an error
// happened" would pass even with this guard deleted. What the guard actually
// buys is a diagnostic naming both sizes at the layer the caller called, rather
// than a wrapped error from two layers down.
func TestNewMLDSA65Signer_RefusesWrongSeedSize(t *testing.T) {
	sizes := []int{0, 1, 31, 33, 64}
	for _, n := range sizes {
		_, err := NewMLDSA65Signer(make([]byte, n))
		if err == nil {
			t.Errorf("a %d-byte seed was accepted; want a refusal", n)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, fmt.Sprintf("%d bytes", n)) ||
			!strings.Contains(msg, "want 32") ||
			!strings.Contains(msg, "ML-DSA-65") {
			t.Errorf("a %d-byte seed gave %q; want a message naming the actual size, "+
				"the wanted size, and the algorithm", n, msg)
		}
	}
}

// TestNewMLDSA65Signer_ErrorNeverLeaksSeedBytes: an error message is the most
// commonly logged string in any program. Key material must never reach one.
//
// The renderings checked here are the ones key material ACTUALLY leaks through:
// %x, %X, %q, %s, %v on a []byte, and base64. An earlier version of this test
// searched for the literal "ab ab", which matches NO Go formatting verb — it
// would have passed against a seed printed every way it is possible to print
// one. Review caught that; the lesson is that a leak test must be built from
// the formatter's output, never from a guess at what a leak looks like.
func TestNewMLDSA65Signer_ErrorNeverLeaksSeedBytes(t *testing.T) {
	// Distinctive and random, so a match cannot be coincidence and cannot be
	// a value that happens to appear in the message for another reason.
	seed := make([]byte, 31) // wrong length on purpose: this is the refusal path
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("read random seed: %v", err)
	}

	_, err := NewMLDSA65Signer(seed)
	if err == nil {
		t.Fatal("expected a refusal for a 31-byte seed")
	}
	assertNoSeedRendering(t, err.Error(), seed)
}

// assertNoSeedRendering fails if msg contains seed under any rendering a Go
// program realistically produces.
func assertNoSeedRendering(t *testing.T, msg string, seed []byte) {
	t.Helper()
	renderings := map[string]string{
		"%x (hex)":           fmt.Sprintf("%x", seed),
		"%X (upper hex)":     fmt.Sprintf("%X", seed),
		"%q (quoted)":        fmt.Sprintf("%q", seed),
		"%s (raw)":           fmt.Sprintf("%s", seed),
		"%v (decimal slice)": fmt.Sprintf("%v", seed),
		"base64":             base64.StdEncoding.EncodeToString(seed),
		"base64url":          base64.RawURLEncoding.EncodeToString(seed),
	}
	for name, r := range renderings {
		if len(r) == 0 {
			continue
		}
		if strings.Contains(msg, r) {
			t.Errorf("error message leaks the seed as %s: %q", name, msg)
		}
		// Also catch a PREFIX leak: a truncated or partially formatted seed is
		// still key material. 16 hex characters is 8 bytes, far more than
		// coincidence allows.
		if len(r) >= 16 && strings.Contains(msg, r[:16]) {
			t.Errorf("error message leaks a %s prefix of the seed: %q", name, msg)
		}
	}
}

// TestSeedLeakDetector_ActuallyDetects proves the detector above is not itself
// theatre: a deliberately leaky message must be caught under every rendering.
// Without this, a broken assertion would silently pass forever — which is
// exactly how the version it replaced survived.
func TestSeedLeakDetector_ActuallyDetects(t *testing.T) {
	seed := make([]byte, 31)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("read random seed: %v", err)
	}

	leaks := map[string]string{
		"hex":       fmt.Sprintf("seed is %x", seed),
		"upper hex": fmt.Sprintf("seed is %X", seed),
		"quoted":    fmt.Sprintf("seed is %q", seed),
		"decimal":   fmt.Sprintf("seed is %v", seed),
		"base64":    "seed is " + base64.StdEncoding.EncodeToString(seed),
		"truncated": fmt.Sprintf("seed starts %x", seed[:10]),
	}
	for name, msg := range leaks {
		t.Run(name, func(t *testing.T) {
			probe := &testing.T{}
			assertNoSeedRendering(probe, msg, seed)
			if !probe.Failed() {
				t.Errorf("the detector did not catch a %s leak: %q", name, msg)
			}
		})
	}
}

// TestSigner_KeyIDMatchesKeyfile is the _38 ↔ _35a seam: an operator must never
// have to copy a key id by hand from `proof keygen` output into a config.
func TestSigner_KeyIDMatchesKeyfile(t *testing.T) {
	s := newTestSigner(t)

	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, testSeed(t))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	want, err := keyfile.KeyIDHex(keyfile.MLDSA65, pub)
	if err != nil {
		t.Fatalf("KeyIDHex: %v", err)
	}
	if s.KeyID() != want {
		t.Errorf("KeyID() = %q, want %q", s.KeyID(), want)
	}
	if len(s.KeyID()) != 32 {
		t.Errorf("key id is %d characters, want 32 hex", len(s.KeyID()))
	}
}

// TestSigner_SeedIsCopied: a caller that zeroizes its own buffer right after
// construction — which is what a caller reading a key file SHOULD do — must not
// thereby break the signer.
func TestSigner_SeedIsCopied(t *testing.T) {
	seed := testSeed(t)
	s, err := NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	defer s.Close()

	for i := range seed {
		seed[i] = 0
	}

	sig, err := s.Sign(nil, []byte("message"), crypto.Hash(0))
	if err != nil {
		t.Fatalf("signing failed after the caller zeroized its own seed: %v", err)
	}
	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, testSeed(t))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, pub, []byte("message"), sig); err != nil {
		t.Errorf("signature did not verify: %v", err)
	}
}

// TestSigner_RefusesPreHashedInput is the guard that makes this signer safe to
// hand to code written for RSA or ECDSA, where passing a digest is correct.
func TestSigner_RefusesPreHashedInput(t *testing.T) {
	s := newTestSigner(t)
	digest := sha256.Sum256([]byte("canonical"))

	_, err := s.Sign(nil, digest[:], crypto.SHA256)
	if !errors.Is(err, ErrPreHashed) {
		t.Errorf("Sign with crypto.SHA256 returned %v, want ErrPreHashed", err)
	}

	// nil and crypto.Hash(0) both mean "not hashed" and must be accepted.
	for _, opts := range []crypto.SignerOpts{nil, crypto.Hash(0)} {
		if _, err := s.Sign(nil, []byte("message"), opts); err != nil {
			t.Errorf("Sign with opts %v was refused: %v", opts, err)
		}
	}
}

// TestSigner_CloseZeroizesAndRefuses covers the whole lifecycle: the seed is
// gone, signing stops, Close is idempotent, and the public identity survives so
// a caller can still publish what it signed with.
func TestSigner_CloseZeroizesAndRefuses(t *testing.T) {
	s, err := NewMLDSA65Signer(testSeed(t))
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	keyIDBefore := s.KeyID()
	pubBefore := pubBytes(t, s)

	// Hold the backing array. Close drops the field, so without this reference
	// the zeroization is unobservable and deleting it would go unnoticed —
	// dropping a pointer is not the same as scrubbing the bytes it pointed at.
	seedRef := s.seed
	if allZero(seedRef) {
		t.Fatal("the seed was already zero before Close; this test would prove nothing")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s.seed != nil {
		t.Error("seed is still held after Close")
	}
	if !allZero(seedRef) {
		t.Error("Close dropped the seed reference but did not zeroize the bytes")
	}
	if _, err := s.Sign(nil, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrSignerClosed) {
		t.Errorf("Sign after Close returned %v, want ErrSignerClosed", err)
	}
	if _, err := s.SignContext(context.Background(), []byte("m")); !errors.Is(err, ErrSignerClosed) {
		t.Errorf("SignContext after Close returned %v, want ErrSignerClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close is not idempotent: %v", err)
	}
	if s.KeyID() != keyIDBefore {
		t.Error("key id did not survive Close; a caller can no longer say which key signed")
	}
	if !bytes.Equal(pubBytes(t, s), pubBefore) {
		t.Error("public key did not survive Close")
	}
}

// TestSigner_SignContextHonoursCancellation: the whole reason ContextSigner
// exists rather than plain crypto.Signer.
func TestSigner_SignContextHonoursCancellation(t *testing.T) {
	s := newTestSigner(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.SignContext(ctx, []byte("message")); !errors.Is(err, context.Canceled) {
		t.Errorf("SignContext with a cancelled context returned %v, want context.Canceled", err)
	}
	if _, err := s.SignContext(context.Background(), []byte("message")); err != nil {
		t.Errorf("SignContext with a live context failed: %v", err)
	}
}

// TestSigner_PublicKeyCopiesAndCompares: a caller mutating what it got back
// must not be able to change what the signer reports next time.
func TestSigner_PublicKeyCopiesAndCompares(t *testing.T) {
	s := newTestSigner(t)

	// MarshalBinary copies on its own, so mutating ITS result proves nothing
	// about whether Public() shared the signer's array. Reach past it and
	// scribble on the returned key's own storage — that is the only way to tell
	// a copy from an alias.
	first := s.Public().(*PublicKey)
	for i := range first.raw {
		first.raw[i] ^= 0xFF
	}
	if bytes.Equal(pubBytes(t, s), mustMarshal(t, first)) {
		t.Error("Public() handed out the signer's own array; a caller mutating the " +
			"returned key changed what the signer reports")
	}

	// And MarshalBinary must copy too, so a caller cannot reach back through it.
	third := s.Public().(*PublicKey)
	raw := mustMarshal(t, third)
	for i := range raw {
		raw[i] = 0
	}
	if allZero(mustMarshal(t, third)) {
		t.Error("MarshalBinary handed out the key's own array")
	}

	other, err := NewMLDSA65Signer(bytes.Repeat([]byte{1}, mldsa.MLDSA65.SeedSize()))
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	defer other.Close()
	if first.Equal(other.Public()) {
		t.Error("two different keys compared equal")
	}
	if first.Equal("not a key") {
		t.Error("a non-key value compared equal")
	}
}

// TestSigner_IsDropInCryptoSigner proves the outbound half of the drop-in
// equivalence with a value typed as crypto.Signer, not as the concrete type —
// the compile-time assertions in signer.go cover the type, this covers use.
func TestSigner_IsDropInCryptoSigner(t *testing.T) {
	var cs crypto.Signer = newTestSigner(t)

	sig, err := cs.Sign(nil, []byte("message"), crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign through crypto.Signer: %v", err)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, pubBytes(t, cs), []byte("message"), sig); err != nil {
		t.Errorf("signature produced through crypto.Signer did not verify: %v", err)
	}
}

// --- foreign signers -------------------------------------------------------

// preHashingSigner is the hazard SignCanonical exists to catch: a signer written
// with RSA or ECDSA habits, which hashes its input before signing. It returns a
// perfectly well-formed ML-DSA-65 signature of exactly the right length — over
// the wrong bytes.
type preHashingSigner struct{ seed []byte }

func (p preHashingSigner) Public() crypto.PublicKey {
	pub, _ := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, p.seed)
	return &PublicKey{raw: pub}
}

func (p preHashingSigner) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return mldsa.Sign(mldsa.MLDSA65, p.seed, digest[:])
}

// wrongAlgorithmSigner returns a public key of the wrong length, as any non
// ML-DSA-65 signer would.
type wrongAlgorithmSigner struct{}

func (wrongAlgorithmSigner) Public() crypto.PublicKey { return &PublicKey{raw: make([]byte, 32)} }
func (wrongAlgorithmSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, SignatureSize), nil
}

// opaquePublicKeySigner's public key cannot be marshalled, so its bytes cannot
// be read and no key id can be derived.
type opaquePublicKeySigner struct{}

func (opaquePublicKeySigner) Public() crypto.PublicKey { return struct{}{} }
func (opaquePublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, SignatureSize), nil
}

// shortSignatureSigner returns a truncated signature.
type shortSignatureSigner struct{ seed []byte }

func (s shortSignatureSigner) Public() crypto.PublicKey {
	pub, _ := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, s.seed)
	return &PublicKey{raw: pub}
}
func (s shortSignatureSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, SignatureSize-1), nil
}

// TestSignCanonical_RejectsPreHashingSigner is the reason step 4 of
// SignCanonical is unconditional. Without the self-verification this signer's
// output passes every structural check and produces an anchor that verifies
// nowhere, with nothing pointing at why.
func TestSignCanonical_RejectsPreHashingSigner(t *testing.T) {
	foreign, err := FromCryptoSigner(preHashingSigner{seed: testSeed(t)})
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	canonical := []byte(`{"version":6}`)

	// First confirm the hazard is real: the signature IS structurally perfect.
	raw, err := foreign.SignContext(context.Background(), canonical)
	if err != nil {
		t.Fatalf("the foreign signer failed outright, so this test proves nothing: %v", err)
	}
	if len(raw) != SignatureSize {
		t.Fatalf("the foreign signer's output is %d bytes; this test needs it to be "+
			"structurally valid (%d) to be meaningful", len(raw), SignatureSize)
	}

	// Now the guard.
	if _, _, err := SignCanonical(context.Background(), foreign, canonical); !errors.Is(err, ErrSignerProducedBadSignature) {
		t.Fatalf("SignCanonical returned %v, want ErrSignerProducedBadSignature", err)
	}
}

// TestSignCanonical_RejectsMalformedSigners covers the rest of what step 4 and
// its length checks catch.
func TestSignCanonical_RejectsMalformedSigners(t *testing.T) {
	cases := []struct {
		name    string
		signer  crypto.Signer
		wantErr string
	}{
		{"wrong algorithm", wrongAlgorithmSigner{}, "different algorithm"},
		{"unreadable public key", opaquePublicKeySigner{}, "BinaryMarshaler"},
		{"truncated signature", shortSignatureSigner{seed: testSeed(t)}, "want 3309"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := FromCryptoSigner(tc.signer)
			if err != nil {
				t.Fatalf("FromCryptoSigner: %v", err)
			}
			_, _, err = SignCanonical(context.Background(), cs, []byte("canonical"))
			if err == nil {
				t.Fatal("expected a refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestSignCanonical_ValidatesItsOwnArguments.
func TestSignCanonical_ValidatesItsOwnArguments(t *testing.T) {
	if _, _, err := SignCanonical(context.Background(), nil, []byte("x")); err == nil {
		t.Error("a nil signer was accepted")
	}
	if _, _, err := SignCanonical(context.Background(), newTestSigner(t), nil); err == nil {
		t.Error("empty canonical bytes were accepted")
	}
}

// TestSignCanonical_KeyIDComesFromTheSigningKey: the whole reason KeyID is not
// on the interface. The id must be derived from Public(), so a caller cannot
// declare one key and sign with another.
func TestSignCanonical_KeyIDComesFromTheSigningKey(t *testing.T) {
	s := newTestSigner(t)
	_, keyID, err := SignCanonical(context.Background(), s, []byte("canonical"))
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	if keyID != s.KeyID() {
		t.Errorf("SignCanonical reported key %q, signer holds %q", keyID, s.KeyID())
	}

	other, err := NewMLDSA65Signer(bytes.Repeat([]byte{9}, mldsa.MLDSA65.SeedSize()))
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	defer other.Close()
	_, otherID, err := SignCanonical(context.Background(), other, []byte("canonical"))
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	if otherID == keyID {
		t.Error("two different keys produced the same key id")
	}
}

// TestFromCryptoSigner_RequiresASigner.
func TestFromCryptoSigner_RequiresASigner(t *testing.T) {
	if _, err := FromCryptoSigner(nil); err == nil {
		t.Error("a nil crypto.Signer was accepted")
	}
}

// TestFromCryptoSigner_DropsCancellation pins the documented behaviour. This is
// asserting a LIMITATION, deliberately: if the adapter ever starts honouring a
// context, that is a behaviour change callers relied on the documentation for,
// and it should fail here rather than pass quietly.
func TestFromCryptoSigner_DropsCancellation(t *testing.T) {
	plain, err := FromCryptoSigner(newTestSigner(t))
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := plain.SignContext(ctx, []byte("message")); err != nil {
		t.Errorf("the adapter is documented to IGNORE the context, but it returned %v", err)
	}
}

// TestSignCanonical_ThroughAForeignWellBehavedSigner: a correct crypto.Signer
// written outside this package must work with no adapter of its own.
func TestSignCanonical_ThroughAForeignWellBehavedSigner(t *testing.T) {
	// Typed as crypto.Signer so nothing about *MLDSA65Signer is visible.
	var foreign crypto.Signer = newTestSigner(t)
	cs, err := FromCryptoSigner(foreign)
	if err != nil {
		t.Fatalf("FromCryptoSigner: %v", err)
	}
	sig, keyID, err := SignCanonical(context.Background(), cs, []byte("canonical"))
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	if len(keyID) != 32 {
		t.Errorf("key id is %q, want 32 hex characters", keyID)
	}
}

// --- end to end ------------------------------------------------------------

// TestSigner_SignsAnAnchorThatVerifies is the acceptance criterion that matters
// most: a signature this package produces must satisfy this package's verifier.
func TestSigner_SignsAnAnchorThatVerifies(t *testing.T) {
	s := newTestSigner(t)

	a := validV6()
	a.SigningKeyID = s.KeyID()
	canonical, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, keyID, err := SignCanonical(context.Background(), s, canonical)
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	ring, err := NewKeyRing(TrustSelf, map[string][]byte{keyID: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	trust, err := VerifySignature(a, ring)
	if err != nil {
		t.Fatalf("an anchor signed by this package's signer did not verify: %v", err)
	}
	if trust != TrustSelf {
		t.Errorf("trust = %q, want %q", trust, TrustSelf)
	}
}

// TestSigner_SignatureDoesNotTransferBetweenAnchors: a signature is over
// specific canonical bytes, and moving it to another anchor must fail.
func TestSigner_SignatureDoesNotTransferBetweenAnchors(t *testing.T) {
	s := newTestSigner(t)

	first := validV6()
	first.SigningKeyID = s.KeyID()
	canonical, err := Canonicalize(first)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, keyID, err := SignCanonical(context.Background(), s, canonical)
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}

	second := validV6()
	second.SigningKeyID = s.KeyID()
	second.AnchorID = "anchor_a_different_one"
	second.Signature = base64.StdEncoding.EncodeToString(sig)

	ring, err := NewKeyRing(TrustSelf, map[string][]byte{keyID: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(second, ring); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("a signature moved to a different anchor returned %v, want ErrInvalidSignature", err)
	}
}

// TestSigner_FromAProofKeygenKeyFile is the _38 ↔ _35a seam end to end: a key
// minted by `proof keygen`, written in the standard PKCS#8 form, loaded back and
// used to sign. If this breaks, the CLI and the library disagree about what a
// key file is.
func TestSigner_FromAProofKeygenKeyFile(t *testing.T) {
	pem, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, testSeed(t))
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}

	alg, seed, err := keyfile.ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if alg != keyfile.MLDSA65 {
		t.Fatalf("round-tripped algorithm is %v, want ML-DSA-65", alg)
	}

	s, err := NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatalf("NewMLDSA65Signer from a key file seed: %v", err)
	}
	defer s.Close()

	a := validV6()
	a.SigningKeyID = s.KeyID()
	canonical, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, keyID, err := SignCanonical(context.Background(), s, canonical)
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	ring, err := NewKeyRing(TrustSelf, map[string][]byte{keyID: pubBytes(t, s)})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if _, err := VerifySignature(a, ring); err != nil {
		t.Errorf("an anchor signed with a key from a key file did not verify: %v", err)
	}
}

// TestSigner_ConcurrentUse: the type documents itself as safe for concurrent
// use, and Close racing with Sign must yield a refusal rather than a torn read.
// Meaningful under -race.
func TestSigner_ConcurrentUse(t *testing.T) {
	s, err := NewMLDSA65Signer(testSeed(t))
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				// Either a good signature or ErrSignerClosed; never anything else.
				if _, err := s.Sign(nil, []byte("message"), crypto.Hash(0)); err != nil &&
					!errors.Is(err, ErrSignerClosed) {
					t.Errorf("unexpected error under concurrency: %v", err)
				}
				_ = s.KeyID()
				_ = s.Public()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Close()
	}()
	wg.Wait()
}
