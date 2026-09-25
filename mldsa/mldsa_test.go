// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package mldsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// specCases pair each parameter set with the RFC 9881 example key files, which
// live in keyfile's testdata with their provenance recorded there.
var specCases = []struct {
	set        mldsa.ParameterSet
	seedFile   string
	publicFile string
	pubSize    int
	sigSize    int

	// sigDigest is SHA-256 of the deterministic signature over the message
	// "determinism" using the specification's example seed. Signing is
	// deterministic, so this is a known-answer test: it fails if a dependency
	// upgrade changes what we produce, which would invalidate every signature
	// verifiers have already accepted.
	sigDigest string
}{
	{mldsa.MLDSA44, "mldsa44_seed.pem", "mldsa44_public.pem", 1312, 2420,
		"77975d3bee3c234d8c3b11ffacedb562600a37d8198ac3f0a922545bad9d48f5"},
	{mldsa.MLDSA65, "mldsa65_seed.pem", "mldsa65_public.pem", 1952, 3309,
		"4827c33d6ad3e4fc4cc434472ddbd3cd3020a97a0402af21344785eda6100fce"},
	{mldsa.MLDSA87, "mldsa87_seed.pem", "mldsa87_public.pem", 2592, 4627,
		"f26ff6250c7d29d0806752bf653a1245aadaa5217af3fa4e4338402f84d10558"},
}

// readKeyfile loads a fixture from the keyfile package's testdata.
func readKeyfile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "keyfile", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// TestSizesMatchTheStandard pins the FIPS 204 sizes. A wrong size here would
// silently change what is written into anchors and key files.
func TestSizesMatchTheStandard(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			if got := tc.set.SeedSize(); got != 32 {
				t.Errorf("SeedSize = %d, want 32", got)
			}
			if got := tc.set.PublicKeySize(); got != tc.pubSize {
				t.Errorf("PublicKeySize = %d, want %d", got, tc.pubSize)
			}
			if got := tc.set.SignatureSize(); got != tc.sigSize {
				t.Errorf("SignatureSize = %d, want %d", got, tc.sigSize)
			}
		})
	}
}

// TestPublicKeyFromSeedMatchesSpec: derive from the specification's example
// seed and require the specification's example public key.
func TestPublicKeyFromSeedMatchesSpec(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse seed: %v", err)
			}
			_, wantPub, err := keyfile.ParsePublicKey(readKeyfile(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			gotPub, err := mldsa.PublicKeyFromSeed(tc.set, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if !bytes.Equal(gotPub, wantPub) {
				t.Error("derived public key does not match the specification's example")
			}
		})
	}
}

// TestSignVerifyRoundTrip covers the happy path and the ways it must fail.
func TestSignVerifyRoundTrip(t *testing.T) {
	msg := []byte("the chain head at sequence 250")
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse seed: %v", err)
			}
			pub, err := mldsa.PublicKeyFromSeed(tc.set, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			sig, err := mldsa.Sign(tc.set, seed, msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(sig) != tc.sigSize {
				t.Errorf("signature is %d bytes, want %d", len(sig), tc.sigSize)
			}
			if err := mldsa.Verify(tc.set, pub, msg, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}

			// Each of these must fail.
			tamperedMsg := append(append([]byte{}, msg...), '!')
			if err := mldsa.Verify(tc.set, pub, tamperedMsg, sig); !errors.Is(err, mldsa.ErrInvalidSignature) {
				t.Errorf("tampered message: err = %v, want ErrInvalidSignature", err)
			}
			tamperedSig := append([]byte{}, sig...)
			tamperedSig[0] ^= 0x01
			if err := mldsa.Verify(tc.set, pub, msg, tamperedSig); !errors.Is(err, mldsa.ErrInvalidSignature) {
				t.Errorf("tampered signature: err = %v, want ErrInvalidSignature", err)
			}
			otherSeed := append([]byte{}, seed...)
			otherSeed[0] ^= 0x01
			otherPub, err := mldsa.PublicKeyFromSeed(tc.set, otherSeed)
			if err != nil {
				t.Fatalf("derive other: %v", err)
			}
			if err := mldsa.Verify(tc.set, otherPub, msg, sig); !errors.Is(err, mldsa.ErrInvalidSignature) {
				t.Errorf("wrong key: err = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

// TestSigningIsDeterministic: the same seed and message always produce the same
// signature, which is what makes signatures reproducible in an audit.
func TestSigningIsDeterministic(t *testing.T) {
	msg := []byte("determinism")
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse seed: %v", err)
			}
			first, err := mldsa.Sign(tc.set, seed, msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			second, err := mldsa.Sign(tc.set, seed, msg)
			if err != nil {
				t.Fatalf("sign again: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Error("two signatures over the same message differ")
			}
			if got := hex.EncodeToString(sha256Of(first)); got != tc.sigDigest {
				t.Errorf("signature changed:\n got  %s\n want %s\n"+
					"Signing is deterministic, so this means the output changed — "+
					"check whether a dependency upgrade altered ML-DSA. Do NOT just "+
					"update this digest: signatures already accepted by verifiers "+
					"were produced by the old behaviour.", got, tc.sigDigest)
			}
		})
	}
}

// TestCrossParameterSetRejected: a signature made under one set must never
// verify under another, even where lengths might otherwise be confused.
func TestCrossParameterSetRejected(t *testing.T) {
	msg := []byte("cross set")
	sets := []mldsa.ParameterSet{mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87}
	files := map[mldsa.ParameterSet]string{
		mldsa.MLDSA44: "mldsa44_seed.pem", mldsa.MLDSA65: "mldsa65_seed.pem", mldsa.MLDSA87: "mldsa87_seed.pem",
	}
	for _, signSet := range sets {
		_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, files[signSet]))
		if err != nil {
			t.Fatalf("parse seed: %v", err)
		}
		sig, err := mldsa.Sign(signSet, seed, msg)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		for _, verifySet := range sets {
			if verifySet == signSet {
				continue
			}
			pub, err := mldsa.PublicKeyFromSeed(verifySet, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if err := mldsa.Verify(verifySet, pub, msg, sig); err == nil {
				t.Errorf("%s signature verified as %s", signSet, verifySet)
			}
		}
	}
}

// TestInvalidInputs covers the argument-checking paths.
func TestInvalidInputs(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := mldsa.Sign(mldsa.ParameterSet(99), seed, nil); !errors.Is(err, mldsa.ErrUnsupportedParameterSet) {
		t.Errorf("unknown set: err = %v", err)
	}
	if _, err := mldsa.Sign(mldsa.MLDSA65, seed[:16], nil); !errors.Is(err, mldsa.ErrInvalidKey) {
		t.Errorf("short seed: err = %v", err)
	}
	if _, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed[:31]); !errors.Is(err, mldsa.ErrInvalidKey) {
		t.Errorf("short seed derive: err = %v", err)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, make([]byte, 10), nil, make([]byte, 3309)); !errors.Is(err, mldsa.ErrInvalidKey) {
		t.Errorf("short public key: err = %v", err)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, make([]byte, 1952), nil, make([]byte, 10)); !errors.Is(err, mldsa.ErrInvalidSignature) {
		t.Errorf("short signature: err = %v", err)
	}
	if err := mldsa.Verify(mldsa.ParameterSet(0), nil, nil, nil); !errors.Is(err, mldsa.ErrUnsupportedParameterSet) {
		t.Errorf("zero set: err = %v", err)
	}
}

// TestEmptyMessageSigns: an empty message is legal and must round-trip.
func TestEmptyMessageSigns(t *testing.T) {
	_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, "mldsa65_seed.pem"))
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sig, err := mldsa.Sign(mldsa.MLDSA65, seed, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, pub, nil, sig); err != nil {
		t.Errorf("empty message did not round-trip: %v", err)
	}
}

// sha256Of is a small helper for the determinism log line.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// TestCallerSeedNotMutated: this package zeroizes the seed copies it owns.
// It must never zeroize — or otherwise touch — the caller's slice, which the
// caller may still need (to derive a public key, or to write a key file).
func TestCallerSeedNotMutated(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse seed: %v", err)
			}
			original := append([]byte(nil), seed...)

			if _, err := mldsa.PublicKeyFromSeed(tc.set, seed); err != nil {
				t.Fatalf("derive: %v", err)
			}
			if !bytes.Equal(seed, original) {
				t.Fatal("PublicKeyFromSeed modified the caller's seed")
			}
			if _, err := mldsa.Sign(tc.set, seed, []byte("msg")); err != nil {
				t.Fatalf("sign: %v", err)
			}
			if !bytes.Equal(seed, original) {
				t.Fatal("Sign modified the caller's seed")
			}
			// Still usable afterwards.
			if _, err := mldsa.PublicKeyFromSeed(tc.set, seed); err != nil {
				t.Fatalf("seed unusable after Sign: %v", err)
			}
		})
	}
}
