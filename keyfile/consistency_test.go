// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile_test

import (
	"bytes"
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/xwing"
)

// TestSeedDerivesTheSpecPublicKey is the end-to-end check that a parsed seed is
// the RIGHT seed: expanded by an independent implementation, it must produce
// the public key the specification publishes for that example.
//
// crypto/mlkem (standard library) covers ML-KEM-768/1024; circl covers
// ML-KEM-512 and all three ML-DSA sets; proof/xwing covers X-Wing. All are
// test-only imports — `go list -deps` without -test shows this package is
// stdlib-only, which TestDependencyIsolation enforces.
func TestSeedDerivesTheSpecPublicKey(t *testing.T) {
	derive := map[keyfile.Algorithm]func(seed []byte) ([]byte, error){
		keyfile.MLKEM512: func(seed []byte) ([]byte, error) {
			// circl takes the 64-byte seed (d ‖ z) directly.
			pub, _ := mlkem512.NewKeyFromSeed(seed)
			out := make([]byte, mlkem512.PublicKeySize)
			pub.Pack(out)
			return out, nil
		},
		keyfile.MLKEM768: func(seed []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, err
			}
			return dk.EncapsulationKey().Bytes(), nil
		},
		keyfile.MLKEM1024: func(seed []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, err
			}
			return dk.EncapsulationKey().Bytes(), nil
		},
		keyfile.MLDSA44: func(seed []byte) ([]byte, error) {
			var s [32]byte
			copy(s[:], seed)
			pub, _ := mldsa44.NewKeyFromSeed(&s)
			return pub.Bytes(), nil
		},
		keyfile.MLDSA65: func(seed []byte) ([]byte, error) {
			var s [32]byte
			copy(s[:], seed)
			pub, _ := mldsa65.NewKeyFromSeed(&s)
			return pub.Bytes(), nil
		},
		keyfile.MLDSA87: func(seed []byte) ([]byte, error) {
			var s [32]byte
			copy(s[:], seed)
			pub, _ := mldsa87.NewKeyFromSeed(&s)
			return pub.Bytes(), nil
		},
		keyfile.XWing: func(seed []byte) ([]byte, error) {
			priv, err := xwing.NewPrivateKey(seed)
			if err != nil {
				return nil, err
			}
			pub, err := priv.PublicKey()
			if err != nil {
				return nil, err
			}
			return pub.MarshalBinary()
		},
	}

	for _, tc := range rfcCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(read(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse private: %v", err)
			}
			_, wantPub, err := keyfile.ParsePublicKey(read(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			gotPub, err := derive[tc.alg](seed)
			if err != nil {
				t.Fatalf("derive public key: %v", err)
			}
			if !bytes.Equal(gotPub, wantPub) {
				t.Errorf("public key derived from the parsed seed does not match the specification's public key")
			}
		})
	}
}

// TestBadKeysFromTheSpec runs RFC 9935's and RFC 9881's deliberately bad
// private keys.
//
// Each expectation states WHY, because two of them are accepted on purpose:
// this package returns only the seed, and checking the rest would require an
// algorithm implementation it deliberately does not carry.
func TestBadKeysFromTheSpec(t *testing.T) {
	tests := []struct {
		file   string
		want   error // nil means "parses; see why"
		reason string
	}{
		{
			// NOT caught here, and the reason is precise: this example's expanded
			// key belongs to a DIFFERENT key pair but is internally consistent —
			// its z matches the seed's second half and its embedded H(ek) matches
			// its embedded ek. Only re-deriving ek from the seed exposes it, and
			// crypto/mlkem implements ML-KEM-768/1024, not 512. The equivalent
			// damage IS caught for 768 and 1024 — see
			// TestConsistencyCatchesTamperedSeed. Harmless here because only the
			// seed is returned and used. aleutianchain_34 would close it.
			"bad_mlkem512_both_1_inconsistent.pem", nil,
			"ML-KEM-512 expanded key is self-consistent but belongs to another key pair; needs derivation this package cannot do for 512",
		},
		{
			"bad_mlkem512_expanded_2_mutated_s.pem", keyfile.ErrExpandedKeyOnly,
			"expandedKey-only: rejected before any mutation matters — there is no seed",
		},
		{
			"bad_mlkem512_expanded_3_mutated_hek.pem", keyfile.ErrExpandedKeyOnly,
			"expandedKey-only: same",
		},
		{
			"bad_mlkem512_both_4_z_mismatch.pem", keyfile.ErrInconsistentKey,
			"example 4: only z differs — caught without any derivation, since z is the seed's second half",
		},
		{
			"bad_mldsa44_both_1_inconsistent.pem", nil,
			"ML-DSA both-form consistency needs an ML-DSA implementation; only the seed is used, so the unchecked half is never read (see CheckConsistency)",
		},
		{
			"bad_mldsa44_expanded_2_mutated.pem", keyfile.ErrExpandedKeyOnly,
			"expandedKey-only: no seed",
		},
		{
			"bad_mldsa44_expanded_3_mutated.pem", keyfile.ErrExpandedKeyOnly,
			"expandedKey-only: no seed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(read(t, tc.file))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("expected this key to parse (%s), got %v", tc.reason, err)
				}
				if len(seed) == 0 {
					t.Error("parsed with an empty seed")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v (%s)", err, tc.want, tc.reason)
			}
		})
	}
}

// TestConsistencyCatchesTamperedSeed builds an inconsistent both-form key from
// a GOOD spec example by flipping one byte of the seed, for each ML-KEM set.
// This covers ML-KEM-768/1024, where the check re-derives the public key — the
// spec's bad examples are all ML-KEM-512.
func TestConsistencyCatchesTamperedSeed(t *testing.T) {
	for _, tc := range []struct {
		alg  keyfile.Algorithm
		file string
	}{
		{keyfile.MLKEM512, "mlkem512_both.pem"},
		{keyfile.MLKEM768, "mlkem768_both.pem"},
		{keyfile.MLKEM1024, "mlkem1024_both.pem"},
	} {
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, seed, err := keyfile.ParsePrivateKey(read(t, tc.file))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// Flip a bit in the d half (first 32 bytes): z still matches, so
			// this is caught only by re-deriving — or not at all for ML-KEM-512.
			tampered := append([]byte(nil), seed...)
			tampered[0] ^= 0x01
			if err := keyfile.CheckConsistency(tc.alg, tampered, expandedFrom(t, tc.file)); err == nil {
				if tc.alg == keyfile.MLKEM512 {
					t.Skip("ML-KEM-512: no derivation available in this package; documented limitation")
				}
				t.Error("tampered seed accepted")
			}

			// Flipping the z half is caught for every ML-KEM set, with no derivation.
			tampered = append([]byte(nil), seed...)
			tampered[len(tampered)-1] ^= 0x01
			if err := keyfile.CheckConsistency(tc.alg, tampered, expandedFrom(t, tc.file)); !errors.Is(err, keyfile.ErrInconsistentKey) {
				t.Errorf("tampered z accepted: %v", err)
			}
		})
	}
}

// expandedFrom extracts the expandedKey half of a both-form fixture.
//
// The package returns only seeds, deliberately, so the test decodes the file
// itself to reach the expanded half and feed CheckConsistency directly.
func expandedFrom(t *testing.T, file string) []byte {
	t.Helper()
	block, _ := pem.Decode(read(t, file))
	if block == nil {
		t.Fatalf("%s: no PEM block", file)
	}
	var k struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(block.Bytes, &k); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	var both struct {
		Seed     []byte
		Expanded []byte
	}
	if _, err := asn1.Unmarshal(k.PrivateKey, &both); err != nil {
		t.Fatalf("%s: not a both-form key: %v", file, err)
	}
	return both.Expanded
}
