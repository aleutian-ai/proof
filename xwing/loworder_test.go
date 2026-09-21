// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package xwing

import (
	"bytes"
	"testing"
)

// lowOrderPoints are X25519 inputs whose scalar multiplication yields the
// all-zero shared secret. Taken from the canonical set used by RFC 7748
// implementations (order 1, 2, 4, and 8 subgroup points plus the two
// non-canonical p-1 / p encodings).
var lowOrderPoints = [][32]byte{
	// order 1
	{0x00},
	// order 2
	{0x01},
	// order 4
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	// order 8
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	// p-1 (order 2^255-19 - 1)
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	// p
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// TestEncapsulateLowOrderX25519PointDoesNotFail pins the X-Wing spec §4.2
// requirement that a low-order X25519 point MUST NOT cause encapsulation to
// fail.
//
// ML-KEM-768 supplies independent post-quantum security, so the combined secret
// remains safe even when the X25519 half degenerates to all zeros. An
// implementation that rejects these inputs is NOT X-Wing — it would refuse
// ciphertexts a conforming peer can legitimately produce.
//
// This test exists to guard a migration from x/crypto/curve25519 to crypto/ecdh
// (aleutianchain_02); crypto/ecdh returns an error on the all-zero result, so
// the zero-substitution must be carried across deliberately.
func TestEncapsulateLowOrderX25519PointDoesNotFail(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	defer priv.Zeroize()
	real, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	for i, lop := range lowOrderPoints {
		pub := PublicKey{MLKEMPub: real.MLKEMPub, X25519Pub: append([]byte(nil), lop[:]...)}

		ct, ss, err := Encapsulate(pub)
		if err != nil {
			t.Fatalf("low-order point %d: Encapsulate returned error %v; spec §4.2 requires success", i, err)
		}
		if ss == (SharedSecret{}) {
			t.Fatalf("low-order point %d: shared secret is all zero; the combiner must still mix ss_M", i)
		}
		if len(ct.MLKEMCT) != 1088 || len(ct.X25519EPK) != 32 {
			t.Fatalf("low-order point %d: malformed ciphertext", i)
		}
	}
}

// TestDecapsulateLowOrderCiphertextDoesNotFail is the receiving-side mirror:
// a ciphertext carrying a low-order ct_X must decapsulate without error.
func TestDecapsulateLowOrderCiphertextDoesNotFail(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	defer priv.Zeroize()

	ct, _, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	for i, lop := range lowOrderPoints {
		tampered := Ciphertext{
			MLKEMCT:   append([]byte(nil), ct.MLKEMCT...),
			X25519EPK: append([]byte(nil), lop[:]...),
		}
		ss, err := Decapsulate(tampered, priv)
		if err != nil {
			t.Fatalf("low-order ct_X %d: Decapsulate returned error %v; spec §4.2 requires success", i, err)
		}
		if ss == (SharedSecret{}) {
			t.Fatalf("low-order ct_X %d: shared secret is all zero", i)
		}
	}
}

// TestRoundTripStillAgrees is the baseline that must survive the migration.
func TestRoundTripStillAgrees(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	defer priv.Zeroize()

	ct, ssEnc, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	ssDec, err := Decapsulate(ct, priv)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc[:], ssDec[:]) {
		t.Fatal("encapsulate/decapsulate shared secrets disagree")
	}
}
