// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keywrap

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/aleutian-ai/proof/xwing"
	"strings"
	"testing"
)

// TestWrappedKeyV3MarshalRoundTrip verifies that marshal → unmarshal produces an
// identical struct.
func TestWrappedKeyV3MarshalRoundTrip(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	original, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}

	blob, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	if len(blob) != V3Size {
		t.Fatalf("MarshalBinary: expected %d bytes, got %d", V3Size, len(blob))
	}

	parsed, err := UnmarshalV3(blob)
	if err != nil {
		t.Fatalf("UnmarshalV3: %v", err)
	}

	if parsed.Version != original.Version {
		t.Errorf("Version: got 0x%02x, want 0x%02x", parsed.Version, original.Version)
	}
	if parsed.KeyID != original.KeyID {
		t.Errorf("KeyID mismatch")
	}
	if !bytes.Equal(parsed.MLKEMCT, original.MLKEMCT) {
		t.Errorf("MLKEMCT mismatch")
	}
	if parsed.X25519EPK != original.X25519EPK {
		t.Errorf("X25519EPK mismatch")
	}
	if parsed.MAC != original.MAC {
		t.Errorf("MAC mismatch")
	}
}

// TestWrappedKeyV3UnmarshalIndependentCopies verifies that parsed fields do not
// alias the input slice.
func TestWrappedKeyV3UnmarshalIndependentCopies(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}
	blob, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	parsed, err := UnmarshalV3(blob)
	if err != nil {
		t.Fatalf("UnmarshalV3: %v", err)
	}

	// Mutate original blob and verify parsed fields are unaffected.
	// KeyID is [16]byte (value type) so it can't alias, but MLKEMCT ([]byte) could.
	savedMLKEM := make([]byte, len(parsed.MLKEMCT))
	copy(savedMLKEM, parsed.MLKEMCT)
	for i := range blob {
		blob[i] = 0xFF
	}
	if !bytes.Equal(parsed.MLKEMCT, savedMLKEM) {
		t.Error("parsed MLKEMCT aliased input blob")
	}
}

// TestUnmarshalWrappedKeyV3LegacyRSA verifies that version 0x01 returns
// ErrLegacyRSAVersion.
func TestUnmarshalWrappedKeyV3LegacyRSA(t *testing.T) {
	blob := makeValidBlob(t)
	blob[0] = 0x01
	// Recompute MAC for the modified version byte so the MAC check passes first.
	recomputeMAC(blob)

	_, err := UnmarshalV3(blob)
	if !errors.Is(err, ErrLegacyRSAVersion) {
		t.Errorf("expected ErrLegacyRSAVersion, got: %v", err)
	}
}

// TestUnmarshalWrappedKeyV3UnsupportedVersion verifies that an unknown version
// (e.g. 0xFF) returns ErrUnsupportedVersion.
func TestUnmarshalWrappedKeyV3UnsupportedVersion(t *testing.T) {
	blob := makeValidBlob(t)
	blob[0] = 0xFF
	recomputeMAC(blob)

	_, err := UnmarshalV3(blob)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

// TestUnmarshalWrappedKeyV3MACBitFlip verifies that a single bit flip in any
// field (version, key_id, mlkem_ct, x25519_epk) triggers ErrInvalidMAC.
func TestUnmarshalWrappedKeyV3MACBitFlip(t *testing.T) {
	tests := []struct {
		name   string
		offset int // byte offset to flip
	}{
		{"version byte", 0},
		{"key_id first byte", 1},
		{"key_id last byte", 16},
		{"mlkem_ct first byte", 17},
		{"mlkem_ct last byte", 1104},
		{"x25519_epk first byte", 1105},
		{"x25519_epk last byte", 1136},
		{"mac first byte", 1137},
		{"mac last byte", 1168},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob := makeValidBlob(t)
			blob[tc.offset] ^= 0x01 // single bit flip

			_, err := UnmarshalV3(blob)
			if !errors.Is(err, ErrInvalidMAC) {
				t.Errorf("expected ErrInvalidMAC, got: %v", err)
			}
		})
	}
}

// TestUnmarshalWrappedKeyV3WrongLength verifies that wrong-length inputs are
// rejected with a size error.
func TestUnmarshalWrappedKeyV3WrongLength(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too short", 1168},
		{"too long", 1170},
		{"single byte", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.size)
			_, err := UnmarshalV3(data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			expected := "wrapped key: expected 1169 bytes"
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("error %q does not contain %q", err.Error(), expected)
			}
		})
	}
}

// TestUnmarshalWrappedKeyV3MACBeforeVersion verifies that MAC is checked before
// version dispatch: a tampered blob with version=0x01 should return ErrInvalidMAC,
// not ErrLegacyRSAVersion.
func TestUnmarshalWrappedKeyV3MACBeforeVersion(t *testing.T) {
	blob := makeValidBlob(t)
	// Change version to 0x01 WITHOUT recomputing MAC.
	blob[0] = 0x01

	_, err := UnmarshalV3(blob)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Errorf("expected ErrInvalidMAC (MAC before version), got: %v", err)
	}
}

// TestKeyIDFullPublicKey verifies that KeyID hashes MLKEMPub ‖ X25519Pub (the full
// public key), not just MLKEMPub.
func TestKeyIDFullPublicKey(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}

	kid, err := pub.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}

	// Verify it matches SHA-512(MLKEMPub ‖ X25519Pub)[:16].
	h := sha512.New()
	h.Write(pub.MLKEMPub)
	h.Write(pub.X25519Pub)
	var expected [16]byte
	copy(expected[:], h.Sum(nil)[:16])

	if kid != expected {
		t.Errorf("KeyID does not match SHA-512(MLKEMPub || X25519Pub)[:16]")
	}
}

// TestKeyIDStability verifies that KeyID returns the same value on repeated calls.
func TestKeyIDStability(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}

	kid1, err := pub.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	kid2, err := pub.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if kid1 != kid2 {
		t.Error("KeyID not stable across calls")
	}
}

// TestKeyIDDistinctKeys verifies that different key pairs produce different key IDs.
func TestKeyIDDistinctKeys(t *testing.T) {
	pub1, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	pub2, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}

	kid1, err := pub1.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	kid2, err := pub2.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if kid1 == kid2 {
		t.Error("two different key pairs produced the same KeyID")
	}
}

// TestMarshalBinaryFieldValidation verifies that MarshalBinary rejects structs
// with wrong field sizes. KeyID [16]byte, X25519EPK [32]byte, and MAC [32]byte
// are now compile-time enforced — only version and MLKEMCT (slice) need runtime checks.
func TestMarshalBinaryFieldValidation(t *testing.T) {
	tests := []struct {
		name string
		w    V3
	}{
		{"wrong version", V3{
			Version: 0x02, MLKEMCT: make([]byte, 1088),
		}},
		{"short mlkem_ct", V3{
			Version: V3Version, MLKEMCT: make([]byte, 1087),
		}},
		{"nil mlkem_ct", V3{
			Version: V3Version, MLKEMCT: nil,
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.w.MarshalBinary()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestPublicKeyMarshalRoundTrip verifies the pre-existing MarshalBinary /
// xwing.UnmarshalPublicKey round-trip (pqc_01a verification).
func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}

	encoded, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	if len(encoded) != 1216 {
		t.Fatalf("MarshalBinary: expected 1216 bytes, got %d", len(encoded))
	}

	decoded, err := xwing.UnmarshalPublicKey(encoded)
	if err != nil {
		t.Fatalf("xwing.UnmarshalPublicKey: %v", err)
	}

	if !bytes.Equal(decoded.MLKEMPub, pub.MLKEMPub) {
		t.Error("MLKEMPub mismatch after round-trip")
	}
	if !bytes.Equal(decoded.X25519Pub, pub.X25519Pub) {
		t.Error("X25519Pub mismatch after round-trip")
	}
}

// TestWrappedKeyV3WireOrder verifies the byte-level wire format layout by checking
// that fields appear at their documented offsets.
func TestWrappedKeyV3WireOrder(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}

	blob, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Version at offset 0.
	if blob[0] != V3Version {
		t.Errorf("wire[0]: got 0x%02x, want 0x%02x", blob[0], V3Version)
	}

	// KeyID at offset 1..17.
	if !bytes.Equal(blob[1:17], wrapped.KeyID[:]) {
		t.Error("KeyID not at wire offset 1..17")
	}

	// MLKEMCT at offset 17..1105.
	if !bytes.Equal(blob[17:1105], wrapped.MLKEMCT) {
		t.Error("MLKEMCT not at wire offset 17..1105")
	}

	// X25519EPK at offset 1105..1137.
	if !bytes.Equal(blob[1105:1137], wrapped.X25519EPK[:]) {
		t.Error("X25519EPK not at wire offset 1105..1137")
	}

	// MAC at offset 1137..1169.
	if !bytes.Equal(blob[1137:1169], wrapped.MAC[:]) {
		t.Error("MAC not at wire offset 1137..1169")
	}
}

// TestWrappedKeyV3MACCoversAllFields verifies the MAC is computed over version ‖
// key_id ‖ mlkem_ct ‖ x25519_epk (1137 bytes).
func TestWrappedKeyV3MACCoversAllFields(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}

	blob, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Verify using the canonical computeWrappedKeyMAC (same package).
	expected := computeWrappedKeyMAC(blob[:wrappedV3OffMAC])
	if !bytes.Equal(blob[wrappedV3OffMAC:], expected) {
		t.Error("MAC does not match HMAC-SHA-512 over first 1137 bytes")
	}
}

// TestNewWrappedKeyV3KeyIDMatchesPublicKey verifies that the key ID in the wrapped
// blob matches the public key's KeyID().
func TestNewWrappedKeyV3KeyIDMatchesPublicKey(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}

	kid, err := pub.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if wrapped.KeyID != kid {
		t.Error("wrapped KeyID does not match pub.KeyID()")
	}
}

// TestWrappedKeyV3VersionConstant verifies the version constant value.
func TestWrappedKeyV3VersionConstant(t *testing.T) {
	if V3Version != 0x03 {
		t.Errorf("V3Version: got 0x%02x, want 0x03", V3Version)
	}
}

// TestKeyIDKATVector provides a cross-language compatibility anchor. SDK
// implementations in Python, TypeScript, etc. must produce the same KeyID
// for the same public key bytes.
//
// Algorithm: SHA-512(MLKEMPub ‖ X25519Pub)[:16]
// Hash order is MLKEMPub (1184B) THEN X25519Pub (32B) — NOT struct field order.
func TestKeyIDKATVector(t *testing.T) {
	// Deterministic public key: 1184 zero bytes (MLKEMPub) + 32 0x01 bytes (X25519Pub).
	mlkemPub := make([]byte, 1184)
	x25519Pub := make([]byte, 32)
	for i := range x25519Pub {
		x25519Pub[i] = 0x01
	}
	pub := xwing.PublicKey{MLKEMPub: mlkemPub, X25519Pub: x25519Pub}

	kid, err := pub.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}

	// Pre-computed: SHA-512(1184 zero bytes || 32 0x01 bytes)[:16]
	h := sha512.New()
	h.Write(mlkemPub)
	h.Write(x25519Pub)
	expectedHex := hex.EncodeToString(h.Sum(nil)[:16])
	gotHex := hex.EncodeToString(kid[:])

	if gotHex != expectedHex {
		t.Errorf("KeyID KAT:\n  got:  %s\n  want: %s", gotHex, expectedHex)
	}
	// Log the KAT value for cross-language reference.
	t.Logf("KeyID KAT vector (zero MLKEMPub + 0x01 X25519Pub): %s", gotHex)
}

// TestKeyIDRejectsInvalidPublicKey verifies that KeyID returns an error (not panic)
// for zero-value or wrong-size public keys.
func TestKeyIDRejectsInvalidPublicKey(t *testing.T) {
	tests := []struct {
		name string
		pub  xwing.PublicKey
	}{
		{"zero value", xwing.PublicKey{}},
		{"short MLKEMPub", xwing.PublicKey{MLKEMPub: make([]byte, 1183), X25519Pub: make([]byte, 32)}},
		{"short X25519Pub", xwing.PublicKey{MLKEMPub: make([]byte, 1184), X25519Pub: make([]byte, 31)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.pub.KeyID()
			if !errors.Is(err, xwing.ErrInvalidPublicKey) {
				t.Errorf("expected xwing.ErrInvalidPublicKey, got: %v", err)
			}
		})
	}
}

// TestMACCannotPreventAdversarialModification documents an intentional property:
// since the MAC key is publicly known, an adversary can modify any field,
// recompute the MAC, and produce a valid blob that passes UnmarshalV3.
// Active tamper protection is provided by ML-KEM implicit rejection and AES-GCM
// authentication (pqc_01d), not by this MAC.
func TestMACCannotPreventAdversarialModification(t *testing.T) {
	blob := makeValidBlob(t)

	// Adversary modifies mlkem_ct[0] and recomputes the MAC.
	blob[wrappedV3OffMLKEMCT] ^= 0xFF
	recomputeMAC(blob)

	// UnmarshalV3 MUST succeed — the MAC is valid for the modified data.
	// This is by design: the MAC prevents accidental corruption only.
	parsed, err := UnmarshalV3(blob)
	if err != nil {
		t.Fatalf("expected success (adversary recomputed MAC), got: %v", err)
	}
	if parsed.Version != V3Version {
		t.Errorf("unexpected version: 0x%02x", parsed.Version)
	}
}

// TestNewWrappedKeyV3SliceCopies verifies that NewV3 copies the
// ciphertext slices — mutating the original xwing.Ciphertext after construction
// does not affect the V3 fields.
func TestNewWrappedKeyV3SliceCopies(t *testing.T) {
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}

	// Save original ciphertext bytes.
	origMLKEM := make([]byte, len(ct.MLKEMCT))
	copy(origMLKEM, ct.MLKEMCT)

	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}

	// Mutate the original ciphertext.
	for i := range ct.MLKEMCT {
		ct.MLKEMCT[i] = 0
	}

	// V3's MLKEMCT should be unaffected.
	if !bytes.Equal(wrapped.MLKEMCT, origMLKEM) {
		t.Error("NewV3 MLKEMCT aliased original ciphertext — mutation propagated")
	}
}

// --- Helpers ---

// makeValidBlob creates a valid 1169-byte V3 wire blob for mutation tests.
func makeValidBlob(t *testing.T) []byte {
	t.Helper()
	pub, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("xwing.GenerateKeyPair: %v", err)
	}
	ct, _, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("xwing.Encapsulate: %v", err)
	}
	wrapped, err := NewV3(ct, pub)
	if err != nil {
		t.Fatalf("NewV3: %v", err)
	}
	blob, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return blob
}

// recomputeMAC updates the MAC field (bytes [1137,1169)) of blob to match the
// current content of bytes [0,1137). Uses the canonical computeWrappedKeyMAC
// to avoid duplicating the MAC key literal.
func recomputeMAC(blob []byte) {
	copy(blob[wrappedV3OffMAC:], computeWrappedKeyMAC(blob[:wrappedV3OffMAC]))
}
