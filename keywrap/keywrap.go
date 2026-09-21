// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keywrap

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/aleutian-ai/proof/internal/mem"
	"github.com/aleutian-ai/proof/xwing"
)

// V3Version is the version byte for the v3 wire format.
//
// Use this constant — never the magic literal 0x03.
const V3Version byte = 0x03

// V3Size is the total serialized size of a V3 blob.
const V3Size = 1169

// macKey is the fixed HMAC-SHA-512 key for V3 integrity verification.
//
// This is a publicly known key — the MAC protects against accidental corruption
// only, not targeted modification. See UnmarshalV3 for the security model.
var macKey = []byte("aleutian-kem-v3-mac")

// Byte offsets within the V3 wire format.
//
//	| version (1B) | key_id (16B) | mlkem_ct (1088B) | x25519_epk (32B) | mac (32B) |
//	|    0..1      |    1..17     |     17..1105      |   1105..1137      | 1137..1169 |
const (
	wrappedV3OffKeyID     = 1
	wrappedV3OffMLKEMCT   = 17
	wrappedV3OffX25519EPK = 1105
	wrappedV3OffMAC       = 1137
)

// Sentinel errors for V3 parsing.
var (
	// ErrLegacyRSAVersion is returned when the wire format contains version 0x01
	// (RSA-OAEP), which is no longer supported.
	ErrLegacyRSAVersion = errors.New(
		"RSA-OAEP (v1) wrapped keys are not supported; re-wrap under an X-Wing key pair",
	)

	// ErrUnsupportedVersion is returned when the wire format contains an
	// unrecognized version byte (neither 0x01 nor 0x03).
	ErrUnsupportedVersion = errors.New("unrecognized wrapped key version")

	// ErrInvalidMAC is returned when the HMAC-SHA-512 integrity check fails,
	// indicating the blob may be corrupted or tampered with.
	ErrInvalidMAC = errors.New("wrapped key integrity check failed — blob may be corrupted")
)

// V3 is the authenticated wire format for a v3 wrapped DEK.
//
// # Description
//
// Total serialized size: 1169 bytes.
// Field order matches XWING ciphertext spec: ct_M before ct_X.
//
// Wire layout:
//
//	| version (1B = 0x03) | key_id (16B) | mlkem_ct (1088B) | x25519_epk (32B) | mac (32B) |
//
// The MAC is HMAC-SHA-512 with a publicly known key ("aleutian-kem-v3-mac") over
// the first 1137 bytes. It protects against accidental corruption only — not
// targeted modification. Active attack prevention is provided by ML-KEM implicit
// rejection and AES-GCM authentication.
type V3 struct {
	Version   byte     // must be V3Version (0x03)
	KeyID     [16]byte // SHA-512(MLKEMPub ‖ X25519Pub)[:16] — fixed size, no aliasing
	MLKEMCT   []byte   // 1088 bytes — ML-KEM-768 ciphertext (ct_M); slice because 1088B is too large for stack
	X25519EPK [32]byte // X25519 ephemeral public key (ct_X) — fixed size, no aliasing
	MAC       [32]byte // HMAC-SHA-512 over preceding fields — fixed size, no aliasing
}

// MarshalBinary serializes the V3 to exactly 1169 bytes in wire order.
//
// # Description
//
// Writes fields in fixed order: version ‖ key_id ‖ mlkem_ct ‖ x25519_epk ‖ mac.
// Returns an error if any field has the wrong size.
//
// # Inputs
//
//   - receiver: V3 with all fields populated at correct sizes
//
// # Outputs
//
//   - []byte: 1169-byte wire format
//   - error: non-nil if any field length is invalid
//
// # Example
//
//	blob, err := wrapped.MarshalBinary()
//	if err != nil {
//	    return err
//	}
//	// blob is exactly 1169 bytes
//
// # Limitations
//
//   - Allocates a fresh 1169-byte slice on every call; does not pool.
//
// # Assumptions
//
//   - w was populated by KEMWrapper.Wrap or a trusted source
func (w V3) MarshalBinary() ([]byte, error) {
	if w.Version != V3Version {
		return nil, fmt.Errorf("wrapped key: version must be 0x%02x, got 0x%02x", V3Version, w.Version)
	}
	if len(w.MLKEMCT) != 1088 {
		return nil, fmt.Errorf("wrapped key: mlkem_ct must be 1088 bytes, got %d", len(w.MLKEMCT))
	}
	// KeyID [16]byte, X25519EPK [32]byte, MAC [32]byte are fixed-size arrays —
	// their sizes are enforced by the type system at compile time.

	out := make([]byte, V3Size)
	out[0] = w.Version
	copy(out[wrappedV3OffKeyID:], w.KeyID[:])
	copy(out[wrappedV3OffMLKEMCT:], w.MLKEMCT)
	copy(out[wrappedV3OffX25519EPK:], w.X25519EPK[:])
	copy(out[wrappedV3OffMAC:], w.MAC[:])
	return out, nil
}

// UnmarshalV3 parses a 1169-byte wire blob into a V3.
//
// # Description
//
// Validation order (security-critical — do not reorder):
//  1. Length check: len != 1169 → descriptive size error.
//  2. MAC verification: HMAC-SHA-512 over bytes [0,1137) compared to bytes [1137,1169).
//     Mismatch → ErrInvalidMAC. MAC is verified BEFORE version dispatch to prevent
//     accidentally reaching version-specific code paths on corrupted data. Note: since
//     the MAC key is publicly known, this ordering does NOT prevent an adversary from
//     crafting a blob that passes the MAC check — active attack prevention is provided
//     by ML-KEM implicit rejection and AES-GCM authentication.
//  3. Version dispatch: 0x01 → ErrLegacyRSAVersion; non-0x03 → ErrUnsupportedVersion.
//  4. Field extraction: split remaining bytes into struct fields.
//
// # Inputs
//
//   - data: exactly 1169 bytes (output of V3.MarshalBinary)
//
// # Outputs
//
//   - V3: parsed struct with independently allocated field slices
//   - error: see validation steps above for possible errors
//
// # Example
//
//	wrapped, err := UnmarshalV3(blob)
//	if err != nil {
//	    if errors.Is(err, ErrLegacyRSAVersion) {
//	        // guide customer to keygen
//	    }
//	    return err
//	}
//
// # Limitations
//
//   - Allocates new slices for all fields (no aliasing into data).
//
// # Assumptions
//
//   - data is the output of V3.MarshalBinary or a network transport
func UnmarshalV3(data []byte) (V3, error) {
	// Step 1: Length check.
	if len(data) != V3Size {
		return V3{}, fmt.Errorf("wrapped key: expected %d bytes, got %d", V3Size, len(data))
	}

	// Step 2: MAC verification BEFORE version dispatch.
	expectedMAC := computeWrappedKeyMAC(data[:wrappedV3OffMAC])
	if !hmac.Equal(data[wrappedV3OffMAC:], expectedMAC) {
		return V3{}, ErrInvalidMAC
	}

	// Step 3: Version dispatch.
	version := data[0]
	if version == 0x01 {
		return V3{}, ErrLegacyRSAVersion
	}
	if version != V3Version {
		return V3{}, ErrUnsupportedVersion
	}

	// Step 4: Field extraction.
	// KeyID, X25519EPK, MAC are fixed-size arrays — copy into them directly.
	// MLKEMCT stays as a slice (1088B too large for stack).
	var w V3
	w.Version = version
	copy(w.KeyID[:], data[wrappedV3OffKeyID:wrappedV3OffMLKEMCT])
	w.MLKEMCT = make([]byte, 1088)
	copy(w.MLKEMCT, data[wrappedV3OffMLKEMCT:wrappedV3OffX25519EPK])
	copy(w.X25519EPK[:], data[wrappedV3OffX25519EPK:wrappedV3OffMAC])
	copy(w.MAC[:], data[wrappedV3OffMAC:])

	return w, nil
}

// computeWrappedKeyMAC computes HMAC-SHA-512 over the given data using the fixed
// public MAC key "aleutian-kem-v3-mac".
//
// The input should be the first 1137 bytes of the wire format (everything before
// the MAC field).
func computeWrappedKeyMAC(data []byte) []byte {
	// HMAC-SHA-512 truncated to 256 bits per NIST SP 800-107 §5.3.4.
	// Truncation to half the hash output is explicitly permitted; the wire
	// format reserves 32 bytes for the MAC field (V3 was sized
	// pre-sweep). Truncated MAC retains 128-bit forgery resistance which is
	// the bottleneck regardless of inner hash choice.
	mac := hmac.New(sha512.New, macKey)
	mac.Write(data)
	return mac.Sum(nil)[:32]
}

// ComputeWrappedKeyV3MAC creates a V3 blob from its components.
//
// # Description
//
// Builds a complete V3 struct from the given XWING ciphertext and public
// key. Computes the key ID as SHA-512(MLKEMPub ‖ X25519Pub)[:16] and the MAC over
// all preceding wire fields.
//
// This is the construction helper callers use after encapsulating.
//
// # Inputs
//
//   - ct: XWING ciphertext from xwing.Encapsulate
//   - pub: the recipient's public key (used to compute key ID)
//
// # Outputs
//
//   - V3: fully populated, ready for MarshalBinary
//   - error: non-nil if field sizes are invalid
//
// # Example
//
//	ct, ss, err := xwing.Encapsulate(pub)
//	if err != nil {
//	    return err
//	}
//	wrapped, err := NewV3(ct, pub)
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - ct and pub are from the same encapsulation operation
func NewV3(ct xwing.Ciphertext, pub xwing.PublicKey) (V3, error) {
	if len(ct.MLKEMCT) != 1088 {
		return V3{}, fmt.Errorf("wrapped key: mlkem_ct must be 1088 bytes, got %d", len(ct.MLKEMCT))
	}
	if len(ct.X25519EPK) != 32 {
		return V3{}, fmt.Errorf("wrapped key: x25519_epk must be 32 bytes, got %d", len(ct.X25519EPK))
	}

	keyID, err := pub.KeyID()
	if err != nil {
		return V3{}, fmt.Errorf("wrapped key: compute key ID: %w", err)
	}

	// Copy MLKEMCT — prevent aliasing so caller zeroization cannot corrupt the
	// V3 before MarshalBinary is called. X25519EPK is a [32]byte
	// (value type) so it copies automatically.
	mlkemCT := make([]byte, len(ct.MLKEMCT))
	copy(mlkemCT, ct.MLKEMCT)

	var x25519EPK [32]byte
	copy(x25519EPK[:], ct.X25519EPK)

	// Build the MAC input: version ‖ key_id ‖ mlkem_ct ‖ x25519_epk
	macInput := make([]byte, wrappedV3OffMAC)
	defer mem.Zeroize(macInput)
	macInput[0] = V3Version
	copy(macInput[wrappedV3OffKeyID:], keyID[:])
	copy(macInput[wrappedV3OffMLKEMCT:], mlkemCT)
	copy(macInput[wrappedV3OffX25519EPK:], x25519EPK[:])

	var mac [32]byte
	copy(mac[:], computeWrappedKeyMAC(macInput))

	return V3{
		Version:   V3Version,
		KeyID:     keyID,
		MLKEMCT:   mlkemCT,
		X25519EPK: x25519EPK,
		MAC:       mac,
	}, nil
}
