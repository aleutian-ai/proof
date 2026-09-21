// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package xwing

import (
	"crypto/sha512"
	"fmt"
)

// KeyID returns the first 16 bytes of SHA-512(MLKEMPub ‖ X25519Pub).
//
// # Description
//
// Hashes the full public key (both ML-KEM and X25519 components) so that two keys
// sharing the same ML-KEM component but differing in X25519 produce distinct IDs.
// Used to identify which private key to use for decapsulation after key rotation,
// avoiding trial-and-error decapsulation.
//
// Hash order is MLKEMPub THEN X25519Pub — this is canonical and does NOT match
// the struct field declaration order. Cross-language SDK implementations must
// follow this exact order.
//
// # Inputs
//
//   - receiver: PublicKey with both fields populated at correct sizes
//
// # Outputs
//
//   - [16]byte: key identifier (truncated SHA-512 digest)
//   - error: ErrInvalidPublicKey if MLKEMPub is not 1184 bytes or X25519Pub is not 32 bytes
//
// # Example
//
//	kid, err := pub.KeyID()
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Key ID: %x\n", kid)
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - pub was produced by GenerateKeyPair, PublicKey, or UnmarshalPublicKey
func (k PublicKey) KeyID() ([16]byte, error) {
	if len(k.MLKEMPub) != 1184 || len(k.X25519Pub) != 32 {
		return [16]byte{}, ErrInvalidPublicKey
	}
	h := sha512.New()
	h.Write(k.MLKEMPub)
	h.Write(k.X25519Pub)
	digest := h.Sum(nil)
	var kid [16]byte
	copy(kid[:], digest[:16])
	return kid, nil
}

// KeyIDHex returns the 32-character lowercase hex string identifying this public key.
//
// # Description
//
// Delegates to KeyID() and hex-encodes the result. This produces the same value
// used as a key fingerprint elsewhere (^[0-9a-f]{32}$). Using this method instead of computing the fingerprint from raw
// bytes ensures consistency with the wrapped-key format's key id regardless of encoding.
//
// # Outputs
//
//   - string: 32-character lowercase hex string (SHA-512(MLKEMPub ‖ X25519Pub)[:16])
//   - error: ErrInvalidPublicKey if field lengths are wrong
func (k PublicKey) KeyIDHex() (string, error) {
	kid, err := k.KeyID()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", kid), nil
}
