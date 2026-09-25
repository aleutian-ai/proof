// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// keyIDDomain separates key-id hashing from every other use of SHA-512 in this
// module, and from the X-Wing scheme below.
const keyIDDomain = "proof.keyid.v1:"

// KeyIDSize is the length of a key identifier in bytes.
const KeyIDSize = 16

// KeyID returns a short, stable identifier for a public key.
//
// # Description
//
// A key id says WHICH key a wrapped key, anchor, or config entry refers to,
// without carrying the key itself. Two schemes exist, and the split is
// deliberate:
//
//	X-Wing        SHA-512(public key)[:16]
//	              Grandfathered. This is what every wrapped key and tenant
//	              fingerprint in the platform already contains, so it cannot
//	              change without orphaning stored data.
//
//	everything    SHA-512("proof.keyid.v1:" ‖ SubjectPublicKeyInfo)[:16]
//	else          The SPKI encoding embeds the algorithm's object identifier,
//	              so the algorithm is bound into the id by construction: the
//	              same bytes under two algorithms cannot collide.
//
// # Inputs
//
//   - alg: the algorithm the key belongs to
//   - pub: the raw public key, exactly alg.PublicKeySize() bytes
//
// # Outputs
//
//   - [KeyIDSize]byte: the identifier
//   - error: ErrUnsupportedAlgorithm or ErrMalformed for a wrong-sized key
//
// # Example
//
//	id, err := keyfile.KeyID(keyfile.MLDSA65, pub)
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Truncated to 128 bits. That is collision resistance of about 2^64 under a
//     birthday attack, which is fine for identifying keys you already hold and
//     is NOT a substitute for verifying a key.
//   - Not a fingerprint for humans to compare aloud; use KeyIDHex for display.
//
// # Assumptions
//
//   - pub is the algorithm's canonical public key encoding.
func KeyID(alg Algorithm, pub []byte) ([KeyIDSize]byte, error) {
	var id [KeyIDSize]byte
	info, ok := algorithms[alg]
	if !ok {
		return id, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, int(alg))
	}
	if len(pub) != info.publicSize {
		return id, fmt.Errorf("%w: %s public key must be %d bytes, got %d",
			ErrMalformed, info.name, info.publicSize, len(pub))
	}

	if alg == XWing {
		// Grandfathered: SHA-512 over the canonical encoding, which is exactly
		// MLKEMPub ‖ X25519Pub. Matches xwing.PublicKey.KeyID byte for byte —
		// asserted by test — so existing wrapped keys keep resolving.
		sum := sha512.Sum512(pub)
		copy(id[:], sum[:KeyIDSize])
		return id, nil
	}

	spkiPEM, err := MarshalPublicKey(alg, pub)
	if err != nil {
		return id, err
	}
	block, _ := pem.Decode(spkiPEM)
	if block == nil {
		return id, fmt.Errorf("%w: could not re-encode the public key", ErrMalformed)
	}
	h := sha512.New()
	h.Write([]byte(keyIDDomain))
	h.Write(block.Bytes)
	copy(id[:], h.Sum(nil)[:KeyIDSize])
	return id, nil
}

// KeyIDHex returns the key id as 32 lowercase hex characters.
//
// # Description
//
// The display form, and the form stored in configuration — it matches the
// `^[0-9a-f]{32}$` shape the platform already uses for key fingerprints.
//
// # Inputs
//
//   - alg: the algorithm the key belongs to
//   - pub: the raw public key
//
// # Outputs
//
//   - string: 32 lowercase hex characters
//   - error: as [KeyID]
//
// # Example
//
//	s, err := keyfile.KeyIDHex(keyfile.XWing, pub)
//
// # Limitations
//
//   - See [KeyID] on truncation.
//
// # Assumptions
//
//   - None beyond those of [KeyID].
func KeyIDHex(alg Algorithm, pub []byte) (string, error) {
	id, err := KeyID(alg, pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
