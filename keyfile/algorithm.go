// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import "encoding/asn1"

// sentinelError is the type of this package's sentinel errors.
//
// Constants, not variables, so no code in the process can reassign one — a nil
// sentinel would turn a rejected key file into an accepted one. Same reasoning
// as the xwing package.
type sentinelError string

// Error implements the error interface.
func (e sentinelError) Error() string { return string(e) }

// Errors returned when a key file cannot be used. Compare with errors.Is.
const (
	// ErrMalformed means the file is not a well-formed key file: bad PEM, bad
	// DER, trailing data, an unexpected structure, or a wrong-sized field.
	ErrMalformed sentinelError = "keyfile: malformed key file"

	// ErrUnsupportedAlgorithm means the algorithm identifier is not one this
	// package knows. The algorithm is never inferred from a length.
	ErrUnsupportedAlgorithm sentinelError = "keyfile: unsupported algorithm identifier"

	// ErrExpandedKeyOnly means the private key contains only an expanded key.
	// Expansion is one-way, so no seed can be recovered, and this module's APIs
	// take seeds.
	ErrExpandedKeyOnly sentinelError = "keyfile: private key has no seed (expandedKey-only form)"

	// ErrInconsistentKey means a "both"-form private key's seed and expanded key
	// disagree. RFC 9935 requires rejecting such a key once the check is run.
	ErrInconsistentKey sentinelError = "keyfile: seed and expanded private key are inconsistent"
)

// Algorithm identifies a key's algorithm, as read from the file.
type Algorithm int

// The algorithms this package can read and write.
const (
	// Unknown is the zero value and is never returned with a nil error.
	Unknown Algorithm = iota

	MLKEM512
	MLKEM768
	MLKEM1024

	MLDSA44
	MLDSA65
	MLDSA87

	// XWing is the hybrid KEM (ML-KEM-768 + X25519) this module uses by
	// default. Its private key is a raw 32-byte seed, with no seed/expandedKey
	// CHOICE — see the draft's Section 5.8.2.
	XWing
)

// algorithmInfo is the per-algorithm table. Sizes are from FIPS 203 / FIPS 204
// and were cross-checked against the example keys in RFC 9935 and RFC 9881.
type algorithmInfo struct {
	name string
	oid  asn1.ObjectIdentifier

	seedSize     int // bytes in the seed — the only private form written
	publicSize   int // bytes in the raw public key
	expandedSize int // bytes in the expanded private key; 0 when the algorithm has no expanded form

	// mlkemK is ML-KEM's module rank (2, 3, 4), used to locate the fields
	// inside an expanded decapsulation key. Zero for non-ML-KEM algorithms.
	mlkemK int
}

// algorithms is indexed by Algorithm.
var algorithms = map[Algorithm]algorithmInfo{
	MLKEM512:  {"ML-KEM-512", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}, 64, 800, 1632, 2},
	MLKEM768:  {"ML-KEM-768", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}, 64, 1184, 2400, 3},
	MLKEM1024: {"ML-KEM-1024", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}, 64, 1568, 3168, 4},

	MLDSA44: {"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, 32, 1312, 2560, 0},
	MLDSA65: {"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 32, 1952, 4032, 0},
	MLDSA87: {"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 32, 2592, 4896, 0},

	XWing: {"X-Wing", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}, 32, 1216, 0, 0},
}

// String returns the algorithm's standard name, such as "ML-KEM-768".
//
// # Outputs
//
//   - string: the standard name, or "unknown" for the zero value
func (a Algorithm) String() string {
	if info, ok := algorithms[a]; ok {
		return info.name
	}
	return "unknown"
}

// SeedSize returns the private key seed length in bytes: 64 for ML-KEM, 32 for
// ML-DSA and X-Wing.
//
// # Outputs
//
//   - int: the seed size, or 0 for an unknown algorithm
func (a Algorithm) SeedSize() int { return algorithms[a].seedSize }

// PublicKeySize returns the raw public key length in bytes.
//
// # Outputs
//
//   - int: the public key size, or 0 for an unknown algorithm
func (a Algorithm) PublicKeySize() int { return algorithms[a].publicSize }

// OID returns the algorithm's object identifier, as written into key files.
//
// # Outputs
//
//   - asn1.ObjectIdentifier: the identifier, or nil for an unknown algorithm.
//     The returned value is a copy; mutating it does not affect this package.
func (a Algorithm) OID() asn1.ObjectIdentifier {
	info, ok := algorithms[a]
	if !ok {
		return nil
	}
	out := make(asn1.ObjectIdentifier, len(info.oid))
	copy(out, info.oid)
	return out
}

// algorithmByOID maps an object identifier to an Algorithm.
//
// # Outputs
//
//   - Algorithm: the matching algorithm
//   - bool: false if the identifier is not recognised
func algorithmByOID(oid asn1.ObjectIdentifier) (Algorithm, bool) {
	for alg, info := range algorithms {
		if info.oid.Equal(oid) {
			return alg, true
		}
	}
	return Unknown, false
}
