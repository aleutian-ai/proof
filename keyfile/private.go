// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/aleutian-ai/proof/internal/mem"
)

// pemTypePrivate is the PEM label for a PKCS#8 private key (RFC 7468).
const pemTypePrivate = "PRIVATE KEY"

// maxFileSize caps input before any parsing, so a malformed or hostile file
// cannot drive an unbounded allocation. The largest key file here is an
// ML-DSA-87 "both" private key at roughly 5 KB.
const maxFileSize = 1 << 16

// oneAsymmetricKey is the RFC 5958 structure PKCS#8 private keys use.
//
// Attributes and PublicKey are declared so their presence is DETECTED rather
// than silently ignored: an embedded public key this package cannot verify
// against the seed is rejected (see ParsePrivateKey).
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey  asn1.RawValue `asn1:"optional,tag:1"`
}

// outAsymmetricKey is what this package WRITES: the three mandatory fields and
// nothing else.
type outAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// bothForm is the SEQUENCE of the "both" CHOICE in RFC 9881 / RFC 9935.
type bothForm struct {
	Seed     []byte
	Expanded []byte
}

// MarshalPrivateKey encodes a seed as a PKCS#8 private key in PEM form.
//
// # Description
//
// Writes the seed form, which both RFCs recommend as the most compact
// representation; the expanded key and the public key are derivable from it.
// The output carries the algorithm's object identifier, so a reader never has
// to infer the algorithm.
//
// # Inputs
//
//   - alg: the algorithm the seed belongs to
//   - seed: exactly alg.SeedSize() bytes
//
// # Outputs
//
//   - []byte: PEM text with the label "PRIVATE KEY"
//   - error: ErrUnsupportedAlgorithm for an unknown algorithm, ErrMalformed for
//     a wrong-sized seed
//
// # Example
//
//	pem, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
//	if err != nil {
//	    return err
//	}
//	os.WriteFile("signing.pem", pem, 0o600)
//
// # Limitations
//
//   - The result is NOT encrypted. Protecting it at rest is the caller's job.
//
// # Assumptions
//
//   - seed came from a secure generator or an existing key file.
func MarshalPrivateKey(alg Algorithm, seed []byte) ([]byte, error) {
	info, ok := algorithms[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, int(alg))
	}
	if len(seed) != info.seedSize {
		return nil, fmt.Errorf("%w: %s seed must be %d bytes, got %d",
			ErrMalformed, info.name, info.seedSize, len(seed))
	}

	// X-Wing carries the raw seed; ML-KEM and ML-DSA wrap it in the CHOICE as
	// [0] IMPLICIT OCTET STRING.
	inner := seed
	if alg != XWing {
		var err error
		inner, err = asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
		if err != nil {
			return nil, fmt.Errorf("keyfile: encode seed: %w", err)
		}
		defer mem.Zeroize(inner)
	}

	der, err := asn1.Marshal(outAsymmetricKey{
		Version:    0,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: info.oid},
		PrivateKey: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("keyfile: encode private key: %w", err)
	}
	defer mem.Zeroize(der)

	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivate, Bytes: der}), nil
}

// ParsePrivateKey reads a private key file and returns its algorithm and seed.
//
// # Description
//
// Accepts a PKCS#8 file in the seed or "both" form, and a legacy
// "ALEUTIAN HYBRID KEM PRIVATE KEY" file (always X-Wing). The algorithm comes
// from the file's object identifier.
//
// For a "both"-form key the seed is returned and the expanded key checked
// where possible — see [CheckConsistency]. An expandedKey-only file is
// rejected: expansion is one-way, so it contains no seed to return.
//
// # Inputs
//
//   - data: the PEM file contents, at most 64 KiB
//
// # Outputs
//
//   - Algorithm: the algorithm named by the file
//   - []byte: a fresh copy of the seed, owned by the caller
//   - error: ErrMalformed, ErrUnsupportedAlgorithm, ErrExpandedKeyOnly, or
//     ErrInconsistentKey
//
// # Example
//
//	alg, seed, err := keyfile.ParsePrivateKey(data)
//	if err != nil {
//	    return err
//	}
//	defer mem.Zeroize(seed)
//
// # Limitations
//
//   - Does not decrypt encrypted private key files (EncryptedPrivateKeyInfo).
//   - Rejects a file carrying an embedded public key, which it cannot verify.
//
// # Assumptions
//
//   - The caller zeroizes the returned seed when finished.
func ParsePrivateKey(data []byte) (Algorithm, []byte, error) {
	if len(data) > maxFileSize {
		return Unknown, nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit",
			ErrMalformed, len(data), maxFileSize)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return Unknown, nil, fmt.Errorf("%w: no PEM block", ErrMalformed)
	}
	defer mem.Zeroize(block.Bytes)
	if len(trimSpace(rest)) != 0 {
		return Unknown, nil, fmt.Errorf("%w: %d bytes after the PEM block", ErrMalformed, len(rest))
	}
	if block.Type == legacyPEMTypePrivate {
		return parseLegacyPrivate(block.Bytes)
	}
	if legacyRawPrivateTypes[block.Type] {
		return parseLegacyRawPrivate(block.Bytes)
	}
	if block.Type != pemTypePrivate {
		return Unknown, nil, fmt.Errorf("%w: PEM label %q, want %q", ErrMalformed, block.Type, pemTypePrivate)
	}

	var k oneAsymmetricKey
	trailing, err := asn1.Unmarshal(block.Bytes, &k)
	if err != nil {
		return Unknown, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(trailing) != 0 {
		return Unknown, nil, fmt.Errorf("%w: %d bytes after the DER structure", ErrMalformed, len(trailing))
	}
	defer mem.Zeroize(k.PrivateKey)

	if k.Version != 0 && k.Version != 1 {
		return Unknown, nil, fmt.Errorf("%w: version %d", ErrMalformed, k.Version)
	}
	if len(k.PublicKey.FullBytes) != 0 {
		// An embedded public key cannot be checked against the seed here, and a
		// mismatched one would mislead a caller about which key this is.
		return Unknown, nil, fmt.Errorf("%w: embedded public key is not accepted", ErrMalformed)
	}
	if len(k.Algorithm.Parameters.FullBytes) != 0 {
		return Unknown, nil, fmt.Errorf("%w: algorithm parameters must be absent", ErrMalformed)
	}
	alg, ok := algorithmByOID(k.Algorithm.Algorithm)
	if !ok {
		return Unknown, nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, k.Algorithm.Algorithm)
	}
	info := algorithms[alg]

	// X-Wing: the privateKey OCTET STRING holds the raw seed, with no CHOICE.
	if alg == XWing {
		if len(k.PrivateKey) != info.seedSize {
			return Unknown, nil, fmt.Errorf("%w: X-Wing private key must be %d bytes, got %d",
				ErrMalformed, info.seedSize, len(k.PrivateKey))
		}
		return alg, clone(k.PrivateKey), nil
	}
	return parseChoice(alg, info, k.PrivateKey)
}

// parseChoice decodes the ML-KEM / ML-DSA private key CHOICE.
//
// # Description
//
// Dispatches on the DER tag, as RFC 9935 directs — [0] IMPLICIT for seed,
// OCTET STRING for expandedKey, SEQUENCE for both — never on the length.
//
// # Outputs
//
//   - Algorithm, []byte: the algorithm and a fresh copy of the seed
//   - error: ErrExpandedKeyOnly, ErrInconsistentKey, or ErrMalformed
func parseChoice(alg Algorithm, info algorithmInfo, inner []byte) (Algorithm, []byte, error) {
	if len(inner) == 0 {
		return Unknown, nil, fmt.Errorf("%w: empty private key", ErrMalformed)
	}
	switch inner[0] {
	case 0x80: // seed [0] IMPLICIT OCTET STRING
		var raw asn1.RawValue
		trailing, err := asn1.Unmarshal(inner, &raw)
		if err != nil || len(trailing) != 0 {
			return Unknown, nil, fmt.Errorf("%w: seed encoding", ErrMalformed)
		}
		if len(raw.Bytes) != info.seedSize {
			return Unknown, nil, fmt.Errorf("%w: %s seed must be %d bytes, got %d",
				ErrMalformed, info.name, info.seedSize, len(raw.Bytes))
		}
		return alg, clone(raw.Bytes), nil

	case 0x04: // expandedKey OCTET STRING
		return Unknown, nil, fmt.Errorf("%w: %s", ErrExpandedKeyOnly, info.name)

	case 0x30: // both SEQUENCE { seed, expandedKey }
		var both bothForm
		trailing, err := asn1.Unmarshal(inner, &both)
		if err != nil || len(trailing) != 0 {
			return Unknown, nil, fmt.Errorf("%w: both-form encoding", ErrMalformed)
		}
		defer mem.Zeroize(both.Expanded)
		if len(both.Seed) != info.seedSize {
			return Unknown, nil, fmt.Errorf("%w: %s seed must be %d bytes, got %d",
				ErrMalformed, info.name, info.seedSize, len(both.Seed))
		}
		if len(both.Expanded) != info.expandedSize {
			return Unknown, nil, fmt.Errorf("%w: %s expanded key must be %d bytes, got %d",
				ErrMalformed, info.name, info.expandedSize, len(both.Expanded))
		}
		if err := CheckConsistency(alg, both.Seed, both.Expanded); err != nil {
			return Unknown, nil, err
		}
		return alg, clone(both.Seed), nil

	default:
		return Unknown, nil, fmt.Errorf("%w: private key tag 0x%02x", ErrMalformed, inner[0])
	}
}

// clone returns a copy of b, so a returned seed never aliases a buffer this
// package is about to zeroize.
func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// trimSpace reports the input with leading and trailing ASCII whitespace
// removed. Used to allow a trailing newline after a PEM block while still
// rejecting real trailing data.
func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

// isSpace reports whether c is ASCII whitespace.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
