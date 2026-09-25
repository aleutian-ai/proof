// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// pemTypePublic is the PEM label for a SubjectPublicKeyInfo (RFC 7468).
const pemTypePublic = "PUBLIC KEY"

// subjectPublicKeyInfo is the X.509 structure public keys use. For all
// algorithms here the BIT STRING holds the raw public key with no inner ASN.1.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// MarshalPublicKey encodes a raw public key as SubjectPublicKeyInfo in PEM form.
//
// # Description
//
// The public key bytes are placed directly in the BIT STRING, as RFC 9935,
// RFC 9881, and the X-Wing draft all require, with the algorithm's object
// identifier and absent parameters.
//
// # Inputs
//
//   - alg: the algorithm the key belongs to
//   - pub: exactly alg.PublicKeySize() bytes
//
// # Outputs
//
//   - []byte: PEM text with the label "PUBLIC KEY"
//   - error: ErrUnsupportedAlgorithm or ErrMalformed for a wrong-sized key
//
// # Example
//
//	pem, err := keyfile.MarshalPublicKey(keyfile.XWing, pub)
//
// # Limitations
//
//   - Does not check that the bytes are a valid key for the algorithm, only
//     that the length is right. Validation belongs to the algorithm package.
//
// # Assumptions
//
//   - pub is the algorithm's canonical public key encoding.
func MarshalPublicKey(alg Algorithm, pub []byte) ([]byte, error) {
	info, ok := algorithms[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, int(alg))
	}
	if len(pub) != info.publicSize {
		return nil, fmt.Errorf("%w: %s public key must be %d bytes, got %d",
			ErrMalformed, info.name, info.publicSize, len(pub))
	}
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: info.oid},
		PublicKey: asn1.BitString{Bytes: pub, BitLength: len(pub) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("keyfile: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: der}), nil
}

// ParsePublicKey reads a public key file and returns its algorithm and bytes.
//
// # Description
//
// Accepts SubjectPublicKeyInfo under the "PUBLIC KEY" label, and the legacy
// "ALEUTIAN HYBRID KEM PUBLIC KEY" format (always X-Wing).
//
// # Inputs
//
//   - data: the PEM file contents, at most 64 KiB
//
// # Outputs
//
//   - Algorithm: the algorithm named by the file
//   - []byte: a fresh copy of the raw public key
//   - error: ErrMalformed or ErrUnsupportedAlgorithm
//
// # Example
//
//	alg, pub, err := keyfile.ParsePublicKey(data)
//
// # Limitations
//
//   - Length is checked; mathematical validity is not.
//
// # Assumptions
//
//   - A public key is not secret, so no zeroization is performed.
func ParsePublicKey(data []byte) (Algorithm, []byte, error) {
	if len(data) > maxFileSize {
		return Unknown, nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit",
			ErrMalformed, len(data), maxFileSize)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return Unknown, nil, fmt.Errorf("%w: no PEM block", ErrMalformed)
	}
	if len(trimSpace(rest)) != 0 {
		return Unknown, nil, fmt.Errorf("%w: %d bytes after the PEM block", ErrMalformed, len(rest))
	}
	if block.Type == legacyPEMTypePublic {
		return parseLegacyPublic(block.Bytes)
	}
	if legacyRawPublicTypes[block.Type] {
		return parseLegacyRawPublic(block.Bytes)
	}
	if block.Type != pemTypePublic {
		return Unknown, nil, fmt.Errorf("%w: PEM label %q, want %q", ErrMalformed, block.Type, pemTypePublic)
	}

	var spki subjectPublicKeyInfo
	trailing, err := asn1.Unmarshal(block.Bytes, &spki)
	if err != nil {
		return Unknown, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(trailing) != 0 {
		return Unknown, nil, fmt.Errorf("%w: %d bytes after the DER structure", ErrMalformed, len(trailing))
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return Unknown, nil, fmt.Errorf("%w: algorithm parameters must be absent", ErrMalformed)
	}
	alg, ok := algorithmByOID(spki.Algorithm.Algorithm)
	if !ok {
		return Unknown, nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, spki.Algorithm.Algorithm)
	}
	info := algorithms[alg]
	if spki.PublicKey.BitLength%8 != 0 {
		return Unknown, nil, fmt.Errorf("%w: public key is not a whole number of bytes", ErrMalformed)
	}
	if len(spki.PublicKey.Bytes) != info.publicSize {
		return Unknown, nil, fmt.Errorf("%w: %s public key must be %d bytes, got %d",
			ErrMalformed, info.name, info.publicSize, len(spki.PublicKey.Bytes))
	}
	return alg, clone(spki.PublicKey.Bytes), nil
}
