// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"bytes"
	"fmt"

	"github.com/aleutian-ai/proof/internal/mem"
)

// The legacy Aleutian key file format, read for compatibility and never
// written. Layout: a 4-byte magic, a 1-byte version, then the raw key.
//
//	ALT1 0x81 <32-byte seed>              37 bytes  — X-Wing private
//	ALT1 0x01 <1216-byte public key>    1221 bytes  — X-Wing public
//
// Files in this format predate the standard encodings in RFC 9881 / RFC 9935
// and always hold X-Wing keys. They are accepted so existing key files,
// Keychain entries, and 1Password items keep working with no migration step.
const (
	// The xwing-keyfile library's format: a 4-byte magic and a version byte
	// before the key.
	legacyPEMTypePrivate = "ALEUTIAN HYBRID KEM PRIVATE KEY"
	legacyPEMTypePublic  = "ALEUTIAN HYBRID KEM PUBLIC KEY"

	legacyPrivateVersion = 0x81
	legacyPublicVersion  = 0x01
)

// The platform's aleutian-keygen format: a PLAIN PEM block whose body is the
// raw key, with no magic and no version byte, under one of three labels per
// key half. The slot variants exist because the onboarding ceremony issues two
// keys — a hot "primary" and a cold "backup" — and tags each file so an
// operator can tell them apart on disk.
//
// These are the files real customers hold. They are read here so that keys
// minted by the onboarding ceremony work with this module without a migration
// step; nothing in this package writes them.
var legacyRawPrivateTypes = map[string]bool{
	"ALEUTIAN XWING PRIVATE KEY":         true,
	"ALEUTIAN XWING PRIMARY PRIVATE KEY": true,
	"ALEUTIAN XWING BACKUP PRIVATE KEY":  true,
}

var legacyRawPublicTypes = map[string]bool{
	"ALEUTIAN XWING PUBLIC KEY":         true,
	"ALEUTIAN XWING PRIMARY PUBLIC KEY": true,
	"ALEUTIAN XWING BACKUP PUBLIC KEY":  true,
}

// parseLegacyRawPrivate reads an aleutian-keygen private key: the PEM body is
// the 32-byte X-Wing seed, nothing else.
//
// # Inputs
//
//   - payload: the PEM block contents, expected to be 32 bytes
//
// # Outputs
//
//   - Algorithm: always XWing on success
//   - []byte: a fresh copy of the seed
//   - error: ErrMalformed if the size is wrong
func parseLegacyRawPrivate(payload []byte) (Algorithm, []byte, error) {
	if len(payload) != XWing.SeedSize() {
		return Unknown, nil, fmt.Errorf("%w: legacy private key must be %d bytes, got %d",
			ErrMalformed, XWing.SeedSize(), len(payload))
	}
	seed := clone(payload)
	mem.Zeroize(payload)
	return XWing, seed, nil
}

// parseLegacyRawPublic reads an aleutian-keygen public key: the PEM body is the
// canonical 1216-byte X-Wing public key.
//
// # Inputs
//
//   - payload: the PEM block contents, expected to be 1216 bytes
//
// # Outputs
//
//   - Algorithm: always XWing on success
//   - []byte: a fresh copy of the public key
//   - error: ErrMalformed if the size is wrong
func parseLegacyRawPublic(payload []byte) (Algorithm, []byte, error) {
	if len(payload) != XWing.PublicKeySize() {
		return Unknown, nil, fmt.Errorf("%w: legacy public key must be %d bytes, got %d",
			ErrMalformed, XWing.PublicKeySize(), len(payload))
	}
	return XWing, clone(payload), nil
}

// legacyMagic is the 4-byte file magic, ASCII "ALT1".
var legacyMagic = []byte{0x41, 0x4C, 0x54, 0x31}

// parseLegacyPrivate reads a legacy X-Wing private key payload.
//
// # Inputs
//
//   - payload: the PEM block contents, expected to be 37 bytes
//
// # Outputs
//
//   - Algorithm: always XWing on success
//   - []byte: a fresh copy of the 32-byte seed
//   - error: ErrMalformed if the magic, version, or size is wrong
func parseLegacyPrivate(payload []byte) (Algorithm, []byte, error) {
	want := len(legacyMagic) + 1 + XWing.SeedSize()
	if len(payload) != want {
		return Unknown, nil, fmt.Errorf("%w: legacy private key must be %d bytes, got %d",
			ErrMalformed, want, len(payload))
	}
	if !bytes.Equal(payload[:4], legacyMagic) {
		return Unknown, nil, fmt.Errorf("%w: legacy file magic", ErrMalformed)
	}
	if payload[4] != legacyPrivateVersion {
		return Unknown, nil, fmt.Errorf("%w: legacy private key version 0x%02x", ErrMalformed, payload[4])
	}
	seed := clone(payload[5:])
	mem.Zeroize(payload)
	return XWing, seed, nil
}

// parseLegacyPublic reads a legacy X-Wing public key payload.
//
// # Inputs
//
//   - payload: the PEM block contents, expected to be 1221 bytes
//
// # Outputs
//
//   - Algorithm: always XWing on success
//   - []byte: a fresh copy of the 1216-byte public key
//   - error: ErrMalformed if the magic, version, or size is wrong
func parseLegacyPublic(payload []byte) (Algorithm, []byte, error) {
	want := len(legacyMagic) + 1 + XWing.PublicKeySize()
	if len(payload) != want {
		return Unknown, nil, fmt.Errorf("%w: legacy public key must be %d bytes, got %d",
			ErrMalformed, want, len(payload))
	}
	if !bytes.Equal(payload[:4], legacyMagic) {
		return Unknown, nil, fmt.Errorf("%w: legacy file magic", ErrMalformed)
	}
	if payload[4] != legacyPublicVersion {
		return Unknown, nil, fmt.Errorf("%w: legacy public key version 0x%02x", ErrMalformed, payload[4])
	}
	return XWing, clone(payload[5:]), nil
}
