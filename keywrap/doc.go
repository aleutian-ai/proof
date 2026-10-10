// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package keywrap implements the versioned wrapped-key wire format.
//
// # Description
//
// A wrapped key is the [xwing] ciphertext plus the framing needed to identify,
// version and checksum it on the wire: a version byte, the recipient key id,
// the KEM ciphertext, and a keyed checksum over the whole structure.
//
// The checksum is HMAC-SHA-512 under a PUBLIC, constant key, in the field the
// format calls "mac". It detects accidental corruption. It authenticates
// nothing: anyone can compute it over any bytes. What stops a modified record
// is ML-KEM's implicit rejection and the AEAD that the unwrapped key opens.
//
// The format is versioned because it is written to durable storage and must be
// parseable by code shipped years later. Parsers reject unknown versions rather
// than guessing.
//
// # Limitations
//
//   - Wraps a key. It does not manage, rotate, escrow or store one.
//   - Version 0x01 (a legacy RSA wrapping) is refused with its OWN error,
//     [ErrLegacyRSAVersion], not the generic unsupported-version error. The
//     distinction is deliberate: "this is an old record needing migration" and
//     "this is not a record I recognise" call for different responses, and
//     collapsing them sends an operator looking for corruption that is not there.
//     It is returned only for a record of V3's size whose checksum holds, since
//     size and checksum are checked first; a real v1 record is a different size
//     and gets the size error.
//
// # Assumptions
//
//   - The checksum covers every byte that a parser will act on, so a truncated
//     or accidentally damaged record fails before any field is read.
package keywrap
