// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package keywrap implements the versioned wrapped-key wire format.
//
// # Description
//
// A wrapped key is the [xwing] ciphertext plus the framing needed to identify,
// authenticate, and version it on the wire: a version byte, the recipient key
// id, the KEM ciphertext, and a MAC over the whole structure.
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
//
// # Assumptions
//
//   - The MAC covers every byte that a parser will act on, so a truncated or
//     spliced record fails before any field is trusted.
package keywrap
