// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package canonical produces deterministic byte encodings.
//
// # Description
//
// A hash is only meaningful if every implementation agrees on the exact bytes
// being hashed. This package fixes those bytes: key ordering, number formatting,
// string escaping, and the treatment of absent versus empty fields.
//
// Canonical form is a COMPATIBILITY CONTRACT, not an implementation detail.
// Changing it changes every hash downstream and invalidates existing chains,
// so changes are versioned rather than made in place, and golden fixtures pin
// the encoding across languages.
//
// # Assumptions
//
//   - Input has already been validated; canonicalization is not a validator.
package canonical
