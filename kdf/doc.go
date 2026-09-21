// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package kdf provides domain-separated key derivation.
//
// # Description
//
// Every derived key is bound to a domain string, so a key derived for one
// purpose cannot be substituted for another even when the input secret is
// identical. Domain separation is the cheapest defense against cross-protocol
// misuse and it must be applied at every derivation site, not most of them.
//
// # Assumptions
//
//   - Domain strings are compile-time constants, never caller-supplied at
//     runtime — a caller-controlled domain defeats the separation.
package kdf
