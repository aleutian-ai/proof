// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package mem holds memory-hygiene helpers shared across the module.
package mem

// Zeroize overwrites b with zeros to narrow the window during which key material
// is readable in process memory after use.
//
// # Description
//
// Go's garbage collector does not scrub freed allocations, so key bytes can stay
// readable until the collector reclaims and rewrites those pages. Calling Zeroize
// as soon as a secret is no longer needed shortens that window.
//
//	dek := make([]byte, 32)
//	defer mem.Zeroize(dek)
//
// # Limitations
//
//   - Go cannot mlock(2) without cgo, so pages may reach swap before this runs.
//   - Defense in depth, not a cryptographic guarantee. A moving collector may
//     have already copied the bytes elsewhere.
//
// # Assumptions
//
//   - The caller holds exclusive access to b; this is not safe for concurrent use.
//
//go:noinline
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
