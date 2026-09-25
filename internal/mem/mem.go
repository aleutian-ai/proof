// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package mem holds memory-hygiene helpers shared across the module.
//
// # Description
//
// One function, [Zeroize], and a clear statement of what it is worth. Go gives
// no way to pin a buffer or to stop the garbage collector copying it, so
// scrubbing a secret as soon as it is finished with narrows the window in which
// it is readable — it does not close it.
//
// This package exists so that the limitation is written down in exactly one
// place, and so every caller that scrubs key material is visibly doing the same
// thing rather than each hand-rolling a loop with its own assumptions.
//
// # Limitations
//
//   - Defence in depth, never a guarantee. A moving collector may already have
//     copied the bytes elsewhere, and those copies are unreachable.
//   - Go cannot mlock(2) without cgo, so pages may reach swap first.
//   - Scrubs only the buffer it is given. A secret that was expanded into
//     another structure — a derived private key, say — is not reached.
//
// # Assumptions
//
//   - The caller holds exclusive access to the buffer. Nothing here is safe for
//     concurrent use.
//   - Internal to this module by design: it makes a promise too weak to export
//     as an API.
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
