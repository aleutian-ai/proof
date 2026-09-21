// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package xwing implements the X-Wing hybrid post-quantum KEM.
//
// # Description
//
// X-Wing combines ML-KEM-768 with X25519 so that the shared secret stays secure
// as long as EITHER primitive holds. That hedges the two live risks at once: a
// cryptanalytic break of the young lattice scheme, and a future quantum
// adversary against the classical one.
//
// ML-KEM comes from the standard library (crypto/mlkem, Go 1.24+) and X25519
// from golang.org/x/crypto. This package deliberately does NOT depend on
// github.com/cloudflare/circl — that dependency belongs to [anchor], which needs
// ML-DSA for signatures. Keeping the split lets a caller vendor the KEM alone.
//
// # Limitations
//
//   - Key serialization is not here. On-disk key formats are a separate concern;
//     see the module README for why that boundary exists.
//
// # Assumptions
//
//   - Secret material is zeroized by the caller when no longer needed; the
//     Zeroize methods are best-effort and cannot defeat a moving GC.
package xwing
