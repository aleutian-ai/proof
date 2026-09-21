// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package anchor implements signed chain anchors and their verification.
//
// # Description
//
// An anchor is a signed statement that a chain had a particular head at a
// particular point in its history. It converts an internally consistent chain
// into evidence a third party can check, because the signature is verifiable
// against a key the verifier already trusts rather than against the chain
// itself.
//
// Signatures are ML-DSA-65, which is why this package — and only this package —
// depends on github.com/cloudflare/circl.
//
// # Limitations
//
//   - An anchor is exactly as trustworthy as the key that signed it. A locally
//     generated key proves the holder's own assertion and nothing more; that is
//     a real but strictly weaker claim than a third-party anchor, and callers
//     must surface the difference rather than reporting a uniform "verified".
//
// # Assumptions
//
//   - The canonical form of an anchor is versioned; verifiers dispatch on the
//     declared version, never on which fields happen to be present.
package anchor
