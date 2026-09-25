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
// Signatures are ML-DSA-65, reached through github.com/aleutian-ai/proof/mldsa
// rather than by importing circl here. Signing and verification share one
// primitive, so "the signer just produced this" and "this package accepts this"
// cannot drift apart.
//
// # Signing, and crypto.Signer
//
// [MLDSA65Signer] signs anchors with an in-memory key. It IS a crypto.Signer,
// so it drops into anything expecting one with no adapter; a compile-time
// assertion enforces that. In the other direction, [FromCryptoSigner] accepts
// any crypto.Signer — Cloud KMS, an HSM, a PKCS#11 token, a keychain — which is
// how a caller signs without this module ever touching a credential.
//
// Produce anchors through [SignAnchor], not by assembling the pieces yourself.
// `signing_key_id` is INSIDE the signed bytes, so populating it after
// canonicalizing signs one set of bytes and publishes another — an anchor that
// fails verification forever with nothing pointing at the cause. SignAnchor
// stamps the key id, validates, canonicalizes, signs and verifies in one call,
// so the order cannot be got wrong.
//
// It also verifies every signature before returning it. That is what makes it
// safe to accept a signer this package did not write: crypto.Signer's byte
// slice means "digest" for RSA and ECDSA but "the whole message" for ML-DSA,
// and a signer that hashes first returns a structurally perfect signature over
// the wrong bytes. Nothing else would catch it until an audit.
//
// # A note on what a verified signature proves
//
// Self-verification establishes CONSISTENCY — the signature matches the key the
// signer advertises. It does not establish AUTHENTICITY: a substituted signer
// that swaps in its own keypair passes every check. For that, verify against a
// key you obtained independently (TrustPlatform or TrustProvided), never a
// TrustSelf ring built from the anchor's own accompanying key.
//
// # Subjects must not carry personal data
//
// An anchor's Subject is inside the signed bytes and is therefore NOT ERASABLE:
// removing or changing it invalidates the signature and every anchor chained
// after it. Anchors are meant to be published to third parties. Use a stable
// pseudonym or an opaque id — never a name, an email address, or anything else
// that identifies a person, because there is no way to take it back afterwards.
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
