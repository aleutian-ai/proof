// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ML-DSA-65 parameter sizes, fixed by FIPS 204.
const (
	// SignatureSize is the exact byte length of an ML-DSA-65 signature.
	SignatureSize = 3309

	// PublicKeySize is the exact byte length of an ML-DSA-65 public key.
	PublicKeySize = 1952
)

// Errors returned by VerifySignature. Callers should branch on these rather
// than on message text.
var (
	// ErrUnknownKeyID means no key source could supply the anchor's signing key.
	// It is deliberately distinct from a bad signature: "I do not know this
	// signer" and "this signer's signature is wrong" call for different actions.
	ErrUnknownKeyID = errors.New("anchor: unknown signing key id")

	// ErrInvalidSignature means the signature did not verify, was malformed, or
	// was the wrong length.
	ErrInvalidSignature = errors.New("anchor: invalid signature")

	// ErrVerificationUnsupported means the anchor's version can be canonicalized
	// but must not be verified. See Trust and the v5 note on VerifySignature.
	ErrVerificationUnsupported = errors.New("anchor: verification not supported for this version")
)

// Trust records WHAT a verified signature establishes, not merely that it verified.
//
// # Description
//
// A signature check answers "was this signed by the holder of key K". It does not
// answer "should I believe K". Those are different questions and collapsing them
// into a single boolean is how a verification tool ends up helping someone make a
// claim they cannot back.
//
// The distinction is not cosmetic — it is the difference between evidence and an
// assertion.
type Trust string

const (
	// TrustPlatform: the key came from a trust store the verifier already had.
	// The strongest claim available — a third party attests to this chain.
	TrustPlatform Trust = "platform"

	// TrustProvided: the caller supplied the key out of band. The claim is only
	// as good as the caller's reason for trusting it, which this library cannot
	// evaluate.
	TrustProvided Trust = "provided"

	// TrustSelf: the key travelled with the anchor, or was generated locally.
	// This proves internal consistency and NOTHING about a third party. An
	// adversary who can write the chain can also mint this.
	TrustSelf Trust = "self"
)

// Establishes returns a one-line statement of what this trust level proves.
//
// # Description
//
// Provided so callers rendering a result to a human do not have to invent the
// wording, and so the weaker levels cannot be described as if they were the
// strongest.
//
// # Outputs
//
//   - string: plain-language claim, safe to show a user
//
// # Example
//
//	fmt.Printf("signature valid (%s)\n", trust.Establishes())
func (t Trust) Establishes() string {
	switch t {
	case TrustPlatform:
		return "a third party attests to this chain"
	case TrustProvided:
		return "the holder of a key you supplied attests to this chain"
	case TrustSelf:
		return "the chain's own holder attests to it; no third party is involved"
	default:
		return "unknown trust level; treat as unverified"
	}
}

// KeySource supplies public keys and says how much they should be trusted.
//
// # Description
//
// Implementations decide policy; this package only does cryptography. A source
// that fetches from the network, reads a manifest, or consults an embedded root
// set all satisfy this — the library stays agnostic about whose keys matter.
//
// # Assumptions
//
//   - Implementations are safe for concurrent use
//   - A returned key is a copy the caller may retain
type KeySource interface {
	// PublicKey returns the ML-DSA-65 public key for keyID and what trusting it
	// establishes. It returns ErrUnknownKeyID when the key is not held.
	PublicKey(keyID string) ([]byte, Trust, error)
}

// KeyRing is an explicit, in-memory KeySource.
//
// # Description
//
// The trust level is a property of the RING, not of individual keys: a caller
// states once where this set came from. Mixing platform and self-signed keys in
// one ring would make the resulting trust level meaningless, so build two rings.
//
// # Thread Safety
//
// Safe for concurrent use after construction. Do not mutate the map afterwards.
type KeyRing struct {
	trust Trust
	keys  map[string][]byte
}

// NewKeyRing builds a KeySource from an explicit key set.
//
// # Description
//
// Copies both the map and every key, so a caller mutating its input afterwards
// cannot silently change what this ring verifies against.
//
// # Inputs
//
//   - trust: what keys in THIS ring establish. Be honest here; it is the whole
//     point of the type.
//   - keys: key id → raw ML-DSA-65 public key bytes
//
// # Outputs
//
//   - *KeyRing: ready to use
//   - error: if trust is unrecognised, or any key is the wrong length
//
// # Example
//
//	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{
//	    "aleutian-ml-dsa-65-2026-v1": pubKeyBytes,
//	})
//
// # Limitations
//
//   - Holds keys in memory; no rotation, expiry or revocation. A source needing
//     those should implement KeySource directly.
func NewKeyRing(trust Trust, keys map[string][]byte) (*KeyRing, error) {
	switch trust {
	case TrustPlatform, TrustProvided, TrustSelf:
	default:
		return nil, fmt.Errorf("anchor: unrecognised trust level %q", trust)
	}

	out := make(map[string][]byte, len(keys))
	for id, k := range keys {
		if len(k) != PublicKeySize {
			// Length only — never echo key bytes into an error.
			return nil, fmt.Errorf("anchor: key %q is %d bytes, want %d (ML-DSA-65)",
				id, len(k), PublicKeySize)
		}
		cp := make([]byte, len(k))
		copy(cp, k)
		out[id] = cp
	}
	return &KeyRing{trust: trust, keys: out}, nil
}

// PublicKey implements KeySource.
func (r *KeyRing) PublicKey(keyID string) ([]byte, Trust, error) {
	k, ok := r.keys[keyID]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}
	// Defensive copy: a caller must not be able to mutate the ring.
	cp := make([]byte, len(k))
	copy(cp, k)
	return cp, r.trust, nil
}

// VerifySignature checks an anchor's ML-DSA-65 signature and reports what it proves.
//
// # Description
//
// The order of operations is security-relevant and deliberate:
//
//  1. Version invariants, BEFORE canonicalization. Version is inside the signed
//     bytes, so checking it first stops a malformed anchor from selecting a
//     different canonical form than the one that was signed.
//  2. Version support. v5 is canonicalizable but NOT verifiable — see below.
//  3. Key lookup. An unknown key is its own error, never a quiet failure.
//  4. Signature decode and LENGTH check, before any cryptography runs.
//  5. Signature verification.
//
// # Why v5 is refused
//
// This package can canonicalize v5 (root_hash, tree_size), but v5 has no
// cross-language test vector anywhere: no SDK implements it and no producer emits
// it. Verifying would assert byte-agreement with implementations that do not
// exist. Canonicalizing is harmless; verifying is a claim. Verifiers must ship
// before any producer emits v5, or every deployed verifier rejects it.
//
// # Inputs
//
//   - a: the anchor to check. Its Signature field is the thing being checked.
//   - src: where to obtain the signing key, and how much to trust it
//
// # Outputs
//
//   - Trust: what a successful verification establishes — NOT merely that it passed
//   - error: ErrUnknownKeyID, ErrInvalidSignature, ErrVerificationUnsupported, or
//     a version-invariant failure
//
// # Example
//
//	trust, err := anchor.VerifySignature(a, ring)
//	if err != nil {
//	    return err
//	}
//	fmt.Println("verified —", trust.Establishes())
//
// # Limitations
//
//   - Checks the signature only. It says nothing about whether the anchor
//     describes the chain in front of you; that is verify.BindAnchor.
//   - Uses pure ML-DSA (FIPS 204 §5.3) with an empty context string, matching the
//     producer's Cloud KMS PQ_SIGN_ML_DSA_65. Passing a context would break every
//     existing signature.
//
// # Assumptions
//
//   - src is safe for concurrent use
func VerifySignature(a Anchor, src KeySource) (Trust, error) {
	if src == nil {
		return "", errors.New("anchor: key source is required")
	}

	// 1. Version invariants BEFORE canonicalization (downgrade guard).
	if err := ValidateVersionInvariants(a); err != nil {
		return "", err
	}

	// 2. v5 canonicalizes but must not be verified.
	//
	// An EXACT test, not ">= MerkleVersion". The open-ended form was written to
	// exclude v5 and silently excluded every version after it too — v6 would
	// have verified nowhere. Merkle is one version, not a floor.
	if a.Version == MerkleVersion {
		return "", fmt.Errorf("%w: v%d has no cross-language test vectors; "+
			"canonicalization is implemented but verification would assert agreement "+
			"with implementations that do not exist",
			ErrVerificationUnsupported, a.Version)
	}

	// 3. Key lookup. Distinct from a bad signature, deliberately.
	pubKey, trust, err := src.PublicKey(a.SigningKeyID)
	if err != nil {
		return "", err
	}
	if len(pubKey) != PublicKeySize {
		return "", fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrInvalidSignature, len(pubKey), PublicKeySize)
	}

	// 4. Decode and length-check the signature BEFORE handing it to the library.
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return "", fmt.Errorf("%w: signature is not valid base64", ErrInvalidSignature)
	}
	if len(sig) != SignatureSize {
		return "", fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrInvalidSignature, len(sig), SignatureSize)
	}

	canonical, err := Canonicalize(a)
	if err != nil {
		return "", fmt.Errorf("anchor: canonicalize: %w", err)
	}

	// 5. Verify, through the same primitive SignCanonical self-checks with, so
	// "the signer just produced this" and "this package accepts this" cannot
	// drift apart.
	if err := verifyMLDSA65(pubKey, canonical, sig); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return trust, nil
}
