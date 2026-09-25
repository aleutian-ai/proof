// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// maxCanonicalSize bounds the bytes [SignCanonical] will sign.
//
// An anchor's canonical form is a handful of fixed fields plus a free-text
// subject; a megabyte is far beyond any legitimate one. The bound exists
// because signing traverses the input twice — once to sign, once for the
// mandatory self-verification — and each signature also expands a fresh private
// key. An unbounded caller-supplied slice in an OSS library deserves a ceiling.
const maxCanonicalSize = 1 << 20

// KeyIDOf derives a signer's key id and public key bytes.
//
// # Description
//
// The single derivation shared by [SignAnchor], [SignCanonical] and any caller
// that must know the key id BEFORE canonicalizing — which, for an anchor, is
// everyone, because signing_key_id is inside the signed bytes.
//
// It exists on the interface rather than as a method so that a Cloud KMS or
// PKCS#11 signer gets it for free, and so there is exactly one implementation of
// the derivation rather than one per caller.
//
// Public() is called ONCE. For a KMS-backed signer every call may be a network
// round trip, and two calls could observe two different keys across a rotation.
//
// # Inputs
//
//   - s: the signer; must not be nil, including a typed nil
//
// # Outputs
//
//   - string: the key id, 32 lowercase hex characters
//   - []byte: the raw ML-DSA-65 public key, PublicKeySize bytes
//   - error: if s is nil, its public key is unreadable, or it is the wrong size
//
// # Example
//
//	keyID, pub, err := anchor.KeyIDOf(signer)
//	if err != nil {
//	    return err
//	}
//	a.SigningKeyID = keyID // BEFORE Canonicalize
//
// # Limitations
//
//   - ML-DSA-65 only: a public key of any other length is refused.
//   - Identifies the key the signer ADVERTISES. It does not prove the signer
//     holds the matching private half; only a signature does that.
//
// # Assumptions
//
//   - s.Public() returns a value implementing encoding.BinaryMarshaler.
func KeyIDOf(s ContextSigner) (string, []byte, error) {
	if isNil(s) {
		return "", nil, errors.New("anchor: signer is required")
	}

	// Once. A second call may cost a network round trip, or observe a different
	// key across a rotation.
	pk := s.Public()
	marshaler, ok := pk.(encoding.BinaryMarshaler)
	if !ok {
		return "", nil, fmt.Errorf("anchor: signer's public key (%T) does not implement "+
			"encoding.BinaryMarshaler, so its bytes cannot be read", pk)
	}
	pub, err := marshaler.MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("anchor: marshal signer public key: %w", err)
	}
	if len(pub) != PublicKeySize {
		return "", nil, fmt.Errorf("anchor: signer's public key is %d bytes, want %d "+
			"(ML-DSA-65); this signer is for a different algorithm", len(pub), PublicKeySize)
	}

	keyID, err := keyfile.KeyIDHex(keyfile.MLDSA65, pub)
	if err != nil {
		return "", nil, fmt.Errorf("anchor: derive key id: %w", err)
	}
	return keyID, pub, nil
}

// SignAnchor signs an anchor and returns the completed, verified copy.
//
// # Description
//
// The entry point for producing anchors. It is the only one that cannot be used
// in the wrong order, which is the entire reason it exists:
//
//	signing_key_id is INSIDE the signed bytes.
//
// Populating it after canonicalizing — the obvious-looking sequence — signs one
// set of bytes and publishes another. The anchor then fails verification
// forever, with a generic "invalid signature" and nothing pointing at the
// cause. Handing a caller the pieces and trusting them to assemble them in the
// right order does not work; this function assembles them.
//
// In order:
//
//  1. Derive the key id and public key from the signer ([KeyIDOf]).
//  2. Stamp the key id, unless the caller set one — see Limitations.
//  3. Validate version invariants, and refuse v5, matching [VerifySignature]
//     exactly. Signing something this package will not verify is pure waste.
//  4. Canonicalize.
//  5. Sign, then VERIFY the result before returning it ([SignCanonical]).
//
// The input anchor is never mutated; the result is a copy.
//
// # Inputs
//
//   - ctx: forwarded to the signer
//   - s: the signer; [FromCryptoSigner] adapts a plain crypto.Signer
//   - a: the anchor to sign. Signature is ignored and replaced.
//
// # Outputs
//
//   - Anchor: a copy carrying SigningKeyID and Signature, already verified
//   - error: from any step; ErrVerificationUnsupported for v5,
//     ErrSignerProducedBadSignature if the signature does not check out
//
// # Example
//
//	signed, err := anchor.SignAnchor(ctx, signer, a)
//	if err != nil {
//	    return err
//	}
//	// signed.SigningKeyID and signed.Signature are set, and the signature
//	// has already been verified against the signer's own public key.
//
// # Limitations
//
//   - If a.SigningKeyID is already set it is KEPT, not overwritten. That is for
//     KMS and registry keys, whose ids are assigned labels such as
//     "aleutian-anchor-2026-01-v2" rather than content-derived hex. In that case
//     the id is the caller's assertion: the signature is still verified against
//     the key that produced it, but nothing checks that the label names that
//     key. Leave the field empty to get the derived id, which cannot be wrong.
//   - Verifies the signature, not the CLAIM. Whether the anchor honestly
//     describes a chain is verify.Chain's job, and `_35b`'s.
//   - ML-DSA-65 only.
//
// # Assumptions
//
//   - The caller has already decided what the anchor says.
func SignAnchor(ctx context.Context, s ContextSigner, a Anchor) (Anchor, error) {
	keyID, _, err := KeyIDOf(s)
	if err != nil {
		return Anchor{}, err
	}

	// Never mutate the caller's anchor. Anchor holds no reference types that
	// need a deep copy: EntryRange is two strings.
	out := a
	if out.SigningKeyID == "" {
		out.SigningKeyID = keyID
	}
	// Defensive, and knowingly redundant: Signature is excluded from every
	// canonical form (pinned by TestCanonicalize_ExcludesSignature) and the
	// final assignment below overwrites it either way, so clearing it here
	// changes nothing observable today. It is kept so that a canonical form
	// which ever DID include the field could not sign a stale signature. A
	// mutation deleting this line survives, correctly.
	out.Signature = ""

	// Refuse before signing exactly what VerifySignature refuses after, so this
	// package cannot produce an anchor it will not accept.
	if err := ValidateVersionInvariants(out); err != nil {
		return Anchor{}, fmt.Errorf("anchor: refusing to sign an invalid anchor: %w", err)
	}
	if out.Version == MerkleVersion {
		return Anchor{}, fmt.Errorf("%w: refusing to sign v%d, which this package "+
			"canonicalizes but will not verify", ErrVerificationUnsupported, out.Version)
	}

	canonical, err := Canonicalize(out)
	if err != nil {
		return Anchor{}, fmt.Errorf("anchor: canonicalize: %w", err)
	}

	sig, _, err := SignCanonical(ctx, s, canonical)
	if err != nil {
		return Anchor{}, err
	}

	out.Signature = base64.StdEncoding.EncodeToString(sig)
	return out, nil
}

// SignCanonical signs canonical bytes and verifies the result before returning it.
//
// # Description
//
// The lower-level primitive under [SignAnchor]. Prefer SignAnchor: this
// function receives opaque bytes and therefore cannot guarantee they were
// assembled correctly.
//
// It does four things, in an order that matters:
//
//  1. Derives the key id and public key from the signer ([KeyIDOf]). A signer
//     for the wrong algorithm dies here.
//  2. Refuses canonical bytes carrying an EMPTY signing_key_id — signing those
//     produces an anchor that can never verify, because populating the field
//     afterwards changes the signed bytes.
//  3. Signs, and length-checks the signature.
//  4. VERIFIES the signature under the signer's own public key, and refuses to
//     return one that does not check out.
//
// # Why step 4 exists
//
// crypto.Signer's byte slice means two incompatible things depending on
// algorithm, and the interface cannot tell them apart:
//
//	RSA, ECDSA        the caller hashes first and passes a 32-byte DIGEST
//	Ed25519, ML-DSA   the caller passes the WHOLE MESSAGE; the algorithm hashes
//
// A signer written with RSA habits hashes internally and then signs. Handed
// canonical anchor bytes it returns a well-formed ML-DSA-65 signature of exactly
// the right length over SHA-256(canonical) instead of over canonical. Every
// structural check passes; the anchor is worthless, and nothing says so until
// someone tries to verify it, possibly at audit time.
//
// Verifying here turns that into an immediate, loud failure with the signature
// never leaving the function. It also catches a truncated signature, a signer of
// the wrong algorithm, a faulted signature, and any merely buggy adapter. It is
// unconditional and there is no flag to switch it off: a signature that does not
// verify under its own key has no legitimate use.
//
// **What step 4 does NOT establish: authenticity.** It proves the signature
// matches the key the signer ADVERTISES. A substituted or compromised signer
// that swaps in its own keypair passes every check here and returns a perfect
// signature under the attacker's key. Catching that requires verifying against a
// key obtained independently — a TrustPlatform or TrustProvided ring — not a
// TrustSelf ring built from the anchor's own accompanying key.
//
// # Inputs
//
//   - ctx: forwarded to s.SignContext
//   - s: the signer; see [FromCryptoSigner] for adapting a plain crypto.Signer
//   - canonical: the bytes to sign, from [Canonicalize]. Never a digest.
//
// # Outputs
//
//   - []byte: the signature, SignatureSize bytes
//   - string: the key id derived from the signer's public key
//   - error: ErrKeyIDMissing, ErrSignerProducedBadSignature, or a wrapped
//     failure from any step
//
// # Example
//
//	sig, keyID, err := anchor.SignCanonical(ctx, signer, canonical)
//
// # Limitations
//
//   - ML-DSA-65 only, matching [VerifySignature].
//   - Costs one extra ML-DSA verification per anchor. Anchors are produced
//     rarely; a signature nobody checked is not worth the microseconds saved.
//   - Refuses an EMPTY signing_key_id but ACCEPTS one that differs from the
//     derived id, because KMS and registry keys legitimately carry assigned
//     labels. Use [SignAnchor] to have the binding handled for you.
//   - Says nothing about whether the canonical bytes describe a real chain.
//
// # Assumptions
//
//   - canonical is already the exact bytes that should be signed.
func SignCanonical(ctx context.Context, s ContextSigner, canonical []byte) ([]byte, string, error) {
	keyID, pub, err := KeyIDOf(s)
	if err != nil {
		return nil, "", err
	}
	if len(canonical) == 0 {
		return nil, "", errors.New("anchor: canonical bytes are required")
	}
	if len(canonical) > maxCanonicalSize {
		return nil, "", fmt.Errorf("anchor: canonical bytes are %d, exceeding the %d limit",
			len(canonical), maxCanonicalSize)
	}

	// An empty signing_key_id is never legitimate: the field is inside these
	// very bytes, so a caller who fills it in afterwards publishes an anchor
	// whose signature covers a different value. That produces a permanent,
	// undiagnosable verification failure, and it is the single easiest mistake
	// to make with this function.
	if bytes.Contains(canonical, []byte(`"signing_key_id":""`)) {
		return nil, "", fmt.Errorf("%w: it is part of the signed form, so setting it after "+
			"canonicalizing would change these bytes; use SignAnchor, or set it before "+
			"Canonicalize (derived id for this signer: %s)", ErrKeyIDMissing, keyID)
	}

	sig, err := s.SignContext(ctx, canonical)
	if err != nil {
		return nil, "", fmt.Errorf("anchor: signer: %w", err)
	}
	if len(sig) != SignatureSize {
		return nil, "", fmt.Errorf("anchor: signature is %d bytes, want %d (ML-DSA-65)",
			len(sig), SignatureSize)
	}

	// Step 4, through the SAME primitive VerifySignature uses. Routing it
	// through a different one would weaken the guarantee to "some verifier
	// accepts this" rather than "this package's verifier accepts this".
	if err := verifyMLDSA65(pub, canonical, sig); err != nil {
		return nil, "", fmt.Errorf("%w (key %s): the most likely cause is a signer that "+
			"hashes its input before signing — ML-DSA signs the message itself: %w",
			ErrSignerProducedBadSignature, keyID, err)
	}

	return sig, keyID, nil
}

// verifyMLDSA65 is the one ML-DSA-65 verification in this package.
//
// Both [VerifySignature] and [SignCanonical]'s self-check call it, so "I just
// produced a signature that verifies" and "this package accepts this signature"
// cannot drift apart.
func verifyMLDSA65(pub, msg, sig []byte) error {
	return mldsa.Verify(mldsa.MLDSA65, pub, msg, sig)
}
