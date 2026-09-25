// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor_test

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aleutian-ai/proof/anchor"
)

// Example_verifyingWithYourOwnKeys shows the bring-your-own-key model (D14).
//
// proof embeds no public keys. You supply them, and you say what trusting them
// establishes — which is why the result can distinguish a third-party
// attestation from the chain holder's own claim.
func Example_verifyingWithYourOwnKeys() {
	// A key you obtained deliberately: from a vendor's published trust manifest,
	// your own KMS, or a colleague. Where it came from is what decides the trust
	// level, and only you know that.
	publicKey := make([]byte, anchor.PublicKeySize)

	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{
		"aleutian-ml-dsa-65-2026-v1": publicKey,
	})
	if err != nil {
		fmt.Println("key ring:", err)
		return
	}

	a := anchor.Anchor{
		Version:      3,
		SigningKeyID: "some-key-we-do-not-hold",
		Signature:    base64.StdEncoding.EncodeToString(make([]byte, anchor.SignatureSize)),
	}

	_, err = anchor.VerifySignature(a, ring)
	switch {
	case errors.Is(err, anchor.ErrUnknownKeyID):
		// Distinct from a bad signature on purpose: a missing trust root is a
		// configuration problem, not an attack, and must not look like one.
		fmt.Println("unknown signer — not a tampering signal")
	case errors.Is(err, anchor.ErrInvalidSignature):
		fmt.Println("signature did not verify")
	case err != nil:
		fmt.Println("error:", err)
	default:
		fmt.Println("verified")
	}

	// Output:
	// unknown signer — not a tampering signal
}

// Example_trustLevelsMakeDifferentClaims shows why the level is reported rather
// than assumed. The same valid signature means different things depending on
// where its key came from, and the wording must not blur them.
func Example_trustLevelsMakeDifferentClaims() {
	for _, t := range []anchor.Trust{anchor.TrustPlatform, anchor.TrustProvided, anchor.TrustSelf} {
		fmt.Printf("%-9s %s\n", t, t.Establishes())
	}
	// Output:
	// platform  a third party attests to this chain
	// provided  the holder of a key you supplied attests to this chain
	// self      the chain's own holder attests to it; no third party is involved
}

// Example_signingAnAnchor shows the whole producer path.
//
// The point of SignAnchor being ONE call is that signing_key_id lives inside
// the signed bytes. Setting it after canonicalizing signs one set of bytes and
// publishes another, giving an anchor that fails verification permanently with
// a diagnostic indistinguishable from forgery. This project has shipped that
// bug before; the API is now shaped so it cannot recur. See docs/decisions.md
// D17.
//
// This example is compiled and executed by `go test`, so unlike prose it cannot
// quietly rot into teaching the wrong order.
func Example_signingAnAnchor() {
	// In practice this comes from `proof keygen`, read back with
	// keyfile.ParsePrivateKey. A fixed seed here keeps the output stable.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	signer, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		fmt.Println("signer:", err)
		return
	}
	// Zeroizes the seed. It cannot promise the key is gone from process memory
	// — see MLDSA65Signer's documented limitations — but it drops the
	// long-lived copy.
	defer signer.Close()

	a := anchor.Anchor{
		Version:         anchor.SubjectVersion, // v6
		AnchorID:        "anchor_2026_09_24",
		Subject:         "acct-pseudonym-7f3a", // NEVER a name or email: see below
		ChainHash:       strings.Repeat("a", 128),
		EntryCount:      42,
		VerifiedThrough: 42,
		Range: anchor.EntryRange{
			StartEntryID: "ent_first",
			EndEntryID:   "ent_last",
		},
		CreatedAtMs: 1758700000000,
	}

	// One call: stamps the key id, validates, refuses v5, canonicalizes, signs,
	// and verifies the signature before handing it back. The input is not
	// mutated; signed is a copy.
	signed, err := anchor.SignAnchor(context.Background(), signer, a)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	// Verify it the way a third party would. TrustSelf is honest here: this key
	// was generated locally, so it establishes the holder's own claim and
	// nothing about an independent witness.
	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		fmt.Println("public key:", err)
		return
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{
		signed.SigningKeyID: pub,
	})
	if err != nil {
		fmt.Println("key ring:", err)
		return
	}
	trust, err := anchor.VerifySignature(signed, ring)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}

	fmt.Println("key id length:", len(signed.SigningKeyID))
	fmt.Println("signed:", signed.Signature != "")
	fmt.Println("establishes:", trust.Establishes())

	// Output:
	// key id length: 32
	// signed: true
	// establishes: the chain's own holder attests to it; no third party is involved
}

// Example_signingWithYourOwnKeyManagement shows the seam for Cloud KMS, an HSM,
// a PKCS#11 token or a keychain. proof holds no credentials and opens no
// connections; you implement two methods.
//
// crypto.Signer is deliberately NOT required here — nothing in the package
// calls it, so demanding it would oblige every KMS implementer to write a Sign
// method whose rand and opts are meaningless for ML-DSA. If you already have a
// crypto.Signer, anchor.FromCryptoSigner wraps it (and says plainly that the
// wrapper cannot honour a context).
func Example_signingWithYourOwnKeyManagement() {
	var _ anchor.ContextSigner = myKMSSigner{}
	fmt.Println("two methods: Public() and SignContext()")
	// Output:
	// two methods: Public() and SignContext()
}

// myKMSSigner stands in for a signer backed by key management you control.
type myKMSSigner struct{}

func (myKMSSigner) Public() crypto.PublicKey {
	// Whatever your KMS returns, so long as its bytes are reachable through
	// encoding.BinaryMarshaler and are a 1952-byte ML-DSA-65 public key.
	return nil
}

func (myKMSSigner) SignContext(ctx context.Context, msg []byte) ([]byte, error) {
	// msg is the WHOLE MESSAGE, never a digest. ML-DSA hashes internally
	// (FIPS 204 §5.3). Pre-hashing here would produce a structurally perfect
	// signature over the wrong bytes — which SignAnchor catches, because it
	// verifies every signature before returning it.
	return nil, errors.New("wire this to your KMS")
}
