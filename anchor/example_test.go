// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor_test

import (
	"encoding/base64"
	"errors"
	"fmt"

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
