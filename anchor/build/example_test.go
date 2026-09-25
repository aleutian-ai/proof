// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/verify"
)

// Example shows the whole producer path: build, sign, verify.
//
// Compiled and executed by `go test`, deliberately. A previous version of this
// module documented a signing sequence that produced permanently unverifiable
// anchors, and prose cannot fail a build.
func Example() {
	entries := exampleChain(3)

	// Build verifies the chain before it will describe it. A broken chain stops
	// here rather than being anchored and signed.
	a, err := build.Anchor(context.Background(), build.Input{
		Subject:   "acct-pseudonym-7f3a", // NEVER a name or email: anchors are not erasable
		Entries:   entries,
		Previous:  nil, // nil = the first anchor in this chain
		CreatedAt: time.Unix(1758700000, 0).UTC(),
	})
	if err != nil {
		fmt.Println("build:", err)
		return
	}

	// Sign it. SignAnchor stamps the key id, canonicalizes, signs, and verifies
	// its own output before handing it back.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		fmt.Println("signer:", err)
		return
	}
	defer signer.Close()

	signed, err := anchor.SignAnchor(context.Background(), signer, a)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	// Verify it the way a third party would. The third argument is the previous
	// anchor's chain hash — the seed sentinel here, because this is the first.
	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		fmt.Println("public key:", err)
		return
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{signed.SigningKeyID: pub})
	if err != nil {
		fmt.Println("ring:", err)
		return
	}
	res, err := verify.VerifyAnchor(signed, entries, anchor.SeedAnchorHash, ring)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}

	fmt.Println("version:         ", signed.Version)
	fmt.Println("entries:         ", signed.EntryCount)
	fmt.Println("verified through:", signed.VerifiedThrough)
	fmt.Println("bound:           ", res.Bound)
	fmt.Println("signature:       ", res.SignatureVerified)
	fmt.Println("establishes:     ", res.Trust.Establishes())

	// Output:
	// version:          6
	// entries:          3
	// verified through: 3
	// bound:            true
	// signature:        true
	// establishes:      the chain's own holder attests to it; no third party is involved
}

// ExampleAnchor_brokenChainIsRefused shows the guarantee that makes
// verified_through worth anything.
func ExampleAnchor_brokenChainIsRefused() {
	entries := exampleChain(3)
	entries[1].ContentHash = strings.Repeat("ff", 64) // someone edited an entry

	_, err := build.Anchor(context.Background(), build.Input{
		Subject: "acct-pseudonym-7f3a",
		Entries: entries,
	})
	fmt.Println(err != nil)

	// Output:
	// true
}

// exampleChain returns n linked v3 entries.
func exampleChain(n int) []verify.Entry {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	out := make([]verify.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e := verify.Entry{
			EntryID:       fmt.Sprintf("ent_%03d", i),
			EntryType:     "capture.request.v3",
			Timestamp:     ts.Format("2006-01-02T15:04:05.000000Z"),
			GlobalSeq:     int64(i),
			FormatVersion: chainformat.FormatV3,
			ContentHash:   strings.Repeat("0123456789abcdef", 8),
		}
		e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, e.ContentHash)
		prev = e.ChainHash
		out = append(out, e)
	}
	return out
}
