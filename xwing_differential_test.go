// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	cx "github.com/cloudflare/circl/kem/xwing"

	"github.com/aleutian-ai/proof/xwing"
)

// differentialRounds is the number of random keys each direction is tested with.
const differentialRounds = 200

// TestXWingDifferentialAgainstCircl checks this module's X-Wing against an
// independent implementation.
//
// # Why this exists
//
// The official vectors in xwing/testdata prove key derivation and
// decapsulation, but not encapsulation: crypto/mlkem has no derandomized
// encapsulation, so the specification's ciphertexts cannot be reproduced here.
// Cloudflare's circl implements the same specification, checks itself against
// the same official vectors, and shares no code with this one. Agreement in
// both directions over random keys is the encapsulation evidence.
//
// # Why circl is only a TEST dependency
//
// circl brings its own ML-KEM, X25519, and SHA-3, all outside Go's FIPS 140-3
// module boundary. xwing imports only the standard library, which keeps it
// inside that boundary. Using circl as an oracle here costs nothing a user
// compiles: TestDependencyIsolation reads `go list -deps` without -test. It is
// also why go.mod lists golang.org/x/crypto as indirect: circl's X25519 reaches
// x/crypto/cryptobyte, and ONLY from this test build — no non-test package in
// the module imports it.
func TestXWingDifferentialAgainstCircl(t *testing.T) {
	for i := 0; i < differentialRounds; i++ {
		seed := make([]byte, cx.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("read seed: %v", err)
		}

		priv, err := xwing.NewPrivateKey(seed)
		if err != nil {
			t.Fatalf("NewPrivateKey: %v", err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		ourPK, err := pub.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		circlSK, circlPK := cx.DeriveKeyPairPacked(seed)

		if !bytes.Equal(ourPK, circlPK) {
			t.Fatalf("round %d: public key derived from the same seed differs from circl", i)
		}

		// Ours encapsulates → circl decapsulates.
		ct, ss, err := xwing.Encapsulate(pub)
		if err != nil {
			t.Fatalf("round %d: Encapsulate: %v", i, err)
		}
		wire := append(append([]byte{}, ct.MLKEMCT...), ct.X25519EPK...)
		if got := cx.Decapsulate(wire, circlSK); !bytes.Equal(got, ss[:]) {
			t.Fatalf("round %d: circl could not decapsulate our ciphertext", i)
		}

		// circl encapsulates → ours decapsulates.
		eseed := make([]byte, cx.EncapsulationSeedSize)
		if _, err := rand.Read(eseed); err != nil {
			t.Fatalf("read eseed: %v", err)
		}
		circlSS, circlCT, err := cx.Encapsulate(circlPK, eseed)
		if err != nil {
			t.Fatalf("round %d: circl Encapsulate: %v", i, err)
		}
		got, err := xwing.Decapsulate(
			xwing.Ciphertext{MLKEMCT: circlCT[:1088], X25519EPK: circlCT[1088:]}, priv)
		if err != nil {
			t.Fatalf("round %d: Decapsulate circl ciphertext: %v", i, err)
		}
		if !bytes.Equal(got[:], circlSS) {
			t.Fatalf("round %d: our decapsulation of circl's ciphertext disagrees", i)
		}
	}
}
