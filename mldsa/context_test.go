// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package mldsa

import (
	"bytes"
	"testing"
)

// TestContext_BindsTheSignature: a signature verifies with the context it was
// made with and with no other, the empty one included; and with an empty
// context the two pairs of functions agree.
func TestContext_BindsTheSignature(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	msg := []byte("canonical bytes")
	for _, set := range []ParameterSet{MLDSA44, MLDSA65, MLDSA87} {
		pub, err := PublicKeyFromSeed(set, seed)
		if err != nil {
			t.Fatal(err)
		}
		a := []byte("aleutian.proof.anchor.v7")
		sig, err := SignWithContext(set, seed, msg, a)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyWithContext(set, pub, msg, sig, a); err != nil {
			t.Errorf("%s: own context: %v", set, err)
		}
		for _, other := range [][]byte{nil, []byte("aleutian.proof.record.v2")} {
			if VerifyWithContext(set, pub, msg, sig, other) == nil {
				t.Errorf("%s: verified under context %q", set, other)
			}
		}
		if Verify(set, pub, msg, sig) == nil {
			t.Errorf("%s: a context signature verified with Verify", set)
		}
		plain, _ := Sign(set, seed, msg)
		empty, _ := SignWithContext(set, seed, msg, nil)
		if !bytes.Equal(plain, empty) {
			t.Errorf("%s: Sign and an empty-context SignWithContext differ", set)
		}
		if _, err := SignWithContext(set, seed, msg, make([]byte, MaxContextSize+1)); err == nil {
			t.Errorf("%s: signed with a 256-byte context", set)
		}
	}
}
