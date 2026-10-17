// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

type v7File struct {
	Context        string `json:"context"`
	SeedAnchorHash string `json:"seed_anchor_hash"`
	Key            struct {
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		KeyID        string `json:"key_id"`
	} `json:"key"`
	Vectors []struct {
		Name              string `json:"name"`
		TipChainHash      string `json:"tip_chain_hash"`
		CanonicalBytes    string `json:"canonical_bytes"`
		ExpectedChainHash string `json:"expected_chain_hash"`
		Text              string `json:"text"`
	} `json:"vectors"`
	Reject []struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
		Text   string `json:"text"`
	} `json:"reject"`
}

func loadV7(t *testing.T) (v7File, *KeyRing) {
	t.Helper()
	var f v7File
	if err := json.Unmarshal(fixtures.AnchorV7Vectors(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Context != ContextV7 || f.SeedAnchorHash != SeedAnchorHash {
		t.Fatalf("vectors are for context %q", f.Context)
	}
	if len(f.Vectors) < 7 || len(f.Reject) < 20 {
		t.Fatalf("%d vectors, %d reject: the file was truncated", len(f.Vectors), len(f.Reject))
	}
	pub, _ := hex.DecodeString(f.Key.PublicKeyHex)
	kr, err := NewKeyRing(TrustProvided, map[string][]byte{f.Key.KeyID: pub})
	if err != nil {
		t.Fatal(err)
	}
	return f, kr
}

// TestAnchorV7_SharedVectors holds Go to the v7 vectors, computed in Python
// with dilithium-py from the spec: canonical bytes, chain hash, signatures
// with the v7 context, and a parse that writes the text back the same.
func TestAnchorV7_SharedVectors(t *testing.T) {
	f, kr := loadV7(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var a Anchor
			if err := json.Unmarshal([]byte(v.Text), &a); err != nil {
				t.Fatal(err)
			}
			canon, err := Canonicalize(a)
			if err != nil {
				t.Fatal(err)
			}
			if string(canon) != v.CanonicalBytes {
				t.Errorf("canonical bytes\n got  %s\n want %s", canon, v.CanonicalBytes)
			}
			if got := ChainHashV7(a.PreviousAnchorHash, a.Subject, a.Range.StartSeq, a.Range.EndSeq, v.TipChainHash); got != v.ExpectedChainHash || a.ChainHash != got {
				t.Errorf("chain hash %s, anchor says %s, want %s", got, a.ChainHash, v.ExpectedChainHash)
			}
			if _, err := VerifySignature(a, kr); err != nil {
				t.Errorf("signature: %v", err)
			}
			if out, _ := json.Marshal(a); string(out) != v.Text {
				t.Errorf("written back as\n %s\nwant\n %s", out, v.Text)
			}
		})
	}
	for _, r := range f.Reject {
		t.Run("reject: "+r.Name, func(t *testing.T) {
			var a Anchor
			if err := json.Unmarshal([]byte(r.Text), &a); err != nil {
				return
			}
			if _, err := VerifySignature(a, kr); err == nil {
				t.Errorf("accepted an anchor every implementation must refuse (%s)", r.Reason)
			}
		})
	}
}

// TestAnchorV7_SignsWhatThePythonVectorsVerify: this package's signer, given
// the vectors' seed, produces the vectors' signatures byte for byte
// (deterministic ML-DSA, FIPS 204), with the v7 context.
func TestAnchorV7_SignsWhatThePythonVectorsVerify(t *testing.T) {
	f, _ := loadV7(t)
	seed, _ := hex.DecodeString(f.Key.SeedHex)
	s, err := NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		var a Anchor
		if err := json.Unmarshal([]byte(v.Text), &a); err != nil {
			t.Fatal(err)
		}
		want := a.Signature
		signed, err := SignAnchor(context.Background(), s, a)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if signed.Signature != want {
			t.Errorf("%s: Go's signature differs from the vector's", v.Name)
		}
	}
}

// TestAnchorV7_SignerWithoutContextIsRefused: a ContextSigner that cannot
// sign with a context string is refused for v7, not allowed to produce a
// signature with the empty one.
func TestAnchorV7_SignerWithoutContextIsRefused(t *testing.T) {
	f, _ := loadV7(t)
	var a Anchor
	if err := json.Unmarshal([]byte(f.Vectors[0].Text), &a); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(f.Key.SeedHex)
	if _, err := SignAnchor(context.Background(), minimalSigner{seed}, a); err == nil {
		t.Fatal("a signer without context strings signed a v7 anchor")
	}
}
