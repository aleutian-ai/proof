// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile_test

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
	"github.com/aleutian-ai/proof/keyfile"
)

// TestKeyID_SharedVectors holds key-id derivation, and the SPKI encoding under
// it, to vectors computed in Python.
func TestKeyID_SharedVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name         string `json:"name"`
			Algorithm    string `json:"algorithm"`
			PublicKeyHex string `json:"public_key_hex"`
			SPKIDERHex   string `json:"spki_der_hex"`
			KeyID        string `json:"key_id"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixtures.KeyIDVectors(), &file); err != nil {
		t.Fatal(err)
	}
	algs := map[string]keyfile.Algorithm{"ML-DSA-65": keyfile.MLDSA65, "X-Wing": keyfile.XWing}
	if len(file.Vectors) < 2 {
		t.Fatalf("%d vectors: the file was truncated", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			alg, ok := algs[v.Algorithm]
			if !ok {
				t.Fatalf("unknown algorithm %q", v.Algorithm)
			}
			pub, err := hex.DecodeString(v.PublicKeyHex)
			if err != nil {
				t.Fatal(err)
			}
			id, err := keyfile.KeyIDHex(alg, pub)
			if err != nil {
				t.Fatal(err)
			}
			if id != v.KeyID {
				t.Errorf("key id = %s, want %s", id, v.KeyID)
			}
			if v.SPKIDERHex == "" {
				return
			}
			p, err := keyfile.MarshalPublicKey(alg, pub)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(p)
			if block == nil || hex.EncodeToString(block.Bytes) != v.SPKIDERHex {
				t.Error("SPKI DER encoding differs from the vector")
			}
		})
	}
}
