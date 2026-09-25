// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package mldsa_test

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/mldsa"
)

// TestACVPKeyGen checks key derivation against NIST's ACVP vectors.
//
// # Why this exists
//
// The signature known-answer digests in mldsa_test.go were produced BY THIS
// CODE: they detect drift, not error. These vectors come from NIST's Automated
// Cryptographic Validation Program — the same data used to validate FIPS 204
// implementations — so agreeing with them means agreeing with the standard.
//
// Only key generation is covered. ACVP's signature vectors drive
// Sign_internal from an expanded signing key with no context prefix, which is
// not the seed-based pure-ML-DSA path this package exposes, so they cannot be
// run through it without reaching into internals. That gap is stated in the
// ticket rather than papered over.
func TestACVPKeyGen(t *testing.T) {
	f, err := os.Open("testdata/acvp_keygen.json.gz")
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	defer gz.Close()

	var file struct {
		Source  string `json:"_source"`
		Vectors []struct {
			TcID         int    `json:"tcId"`
			ParameterSet string `json:"parameterSet"`
			Seed         string `json:"seed"`
			PK           string `json:"pk"`
		} `json:"vectors"`
	}
	if err := json.NewDecoder(gz).Decode(&file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	sets := map[string]mldsa.ParameterSet{
		"ML-DSA-44": mldsa.MLDSA44, "ML-DSA-65": mldsa.MLDSA65, "ML-DSA-87": mldsa.MLDSA87,
	}
	seen := map[mldsa.ParameterSet]int{}
	for _, v := range file.Vectors {
		set, ok := sets[v.ParameterSet]
		if !ok {
			t.Fatalf("tc %d: unknown parameter set %q", v.TcID, v.ParameterSet)
		}
		seed, err := hex.DecodeString(strings.TrimSpace(v.Seed))
		if err != nil {
			t.Fatalf("tc %d: seed: %v", v.TcID, err)
		}
		want, err := hex.DecodeString(strings.TrimSpace(v.PK))
		if err != nil {
			t.Fatalf("tc %d: pk: %v", v.TcID, err)
		}
		got, err := mldsa.PublicKeyFromSeed(set, seed)
		if err != nil {
			t.Fatalf("tc %d: derive: %v", v.TcID, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("tc %d (%s): derived public key does not match the ACVP vector", v.TcID, v.ParameterSet)
		}
		seen[set]++
	}
	for name, set := range sets {
		if seen[set] == 0 {
			t.Errorf("no vectors exercised %s", name)
		}
	}
	t.Logf("ACVP keyGen: %d vectors across %d parameter sets", len(file.Vectors), len(seen))
}
