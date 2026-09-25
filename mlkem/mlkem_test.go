// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package mlkem_test

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mlkem"
)

// specCases pair each parameter set with the RFC 9935 example key files, which
// live in keyfile's testdata with provenance recorded there.
var specCases = []struct {
	set        mlkem.ParameterSet
	seedFile   string
	publicFile string
	pubSize    int
	ctSize     int
}{
	{mlkem.MLKEM768, "mlkem768_seed.pem", "mlkem768_public.pem", 1184, 1088},
	{mlkem.MLKEM1024, "mlkem1024_seed.pem", "mlkem1024_public.pem", 1568, 1568},
}

// readKeyfile loads a fixture from the keyfile package's testdata.
func readKeyfile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "keyfile", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// seedFor parses a spec example seed.
func seedFor(t *testing.T, file string) []byte {
	t.Helper()
	_, seed, err := keyfile.ParsePrivateKey(readKeyfile(t, file))
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	return seed
}

// TestSizesMatchTheStandard pins the FIPS 203 sizes against real derived keys.
func TestSizesMatchTheStandard(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			if got := tc.set.SeedSize(); got != 64 {
				t.Errorf("SeedSize = %d, want 64", got)
			}
			if got := tc.set.PublicKeySize(); got != tc.pubSize {
				t.Errorf("PublicKeySize = %d, want %d", got, tc.pubSize)
			}
			if got := tc.set.CiphertextSize(); got != tc.ctSize {
				t.Errorf("CiphertextSize = %d, want %d", got, tc.ctSize)
			}
			// Cross-check against what the implementation actually produces.
			pub, err := mlkem.PublicKeyFromSeed(tc.set, seedFor(t, tc.seedFile))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if len(pub) != tc.pubSize {
				t.Errorf("derived public key is %d bytes, want %d", len(pub), tc.pubSize)
			}
			ct, ss, err := mlkem.Encapsulate(tc.set, pub)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			defer ss.Zeroize()
			if len(ct) != tc.ctSize {
				t.Errorf("ciphertext is %d bytes, want %d", len(ct), tc.ctSize)
			}
		})
	}
}

// TestPublicKeyFromSeedMatchesSpec: derive from the specification's example
// seed and require the specification's example public key.
func TestPublicKeyFromSeedMatchesSpec(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			_, wantPub, err := keyfile.ParsePublicKey(readKeyfile(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			gotPub, err := mlkem.PublicKeyFromSeed(tc.set, seedFor(t, tc.seedFile))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if !bytes.Equal(gotPub, wantPub) {
				t.Error("derived public key does not match the specification's example")
			}
		})
	}
}

// TestEncapsulateDecapsulateRoundTrip is the core property.
func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			seed := seedFor(t, tc.seedFile)
			pub, err := mlkem.PublicKeyFromSeed(tc.set, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			ct, sender, err := mlkem.Encapsulate(tc.set, pub)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			recipient, err := mlkem.Decapsulate(tc.set, seed, ct)
			if err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if sender != recipient {
				t.Error("sender and recipient derived different shared secrets")
			}
			if sender == (mlkem.SharedSecret{}) {
				t.Error("shared secret is all zeros")
			}
		})
	}
}

// TestImplicitRejection pins ML-KEM's defining behaviour: a ciphertext for a
// different key yields an unrelated secret and NO error. Code that expects an
// error here would wrongly treat a wrong key as a system failure.
func TestImplicitRejection(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			seed := seedFor(t, tc.seedFile)
			pub, err := mlkem.PublicKeyFromSeed(tc.set, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			ct, sender, err := mlkem.Encapsulate(tc.set, pub)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}

			otherSeed := append([]byte(nil), seed...)
			otherSeed[0] ^= 0x01
			wrong, err := mlkem.Decapsulate(tc.set, otherSeed, ct)
			if err != nil {
				t.Fatalf("decapsulate with the wrong key returned an error: %v", err)
			}
			if wrong == sender {
				t.Error("the wrong key recovered the sender's secret")
			}

			tampered := append([]byte(nil), ct...)
			tampered[0] ^= 0x01
			altered, err := mlkem.Decapsulate(tc.set, seed, tampered)
			if err != nil {
				t.Fatalf("decapsulate of a tampered ciphertext returned an error: %v", err)
			}
			if altered == sender {
				t.Error("a tampered ciphertext recovered the original secret")
			}
		})
	}
}

// TestEncapsulateIsRandomised: two encapsulations to the same key must differ.
// Identical output would mean the randomness is broken.
func TestEncapsulateIsRandomised(t *testing.T) {
	seed := seedFor(t, "mlkem768_seed.pem")
	pub, err := mlkem.PublicKeyFromSeed(mlkem.MLKEM768, seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	ct1, ss1, err := mlkem.Encapsulate(mlkem.MLKEM768, pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	ct2, ss2, err := mlkem.Encapsulate(mlkem.MLKEM768, pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("two encapsulations produced the same ciphertext")
	}
	if ss1 == ss2 {
		t.Error("two encapsulations produced the same shared secret")
	}
}

// TestCrossParameterSetRejected: a ML-KEM-768 key must not be usable as 1024.
func TestCrossParameterSetRejected(t *testing.T) {
	seed := seedFor(t, "mlkem768_seed.pem")
	pub, err := mlkem.PublicKeyFromSeed(mlkem.MLKEM768, seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if _, _, err := mlkem.Encapsulate(mlkem.MLKEM1024, pub); !errors.Is(err, mlkem.ErrInvalidKey) {
		t.Errorf("768 key accepted as 1024: err = %v", err)
	}
	ct, _, err := mlkem.Encapsulate(mlkem.MLKEM768, pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	if _, err := mlkem.Decapsulate(mlkem.MLKEM1024, seed, ct); !errors.Is(err, mlkem.ErrInvalidCiphertext) {
		t.Errorf("768 ciphertext accepted as 1024: err = %v", err)
	}
}

// TestSharedSecretRedacts mirrors the xwing rules from _26.
func TestSharedSecretRedacts(t *testing.T) {
	var ss mlkem.SharedSecret
	for i := range ss {
		ss[i] = 0xa5
	}
	leaks := func(s string) bool {
		for _, m := range []string{"165", "a5a5", "A5A5", "245", "10100101", "paWl"} {
			if strings.Contains(s, m) {
				return true
			}
		}
		return false
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q"} {
		out := fmt.Sprintf(verb, ss)
		if leaks(out) || !strings.Contains(out, "[REDACTED SharedSecret]") {
			t.Errorf("%s printed %q", verb, out)
		}
	}
	if _, err := json.Marshal(ss); err == nil {
		t.Error("json.Marshal serialized a shared secret")
	}
	if _, err := ss.MarshalText(); err == nil {
		t.Error("MarshalText serialized a shared secret")
	}
	if err := gob.NewEncoder(&bytes.Buffer{}).Encode(ss); err == nil {
		t.Error("gob serialized a shared secret")
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("k", "ss", ss)
	if leaks(buf.String()) || strings.Contains(buf.String(), "ERROR") {
		t.Errorf("slog logged %q", buf.String())
	}
	ss.Zeroize()
	if ss != (mlkem.SharedSecret{}) {
		t.Error("Zeroize did not clear the secret")
	}
}

// TestInvalidInputs covers the argument-checking paths.
func TestInvalidInputs(t *testing.T) {
	seed := make([]byte, 64)
	bad := mlkem.ParameterSet(99)
	if _, err := mlkem.PublicKeyFromSeed(bad, seed); !errors.Is(err, mlkem.ErrUnsupportedParameterSet) {
		t.Errorf("unknown set: %v", err)
	}
	if _, _, err := mlkem.Encapsulate(bad, make([]byte, 1184)); !errors.Is(err, mlkem.ErrUnsupportedParameterSet) {
		t.Errorf("unknown set encapsulate: %v", err)
	}
	if _, err := mlkem.Decapsulate(bad, seed, make([]byte, 1088)); !errors.Is(err, mlkem.ErrUnsupportedParameterSet) {
		t.Errorf("unknown set decapsulate: %v", err)
	}
	if _, err := mlkem.PublicKeyFromSeed(mlkem.MLKEM768, seed[:32]); !errors.Is(err, mlkem.ErrInvalidKey) {
		t.Errorf("short seed: %v", err)
	}
	if _, _, err := mlkem.Encapsulate(mlkem.MLKEM768, make([]byte, 10)); !errors.Is(err, mlkem.ErrInvalidKey) {
		t.Errorf("short public key: %v", err)
	}
	if _, err := mlkem.Decapsulate(mlkem.MLKEM768, seed, make([]byte, 10)); !errors.Is(err, mlkem.ErrInvalidCiphertext) {
		t.Errorf("short ciphertext: %v", err)
	}
}

// TestCallerSeedNotMutated: the package must not touch the caller's seed.
func TestCallerSeedNotMutated(t *testing.T) {
	for _, tc := range specCases {
		t.Run(tc.set.String(), func(t *testing.T) {
			seed := seedFor(t, tc.seedFile)
			original := append([]byte(nil), seed...)
			pub, err := mlkem.PublicKeyFromSeed(tc.set, seed)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			ct, _, err := mlkem.Encapsulate(tc.set, pub)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			if _, err := mlkem.Decapsulate(tc.set, seed, ct); err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if !bytes.Equal(seed, original) {
				t.Error("the caller's seed was modified")
			}
		})
	}
}

// TestACVPKeyGen checks key derivation against NIST's ACVP vectors — external
// evidence, unlike anything this code produces itself. See testdata/README.md.
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
		Vectors []struct {
			TcID         int    `json:"tcId"`
			ParameterSet string `json:"parameterSet"`
			Seed         string `json:"seed"`
			EK           string `json:"ek"`
		} `json:"vectors"`
	}
	if err := json.NewDecoder(gz).Decode(&file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	sets := map[string]mlkem.ParameterSet{"ML-KEM-768": mlkem.MLKEM768, "ML-KEM-1024": mlkem.MLKEM1024}
	seen := map[mlkem.ParameterSet]int{}
	for _, v := range file.Vectors {
		set, ok := sets[v.ParameterSet]
		if !ok {
			t.Fatalf("tc %d: unexpected parameter set %q", v.TcID, v.ParameterSet)
		}
		seed, err := hex.DecodeString(strings.TrimSpace(v.Seed))
		if err != nil {
			t.Fatalf("tc %d: seed: %v", v.TcID, err)
		}
		want, err := hex.DecodeString(strings.TrimSpace(v.EK))
		if err != nil {
			t.Fatalf("tc %d: ek: %v", v.TcID, err)
		}
		got, err := mlkem.PublicKeyFromSeed(set, seed)
		if err != nil {
			t.Fatalf("tc %d: derive: %v", v.TcID, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("tc %d (%s): derived key does not match the ACVP vector", v.TcID, v.ParameterSet)
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
