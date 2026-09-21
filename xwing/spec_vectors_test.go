// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package xwing

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// specChecksum is the SHAKE128 checksum of the X-Wing specification's official
// spec/test-vectors.txt. It is hard-coded here, not read from the fixture, so
// that editing the fixture's vectors AND its recorded checksum together still
// fails.
const specChecksum = "1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe"

// specVectorFile is testdata/xwing_spec_vectors.json.
type specVectorFile struct {
	ChecksumSHAKE128 string       `json:"checksum_shake128"`
	Vectors          []specVector `json:"vectors"`
}

// specVector is one official vector. Field order matches the specification's
// text file, which matters for TestSpecVectorsAreOfficial.
type specVector struct {
	Seed  string `json:"seed"`
	SK    string `json:"sk"`
	PK    string `json:"pk"`
	ESeed string `json:"eseed"`
	CT    string `json:"ct"`
	SS    string `json:"ss"`
}

// loadSpecVectors reads and decodes the fixture.
func loadSpecVectors(t *testing.T) specVectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/xwing_spec_vectors.json")
	if err != nil {
		t.Fatalf("read spec vectors: %v", err)
	}
	var f specVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode spec vectors: %v", err)
	}
	if len(f.Vectors) != 3 {
		t.Fatalf("fixture has %d vectors, the specification publishes 3", len(f.Vectors))
	}
	return f
}

// mustHex decodes a fixture field or fails the test.
func mustHex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return b
}

// renderSpecText reproduces the byte layout of spec/test-vectors.txt: a field
// that fits on one line is "name     hex"; a longer one is the name alone,
// followed by the hex wrapped at 72 characters with a two-space indent. Each
// vector ends with a blank line.
func renderSpecText(t *testing.T, vs []specVector) []byte {
	t.Helper()
	var w bytes.Buffer
	field := func(name, h string) {
		const indent, width = "  ", 74
		if len(name)+len(h)+5 < width {
			fmt.Fprintf(&w, "%s     %s\n", name, h)
			return
		}
		fmt.Fprintf(&w, "%s\n", name)
		for len(h) > 0 {
			n := width - len(indent)
			if len(h) < n {
				n = len(h)
			}
			fmt.Fprintf(&w, "%s%s\n", indent, h[:n])
			h = h[n:]
		}
	}
	for _, v := range vs {
		field("seed", v.Seed)
		field("sk", v.SK)
		field("pk", v.PK)
		field("eseed", v.ESeed)
		field("ct", v.CT)
		field("ss", v.SS)
		w.WriteString("\n")
	}
	return w.Bytes()
}

// TestSpecVectorsAreOfficial proves the fixture IS the specification's vector
// file rather than something that merely resembles it.
//
// # Why this exists
//
// Every earlier X-Wing test in this module, and in each SDK that copied it, was
// checked against self-generated vectors (testdata/xwing_kat.json). Those prove
// that implementations agree with each other; they cannot detect a deviation
// that all of them share. A fixture of "official" vectors is only worth
// something if nobody can quietly regenerate it from this code — so the whole
// file is re-rendered in the specification's text format and hashed, and the
// hash must equal the one published for spec/test-vectors.txt.
func TestSpecVectorsAreOfficial(t *testing.T) {
	f := loadSpecVectors(t)

	h := sha3.NewSHAKE128()
	h.Write(renderSpecText(t, f.Vectors))
	sum := make([]byte, 32)
	h.Read(sum)
	got := hex.EncodeToString(sum)

	if got != specChecksum {
		t.Fatalf("fixture does not reproduce the specification's vector file:\n"+
			" got  %s\n want %s\n"+
			"A vector was edited, regenerated, or reordered. Restore it from the "+
			"specification rather than from this implementation.", got, specChecksum)
	}
	if f.ChecksumSHAKE128 != specChecksum {
		t.Errorf("fixture records checksum %s, want %s", f.ChecksumSHAKE128, specChecksum)
	}
}

// TestSpecVectors checks this implementation against the official vectors.
//
// # Coverage
//
// Key derivation and decapsulation are checked directly. Encapsulation is not:
// the specification's ct is derived from eseed, and crypto/mlkem exposes no
// derandomized encapsulation, so this package cannot reproduce it. Encapsulation
// conformance is covered instead by the differential test against an
// independent implementation at the repository root.
func TestSpecVectors(t *testing.T) {
	for i, v := range loadSpecVectors(t).Vectors {
		t.Run(fmt.Sprintf("vector%d", i+1), func(t *testing.T) {
			seed := mustHex(t, "seed", v.Seed)
			wantSK := mustHex(t, "sk", v.SK)
			wantPK := mustHex(t, "pk", v.PK)
			ct := mustHex(t, "ct", v.CT)
			wantSS := mustHex(t, "ss", v.SS)

			// In the final specification the private key IS the 32-byte seed.
			if !bytes.Equal(seed, wantSK) {
				t.Fatalf("specification sk differs from seed; the key format has changed")
			}

			priv, err := NewPrivateKey(seed)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			pub, err := priv.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			gotPK, err := pub.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if !bytes.Equal(gotPK, wantPK) {
				t.Errorf("public key differs from the specification")
			}

			if len(ct) != 1120 {
				t.Fatalf("ciphertext is %d bytes, want 1120", len(ct))
			}
			ss, err := Decapsulate(Ciphertext{MLKEMCT: ct[:1088], X25519EPK: ct[1088:]}, priv)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if !bytes.Equal(ss[:], wantSS) {
				t.Errorf("shared secret differs from the specification")
			}
		})
	}
}
