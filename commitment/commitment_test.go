// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package commitment

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

type vector struct {
	Description string `json:"description"`
	NonceHex    string `json:"nonce_hex"`
	ContentHex  string `json:"content_hex"`
	Commitment  string `json:"commitment"`
}

func decodeVector(t *testing.T, v vector) (nonce, content []byte) {
	t.Helper()
	nonce, err := hex.DecodeString(v.NonceHex)
	if err != nil {
		t.Fatalf("fixture nonce_hex is not hex: %v", err)
	}
	content, err = hex.DecodeString(v.ContentHex)
	if err != nil {
		t.Fatalf("fixture content_hex is not hex: %v", err)
	}
	return nonce, content
}

// TestCompute_MatchesTheVectors is the conformance check. The expected values
// were computed with Python's hashlib, not by this package, so agreement here
// means two independent implementations agree. The reject cases are shared too,
// so every language checks the same refusals.
func TestCompute_MatchesTheVectors(t *testing.T) {
	var file struct {
		Domain    string   `json:"domain"`
		NonceSize int      `json:"nonce_size"`
		Vectors   []vector `json:"vectors"`
		Reject    []vector `json:"reject"`
	}
	if err := json.Unmarshal(fixtures.CommitmentVectors(), &file); err != nil {
		t.Fatal(err)
	}
	if file.Domain != Domain || file.NonceSize != NonceSize {
		t.Fatalf("the vectors are for domain %q / nonce %d, this package uses %q / %d",
			file.Domain, file.NonceSize, Domain, NonceSize)
	}
	if len(file.Vectors) < 10 || len(file.Reject) < 6 {
		t.Fatalf("%d vectors / %d reject cases; the file has been truncated",
			len(file.Vectors), len(file.Reject))
	}
	for _, v := range file.Vectors {
		t.Run(v.Description, func(t *testing.T) {
			nonce, content := decodeVector(t, v)
			got, err := compute(nonce, content)
			if err != nil {
				t.Fatal(err)
			}
			if got != v.Commitment {
				t.Errorf("commitment = %s\n want %s", got, v.Commitment)
			}
			if !Verify(v.Commitment, nonce, content) {
				t.Error("Verify rejected a vector")
			}
		})
	}
	for _, v := range file.Reject {
		t.Run("reject: "+v.Description, func(t *testing.T) {
			nonce, content := decodeVector(t, v)
			if Verify(v.Commitment, nonce, content) {
				t.Error("Verify accepted a case every implementation must reject")
			}
		})
	}
}

// TestSalted_FreshNonceEveryTime: identical content must not produce identical
// commitments, or the chain reveals which entries share content.
func TestSalted_FreshNonceEveryTime(t *testing.T) {
	content := []byte("consent: yes")
	c1, n1, err := Salted(content)
	if err != nil {
		t.Fatal(err)
	}
	c2, n2, err := Salted(content)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 || bytes.Equal(n1, n2) {
		t.Fatal("two commitments to the same content are identical; the nonce is not fresh")
	}
	if len(n1) != NonceSize {
		t.Fatalf("nonce is %d bytes, want %d", len(n1), NonceSize)
	}
	if !Verify(c1, n1, content) || !Verify(c2, n2, content) {
		t.Fatal("a fresh commitment does not verify against its own nonce and content")
	}
}

// TestCompute_RefusesWrongNonceSize: the fixed size is what makes
// domain ‖ nonce ‖ content unambiguous. A wrong size is refused, never hashed.
func TestCompute_RefusesWrongNonceSize(t *testing.T) {
	for _, n := range []int{0, 1, NonceSize - 1, NonceSize + 1, 64} {
		nonce := make([]byte, n)
		if _, err := compute(nonce, []byte("x")); !errors.Is(err, ErrNonceSize) {
			t.Errorf("nonce of %d bytes: got %v, want ErrNonceSize", n, err)
		}
		if Verify(strings.Repeat("0", 128), nonce, []byte("x")) {
			t.Errorf("Verify accepted a %d-byte nonce", n)
		}
		// An empty commitment is the case that matters: if the size error were
		// ignored, the recomputed value would be "" and would match it.
		if Verify("", nonce, []byte("x")) {
			t.Errorf("Verify accepted an empty commitment with a %d-byte nonce", n)
		}
	}
}

// TestVerify_Rejects covers every way a disclosure can fail to match.
func TestVerify_Rejects(t *testing.T) {
	content := []byte("consent: yes")
	c, nonce, err := Salted(content)
	if err != nil {
		t.Fatal(err)
	}
	otherNonce := bytes.Clone(nonce)
	otherNonce[0] ^= 1

	tests := []struct {
		name       string
		commitment string
		nonce      []byte
		content    []byte
	}{
		{"other content", c, nonce, []byte("consent: no")},
		{"other nonce", c, otherNonce, content},
		{"uppercase commitment", strings.ToUpper(c), nonce, content},
		{"truncated commitment", c[:127], nonce, content},
		{"empty commitment", "", nonce, content},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.commitment, tc.nonce, tc.content) {
				t.Error("Verify accepted a disclosure that does not match")
			}
		})
	}
}

// TestCompute_IsNotAPlainOrExtendableHash pins the construction: a commitment
// must differ from a plain hash of the content, from the undomained form, and
// from SHA-512(domain ‖ nonce ‖ content) — the length-extendable form this
// package deliberately does not use.
func TestCompute_IsNotAPlainOrExtendableHash(t *testing.T) {
	nonce := make([]byte, NonceSize)
	content := []byte("consent: yes")
	c, err := compute(nonce, content)
	if err != nil {
		t.Fatal(err)
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	plain := sha512.Sum512(content)
	undomained := sha512.Sum512(cat(nonce, content))
	extendable := sha512.Sum512(cat([]byte(Domain), nonce, content))
	for name, other := range map[string][64]byte{
		"SHA-512(content)":                  plain,
		"SHA-512(nonce ‖ content)":          undomained,
		"SHA-512(domain ‖ nonce ‖ content)": extendable,
	} {
		if c == hex.EncodeToString(other[:]) {
			t.Errorf("commitment equals %s", name)
		}
	}
}
