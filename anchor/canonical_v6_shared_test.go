// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

// TestCanonicalize_V6SharedVectors holds Go's canonical bytes to the shared
// vectors, computed in Python from the spec. The HTML-escaping and U+2028 cases
// are the ones another language gets wrong without being told.
func TestCanonicalize_V6SharedVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name            string `json:"name"`
			Anchor          Anchor `json:"anchor"`
			CanonicalBytes  string `json:"canonical_bytes"`
			CanonicalSHA512 string `json:"canonical_sha512"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixtures.AnchorV6Vectors(), &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 5 {
		t.Fatalf("%d vectors: the file was truncated", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Anchor.Version != SubjectVersion {
				t.Fatalf("vector is v%d, want v%d", v.Anchor.Version, SubjectVersion)
			}
			got, err := Canonicalize(v.Anchor)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != v.CanonicalBytes {
				t.Errorf("canonical bytes differ:\n got  %s\n want %s", got, v.CanonicalBytes)
			}
			sum := sha512.Sum512(got)
			if hex.EncodeToString(sum[:]) != v.CanonicalSHA512 {
				t.Error("canonical_sha512 does not match the bytes")
			}
		})
	}
}
