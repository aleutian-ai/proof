// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed MANIFEST.json
var manifestJSON []byte

// VectorDigest records one conformance vector's identity.
type VectorDigest struct {
	// SHA256 is the hex digest of the file's exact bytes.
	SHA256 string `json:"sha256"`

	// Bytes is the file length, carried so a truncated copy is obvious before
	// the digest is even computed.
	Bytes int `json:"bytes"`
}

// Manifest is the conformance contract: which vectors exist, and their digests.
type Manifest struct {
	Comment string                  `json:"_comment"`
	Vectors map[string]VectorDigest `json:"vectors"`
}

// LoadManifest returns the embedded conformance manifest.
//
// # Description
//
// The manifest is what makes a vendored copy of these vectors trustworthy in
// another repository. An implementation that cannot import this module — Python,
// JavaScript, or a third party's — vendors the vector files and checks them
// against these digests before running against them.
//
// Without it, three copies of a vector agree only by coincidence, and nothing
// fails when one drifts. A drifted vector is worse than a missing one: it looks
// like agreement.
//
// # Outputs
//
//   - Manifest: the vector set and digests
//   - error: if the embedded manifest cannot be parsed, which would mean this
//     module was built from a corrupt tree
//
// # Example
//
//	m, err := fixtures.LoadManifest()
//	if err != nil {
//	    return err
//	}
//	fmt.Println(len(m.Vectors), "conformance vectors")
//
// # Limitations
//
//   - Records WHAT the vectors are, not what they mean. The expected outputs
//     live inside the vector files themselves.
//
// # Assumptions
//
//   - Vector files are byte-stable. They are data, never regenerated to make a
//     failing implementation pass.
func LoadManifest() (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return Manifest{}, fmt.Errorf("fixtures: parse MANIFEST.json: %w", err)
	}
	if len(m.Vectors) == 0 {
		return Manifest{}, fmt.Errorf("fixtures: MANIFEST.json lists no vectors")
	}
	return m, nil
}
