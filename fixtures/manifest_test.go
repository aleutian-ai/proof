// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestManifestMatchesTheFilesOnDisk is the anchor of the conformance contract.
//
// Every other implementation trusts these digests to tell it whether its
// vendored copy is the real thing. If the manifest and the files disagree HERE,
// every downstream check is meaningless.
func TestManifestMatchesTheFilesOnDisk(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	for name, want := range m.Vectors {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("the manifest lists %s, which does not exist: %v", name, err)
			}
			if len(raw) != want.Bytes {
				t.Errorf("%s is %d bytes, manifest says %d", name, len(raw), want.Bytes)
			}
			sum := sha256.Sum256(raw)
			if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
				t.Errorf("%s digest changed:\n got  %s\n want %s\n\n"+
					"If you changed this vector deliberately, regenerate the manifest "+
					"AND expect the other implementations to fail until they are synced "+
					"— that failure is the point.", name, got, want.SHA256)
			}
		})
	}
}

// TestEveryVectorFileIsInTheManifest closes the other direction.
//
// A vector present on disk but absent from the manifest is invisible to every
// other implementation: they would never know to vendor it, and its coverage
// would silently be Go-only.
func TestEveryVectorFileIsInTheManifest(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found; this test would pass vacuously")
	}

	for _, f := range files {
		name := filepath.Base(f)
		if _, ok := m.Vectors[name]; !ok {
			t.Errorf("%s exists but is not in MANIFEST.json, so no other "+
				"implementation can know to vendor it", name)
		}
	}
}
