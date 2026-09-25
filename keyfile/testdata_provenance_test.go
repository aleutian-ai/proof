// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the guard behind testdata/README.md's provenance claim.
//
// testdata/ contains 30 files carrying private key material, committed to a
// PUBLIC repository. That is safe only because every one of
// them is a value already published in an RFC or a specification draft — which
// is a claim a README can make and cannot enforce.
//
// A prose claim decays. Someone debugging a key-handling bug drops a real key in
// here to reproduce it, the file looks exactly like its 40 neighbours, and it
// ships. These tests make that fail loudly instead.
//
// Two layers, because they catch different mistakes:
//
//	seed       an EXISTING file swapped for a real key fails on its seed
//	manifest   a NEW private key file fails until someone lists it on purpose
//
// If you are here because a test failed: do not add your file to the manifest to
// make it pass. Work out first whether it should be in a public repository.

// publishedSeeds are the only private seeds permitted in testdata.
//
// All three are sequential byte runs, which is the point: no key generator
// produces them, so no real key can collide with one.
var publishedSeeds = map[string]string{
	// 32 bytes, 0x00..0x1f. ML-DSA (RFC 9881 App. C) and X-Wing (draft App. D).
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f": "sequential 0x00-0x1f (RFC 9881 App. C; X-Wing draft App. D)",

	// 64 bytes, 0x00..0x3f. ML-KEM's seed is d‖z, two 32-byte halves.
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f": "sequential 0x00-0x3f, d‖z (RFC 9935 App. C)",

	// The same d, but z runs 0x21..0x40 — shifted one byte. That off-by-one IS
	// the defect: RFC 9935 App. C.4.1 ships it so a verifier can prove it
	// REJECTS a key whose halves disagree. It is a published wrong answer, and
	// a test suite without one only ever proves it can accept.
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40": "sequential d, z shifted by one — RFC 9935 App. C.4.1, DELIBERATELY inconsistent",
}

// expandedOnlyFixtures are private key files that carry no seed, so the seed
// check cannot reach them. Each is listed deliberately, with its source.
//
// An expanded ML-DSA or ML-KEM private key is pseudorandom by construction and
// therefore indistinguishable from a real one by inspection. That is exactly why
// these are enumerated by name rather than pattern-matched: adding one has to be
// a decision somebody made, not something that slipped through.
var expandedOnlyFixtures = map[string]string{
	"mldsa44_expanded.pem":                    "RFC 9881 App. C, expanded form of the 0x00-0x1f seed",
	"mldsa65_expanded.pem":                    "RFC 9881 App. C, expanded form of the 0x00-0x1f seed",
	"mldsa87_expanded.pem":                    "RFC 9881 App. C, expanded form of the 0x00-0x1f seed",
	"mlkem512_expanded.pem":                   "RFC 9935 App. C, expanded form of the 0x20-0x3f seed",
	"mlkem768_expanded.pem":                   "RFC 9935 App. C, expanded form of the 0x20-0x3f seed",
	"mlkem1024_expanded.pem":                  "RFC 9935 App. C, expanded form of the 0x20-0x3f seed",
	"bad_mldsa44_expanded_2_mutated.pem":      "RFC 9881 App. C, DELIBERATELY inconsistent",
	"bad_mldsa44_expanded_3_mutated.pem":      "RFC 9881 App. C, DELIBERATELY inconsistent",
	"bad_mlkem512_expanded_2_mutated_s.pem":   "RFC 9935 App. C.4.1, DELIBERATELY inconsistent",
	"bad_mlkem512_expanded_3_mutated_hek.pem": "RFC 9935 App. C.4.1, DELIBERATELY inconsistent",
}

// rejectedByDesign are fixtures that ParsePrivateKey REFUSES, on purpose.
//
// Their seed and expanded halves disagree, which is the defect they exist to
// demonstrate — so no seed comes back and the seed check cannot see them. They
// are listed by name for the same reason as expandedOnlyFixtures: a file that
// this package cannot parse is a file whose contents nothing here has inspected,
// which is precisely the shape a real key would arrive in.
var rejectedByDesign = map[string]string{
	"bad_mlkem512_both_4_z_mismatch.pem": "RFC 9935 App. C.4.1, z does not match the seed; ParsePrivateKey must reject it",
}

// TestTestdata_EveryPrivateKeyIsAPublishedVector is the layer that catches an
// existing fixture being replaced with real key material.
func TestTestdata_EveryPrivateKeyIsAPublishedVector(t *testing.T) {
	for _, path := range privateKeyFixtures(t) {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			_, seed, err := ParsePrivateKey(data)
			if err != nil {
				// No seed to check, so it must be a fixture we named on purpose:
				// either expanded-only, or one this package refuses by design.
				if _, ok := expandedOnlyFixtures[name]; ok {
					return
				}
				if _, ok := rejectedByDesign[name]; ok {
					return
				}
				t.Fatalf("carries no seed and is not a listed fixture (parse said: %v). "+
					"If this is a real key, it must not be in a public repository. If it "+
					"is a published vector, add it to expandedOnlyFixtures or "+
					"rejectedByDesign with its source.", err)
			}

			got := hex.EncodeToString(seed)
			if _, ok := publishedSeeds[got]; !ok {
				// Deliberately does NOT print the seed: if this fired on a real key,
				// echoing it into CI logs would be the second mistake.
				t.Fatalf("seed is not one of the published test vectors. A private key "+
					"whose seed nobody published is either a real key or an undocumented "+
					"one, and neither belongs in a public repository. (%d-byte seed, "+
					"not shown.)", len(seed))
			}
		})
	}
}

// TestTestdata_ManifestIsExhaustive is the layer that catches a NEW file.
//
// Every expanded-only entry must exist, and every private key file must be
// reachable by one of the two checks. A fixture that is deleted but left in the
// manifest is also a failure — a stale allowlist entry is how a future real file
// would find a ready-made hole to land in.
func TestTestdata_ManifestIsExhaustive(t *testing.T) {
	present := map[string]bool{}
	for _, p := range privateKeyFixtures(t) {
		present[filepath.Base(p)] = true
	}
	for _, m := range []struct {
		label string
		set   map[string]string
	}{
		{"expandedOnlyFixtures", expandedOnlyFixtures},
		{"rejectedByDesign", rejectedByDesign},
	} {
		for name := range m.set {
			if !present[name] {
				t.Errorf("%s lists %q, which no longer exists; remove it rather than "+
					"leaving a hole a future file could drop into", m.label, name)
			}
		}
	}

	if len(present) == 0 {
		t.Fatal("found no private key fixtures at all; this test would pass vacuously")
	}
	t.Logf("checked %d private key fixtures against %d published seeds, "+
		"%d expanded-only and %d rejected-by-design exceptions",
		len(present), len(publishedSeeds), len(expandedOnlyFixtures), len(rejectedByDesign))
}

// privateKeyFixtures returns every testdata file containing a private key.
func privateKeyFixtures(t *testing.T) []string {
	t.Helper()
	all, err := filepath.Glob("testdata/*.pem")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []string
	for _, p := range all {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if strings.Contains(string(b), "PRIVATE KEY") {
			out = append(out, p)
		}
	}
	return out
}
