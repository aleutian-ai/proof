// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha512HexOf(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestManifestRoot_GoldenVector pins the v2 recipe to the SDK's cross-language
// golden vector — independently computed by a Python implementation of the same
// TLV recipe. A change here is a breaking wire-format change requiring a domain
// bump, not a bug fix.
func TestManifestRoot_GoldenVector(t *testing.T) {
	// Deliberately UNSORTED: ManifestRoot must sort by path.
	files := []FileEntry{
		{Path: "chain_extracts/consent.jsonl", SHA512: sha512HexOf("consent"), Kind: "chain_extract", Bytes: 7},
		{Path: "anchors/anchors.jsonl", SHA512: sha512HexOf("anchor"), Kind: "anchor", Bytes: 6},
		{Path: "README.txt", SHA512: sha512HexOf("readme"), Kind: "readme", Bytes: 6},
		{Path: "trust_manifest/manifest.json", SHA512: sha512HexOf("trust"), Kind: "trust_manifest", Bytes: 5},
	}
	const want = "238e7ae596d9ef2a45d05ddc687032f8d96e74a91c32dc925c9251c3ffa0ba00c3a494f0397d41666dfc1ffe2cf451fa33cdb7a852f17638cd3a20f5f7515932"

	got, err := ManifestRoot(files)
	if err != nil {
		t.Fatalf("ManifestRoot: %v", err)
	}
	if got != want {
		t.Fatalf("manifest_root drifted from the cross-language vector\n got:  %s\n want: %s", got, want)
	}
}

// TestManifestRoot_InformationalFieldsAreNotBound pins the v2 decision: Kind,
// Bytes and RowCount are display metadata a verifier cannot reproduce from file
// bytes, so they are deliberately outside the signed root.
func TestManifestRoot_InformationalFieldsAreNotBound(t *testing.T) {
	base := []FileEntry{{Path: "a.txt", SHA512: sha512HexOf("a")}}
	want, err := ManifestRoot(base)
	if err != nil {
		t.Fatal(err)
	}

	rc := int64(99)
	mutated := []FileEntry{{
		Path: "a.txt", SHA512: sha512HexOf("a"),
		Kind: "DIFFERENT", Bytes: 123456, RowCount: &rc,
	}}
	got, err := ManifestRoot(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Error("Kind/Bytes/RowCount must not affect manifest_root (v2)")
	}
}

// TestManifestRoot_IsOrderIndependent pins that input order cannot change the root.
func TestManifestRoot_IsOrderIndependent(t *testing.T) {
	a := []FileEntry{
		{Path: "z.txt", SHA512: sha512HexOf("z")},
		{Path: "a.txt", SHA512: sha512HexOf("a")},
		{Path: "m.txt", SHA512: sha512HexOf("m")},
	}
	b := []FileEntry{a[1], a[2], a[0]}

	ra, err := ManifestRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := ManifestRoot(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra != rb {
		t.Error("manifest_root depends on input order; the producer and verifier will disagree")
	}
}

// TestManifestRoot_DoesNotMutateInput pins that sorting works on a copy.
func TestManifestRoot_DoesNotMutateInput(t *testing.T) {
	files := []FileEntry{
		{Path: "z.txt", SHA512: sha512HexOf("z")},
		{Path: "a.txt", SHA512: sha512HexOf("a")},
	}
	if _, err := ManifestRoot(files); err != nil {
		t.Fatal(err)
	}
	if files[0].Path != "z.txt" {
		t.Error("ManifestRoot reordered the caller's slice")
	}
}

// TestManifestRoot_DuplicatePathRejected is the ambiguity guard.
//
// Two entries for one path mean the inventory does not say what the bundle
// contains. An ambiguous inventory must not hash to a well-defined root — that
// would let a file be swapped while the root still resolved.
func TestManifestRoot_DuplicatePathRejected(t *testing.T) {
	files := []FileEntry{
		{Path: "a.txt", SHA512: sha512HexOf("one")},
		{Path: "a.txt", SHA512: sha512HexOf("two")},
	}
	_, err := ManifestRoot(files)
	if !errors.Is(err, ErrManifestRoot) {
		t.Fatalf("duplicate path must be rejected, got %v", err)
	}
}

// TestManifestRoot_RejectsMalformedDigests covers the strictness that prevents a
// root from validating while a downstream lowercase re-hash comparison fails.
func TestManifestRoot_RejectsMalformedDigests(t *testing.T) {
	valid := sha512HexOf("x")
	tests := map[string]string{
		"uppercase":  strings.ToUpper(valid),
		"too short":  valid[:127],
		"too long":   valid + "a",
		"empty":      "",
		"non-hex":    strings.Repeat("g", 128),
		"mixed case": valid[:127] + "A",
	}
	for name, digest := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ManifestRoot([]FileEntry{{Path: "a.txt", SHA512: digest}})
			if !errors.Is(err, ErrManifestRoot) {
				t.Fatalf("malformed digest accepted: %v", err)
			}
		})
	}
}

// TestManifestRoot_ErrorDoesNotEchoTheDigest keeps errors from confirming
// attacker-supplied content.
func TestManifestRoot_ErrorDoesNotEchoTheDigest(t *testing.T) {
	canary := strings.Repeat("C4N4RY", 21) + "AB"
	_, err := ManifestRoot([]FileEntry{{Path: "a.txt", SHA512: canary}})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "C4N4RY") {
		t.Errorf("error echoed the offending digest: %v", err)
	}
}

// =============================================================================
// VerifyDir
// =============================================================================

// writeBundle creates a bundle directory and returns its path plus the manifest.
func writeBundle(t *testing.T, contents map[string]string) (string, []FileEntry) {
	t.Helper()
	dir := t.TempDir()

	files := make([]FileEntry, 0, len(contents))
	for path, body := range contents {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntry{Path: path, SHA512: sha512HexOf(body)})
	}
	return dir, files
}

// TestVerifyDir_IntactBundle is the happy path.
func TestVerifyDir_IntactBundle(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{
		"README.txt":            "readme",
		"chain/entries.jsonl":   `{"entry":1}`,
		"anchors/anchors.jsonl": `{"anchor":1}`,
	})
	root, err := ManifestRoot(files)
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDir(dir, files, root, 0)
	if err != nil {
		t.Fatalf("VerifyDir: %v", err)
	}
	if !res.Intact {
		t.Fatalf("intact bundle reported problems: %+v", res.Problems)
	}
	if res.FilesChecked != 3 {
		t.Errorf("FilesChecked = %d, want 3", res.FilesChecked)
	}
}

// TestVerifyDir_DetectsASwappedFile is the case the whole package exists for:
// the manifest root still resolves, because the manifest was not touched — only
// the bytes on disk were.
func TestVerifyDir_DetectsASwappedFile(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{
		"README.txt":          "readme",
		"chain/entries.jsonl": `{"entry":1}`,
	})
	root, err := ManifestRoot(files)
	if err != nil {
		t.Fatal(err)
	}

	// Swap the content, leaving the manifest untouched.
	if err := os.WriteFile(filepath.Join(dir, "chain", "entries.jsonl"),
		[]byte(`{"entry":"TAMPERED"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDir(dir, files, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("a swapped file went undetected")
	}
	if len(res.Problems) != 1 || res.Problems[0].Kind != ProblemContentMismatch {
		t.Fatalf("want one content_mismatch, got %+v", res.Problems)
	}
	if res.Problems[0].Path != "chain/entries.jsonl" {
		t.Errorf("wrong path reported: %s", res.Problems[0].Path)
	}
}

// TestVerifyDir_DetectsMissingAndUnlistedFiles covers both directions of
// inventory disagreement.
func TestVerifyDir_DetectsMissingAndUnlistedFiles(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{"README.txt": "readme"})

	// Delete a listed file and add an unlisted one.
	if err := os.Remove(filepath.Join(dir, "README.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "surprise.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDir(dir, files, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[ProblemKind]bool{}
	for _, p := range res.Problems {
		kinds[p.Kind] = true
	}
	if !kinds[ProblemMissingFile] {
		t.Error("a missing listed file was not reported")
	}
	if !kinds[ProblemUnlistedFile] {
		t.Error("an unlisted file was not reported")
	}
}

// TestVerifyDir_ReportsEveryProblemNotJustTheFirst pins that verification does
// not stop early. A caller repairing a bundle needs the full list.
func TestVerifyDir_ReportsEveryProblemNotJustTheFirst(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{
		"a.txt": "a", "b.txt": "b", "c.txt": "c",
	})
	for _, p := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("TAMPERED"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := VerifyDir(dir, files, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Assert the KINDS, not just the count. Counting alone passed a mutation
	// that broke out of the loop early: the un-inspected files then showed up as
	// "unlisted" problems instead, and 1 mismatch + 2 unlisted still totalled 3.
	// The right number for the wrong reason.
	if len(res.Problems) != 3 {
		t.Fatalf("want 3 problems, got %d: %+v", len(res.Problems), res.Problems)
	}
	for _, p := range res.Problems {
		if p.Kind != ProblemContentMismatch {
			t.Fatalf("every problem must be a content mismatch; got %s on %q — "+
				"verification stopped early and the rest were never hashed",
				p.Kind, p.Path)
		}
	}
	if res.FilesChecked != 3 {
		t.Errorf("FilesChecked = %d, want 3 — not every listed file was hashed", res.FilesChecked)
	}
}

// TestVerifyDir_RejectsPathTraversal is the untrusted-manifest guard.
//
// An attacker who controls the manifest must not be able to point the verifier
// at a file outside the bundle and learn, from whether the digest matched,
// something about that file.
func TestVerifyDir_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()

	outside := filepath.Join(dir, "outside.secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, evil := range []string{
		"../outside.secret",
		"../../etc/passwd",
		"nested/../../outside.secret",
	} {
		t.Run(evil, func(t *testing.T) {
			res, err := VerifyDir(inner, []FileEntry{
				{Path: evil, SHA512: sha512HexOf("secret")},
			}, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if res.Intact {
				t.Fatal("a traversal path verified successfully")
			}
			if res.Problems[0].Kind != ProblemUnsafePath {
				t.Fatalf("want unsafe_path, got %s: %s", res.Problems[0].Kind, res.Problems[0].Detail)
			}
		})
	}
}

// TestVerifyDir_RefusesAbsoluteAndNulPaths covers the other path rejections.
func TestVerifyDir_RefusesAbsoluteAndNulPaths(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"/etc/passwd", "a\x00b", ""} {
		res, err := VerifyDir(dir, []FileEntry{{Path: bad, SHA512: sha512HexOf("x")}}, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if res.Intact {
			t.Fatalf("path %q was accepted", bad)
		}
	}
}

// TestVerifyDir_RefusesSymlinks pins that a symlinked entry is refused rather
// than followed — otherwise an in-bundle path could point anywhere.
func TestVerifyDir_RefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// List BOTH files, so the unlisted-file check cannot mask the result. Without
	// this the test passed even when symlinks were followed, because the symlink
	// target was itself unlisted and failed the bundle for an unrelated reason.
	res, err := VerifyDir(dir, []FileEntry{
		{Path: "link.txt", SHA512: sha512HexOf("content")},
		{Path: "real.txt", SHA512: sha512HexOf("content")},
	}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("a symlink was followed and verified")
	}
	var sawLinkProblem bool
	for _, p := range res.Problems {
		if p.Path == "link.txt" && p.Kind == ProblemUnreadable {
			sawLinkProblem = true
		}
	}
	if !sawLinkProblem {
		t.Fatalf("the symlink itself must be refused as unreadable, got %+v", res.Problems)
	}
}

// TestVerifyDir_EnforcesTheSizeCap pins the denial-of-service guard.
func TestVerifyDir_EnforcesTheSizeCap(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{"big.txt": strings.Repeat("x", 4096)})

	res, err := VerifyDir(dir, files, "", 1024) // cap below the file size
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("a file exceeding the cap was hashed anyway")
	}
	if res.Problems[0].Kind != ProblemUnreadable {
		t.Fatalf("want unreadable, got %s", res.Problems[0].Kind)
	}
}

// TestVerifyDir_DetectsRootMismatch covers a manifest whose own root is wrong.
func TestVerifyDir_DetectsRootMismatch(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{"a.txt": "a"})

	res, err := VerifyDir(dir, files, strings.Repeat("f", 128), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("a wrong manifest_root was accepted")
	}
	if res.Problems[0].Kind != ProblemRootMismatch {
		t.Fatalf("want root_mismatch, got %s", res.Problems[0].Kind)
	}
}

// TestVerifyDir_StatesWhatIsNotProven is the honesty check.
//
// A bundle that verifies is internally consistent, which is NOT the same as
// trustworthy: whoever built it could have made the files and the manifest agree.
func TestVerifyDir_StatesWhatIsNotProven(t *testing.T) {
	dir, files := writeBundle(t, map[string]string{"a.txt": "a"})
	root, _ := ManifestRoot(files)

	res, err := VerifyDir(dir, files, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.NotProven, "signature") {
		t.Errorf("the result must say no signature was checked: %q", res.NotProven)
	}
}
