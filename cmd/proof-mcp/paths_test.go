// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/bundle"
	"github.com/aleutian-ai/proof/verify"
)

// =============================================================================
// The path root
// =============================================================================

// copyFile copies src into dir under name and returns the new path.
func copyFile(t *testing.T, src, dir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestPaths_OutsideTheRootGetOneFixedError: a path outside the root gets the
// same answer whether it names nothing, a directory or a readable file, in
// every argument that takes a path.
//
// Different answers would let a tool call learn what exists anywhere on the
// machine, and of what kind, one error at a time.
func TestPaths_OutsideTheRootGetOneFixedError(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 3, 0)
	cs := connectWith(t, serverConfig{root: testRoot(t, filepath.Dir(entries))})

	outside := t.TempDir()
	targets := []struct {
		name string
		path string
	}{
		{"a missing file", filepath.Join(outside, "absent.json")},
		{"a directory", outside},
		{"a readable entries file", copyFile(t, entries, outside, "entries.json")},
		{"a relative path that climbs out", filepath.Join("..", filepath.Base(outside), "entries.json")},
	}
	arguments := []struct {
		name string
		tool string
		args func(path string) map[string]any
	}{
		{"verify_chain path", "verify_chain", func(p string) map[string]any {
			return map[string]any{"path": p}
		}},
		{"verify_anchor entries_path", "verify_anchor", func(p string) map[string]any {
			return map[string]any{"entries_path": p, "anchor_path": anchorPath}
		}},
		{"verify_anchor anchor_path", "verify_anchor", func(p string) map[string]any {
			return map[string]any{"entries_path": entries, "anchor_path": p}
		}},
		{"verify_anchor public_key_path", "verify_anchor", func(p string) map[string]any {
			return map[string]any{"entries_path": entries, "anchor_path": anchorPath, "public_key_path": p}
		}},
		{"verify_bundle dir", "verify_bundle", func(p string) map[string]any {
			return map[string]any{"dir": p}
		}},
	}

	// The fixture itself must be usable, or every refusal below proves nothing.
	var ok verifyAnchorOut
	call(t, cs, "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath, "public_key_path": keyPath,
	}, &ok)
	if !ok.Bound {
		t.Fatalf("the fixture inside the root does not verify: %+v", ok)
	}

	for _, a := range arguments {
		for _, tg := range targets {
			t.Run(a.name+"/"+tg.name, func(t *testing.T) {
				got := callErr(t, cs, a.tool, a.args(tg.path))
				if got != errOutsideRoot.Error() {
					t.Errorf("got %q\nwant the fixed error %q", got, errOutsideRoot)
				}
			})
		}
	}
}

// TestPaths_SymlinkLeavingTheRootIsRefused: a link inside the root does not
// make a file outside it readable, and the answer does not say whether the
// link's target exists.
func TestPaths_SymlinkLeavingTheRootIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := copyFile(t, writeChain(t, 3, false), outside, "entries.json")

	links := map[string]string{
		"to-file.json":    target,
		"to-nothing.json": filepath.Join(outside, "absent.json"),
		"to-dir":          outside,
	}
	for name, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, name)); err != nil {
			t.Skipf("cannot create a symbolic link here: %v", err)
		}
	}
	cs := connectWith(t, serverConfig{root: testRoot(t, root)})

	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"a link to a file", "verify_chain", map[string]any{"path": filepath.Join(root, "to-file.json")}},
		{"the same link, as a relative path", "verify_chain", map[string]any{"path": "to-file.json"}},
		{"a link to nothing", "verify_chain", map[string]any{"path": filepath.Join(root, "to-nothing.json")}},
		{"a file under a linked directory", "verify_chain", map[string]any{"path": filepath.Join(root, "to-dir", "entries.json")}},
		{"a linked bundle directory", "verify_bundle", map[string]any{"dir": filepath.Join(root, "to-dir")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := callErr(t, cs, tc.tool, tc.args); got != errOutsideRoot.Error() {
				t.Errorf("got %q\nwant the fixed error %q", got, errOutsideRoot)
			}
		})
	}
}

// TestPaths_InsideTheRoot covers what must keep working: a relative path, a
// name that merely contains "..", and a link that stays inside the root.
func TestPaths_InsideTheRoot(t *testing.T) {
	root := t.TempDir()
	chain := writeChain(t, 3, false)
	copyFile(t, chain, root, "a..b.json")
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, chain, filepath.Join(root, "sub"), "entries.json")
	linked := os.Symlink(filepath.Join("sub", "entries.json"), filepath.Join(root, "link.json")) == nil

	cs := connectWith(t, serverConfig{root: testRoot(t, root)})
	paths := []string{
		filepath.Join(root, "a..b.json"), // once refused for containing ".."
		"a..b.json",
		filepath.Join("sub", "entries.json"),
		filepath.Join("sub", "..", "a..b.json"),
	}
	if linked {
		paths = append(paths, "link.json", filepath.Join(root, "link.json"))
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			var out verifyChainOut
			res := call(t, cs, "verify_chain", map[string]any{"path": p}, &out)
			if res.IsError || out.Verdict != string(verify.VerdictIntact) {
				t.Fatalf("a file inside the root was not verified: %q %+v", callErr(t, cs, "verify_chain", map[string]any{"path": p}), out)
			}
		})
	}
}

// TestVerifyAnchor_NonJSONAnchorLeaksNoByte: pointing anchor_path at a file
// that is not JSON once returned "invalid character 'r' looking for beginning
// of value" — the file's first byte, from the decoder's error.
func TestVerifyAnchor_NonJSONAnchorLeaksNoByte(t *testing.T) {
	entries, _, _ := anchoredFixture(t, 3, 0)
	dir := filepath.Dir(entries)
	contents := map[string]string{
		"passwd":      "root:x:0:0:root:/root:/bin/sh\n",
		"number.json": `{"version": "SECRETVALUE"}`, // valid JSON, wrong type: the decoder quotes it
	}
	cs := connect(t)
	for name, body := range contents {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := callErr(t, cs, "verify_anchor", map[string]any{"entries_path": entries, "anchor_path": path})
			if want := path + " is not valid JSON for an anchor"; got != want {
				t.Errorf("got %q\nwant exactly %q: anything else may carry file contents", got, want)
			}
		})
	}
}

// TestVerifyAnchor_UnparsableKeyLeaksNothing: the key parser's error names the
// file's PEM label, so it is not passed on either.
func TestVerifyAnchor_UnparsableKeyLeaksNothing(t *testing.T) {
	entries, anchorPath, _ := anchoredFixture(t, 3, 0)
	path := filepath.Join(filepath.Dir(entries), "other.pem")
	body := "-----BEGIN CANARYLABEL-----\nQ0FOQVJZ\n-----END CANARYLABEL-----\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := callErr(t, connect(t), "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath, "public_key_path": path,
	})
	if got == "" {
		t.Fatal("a file that is not a public key was accepted")
	}
	if strings.Contains(got, "CANARY") {
		t.Errorf("the error echoes the file's contents: %q", got)
	}
}

// =============================================================================
// verify_bundle
// =============================================================================

// TestVerifyBundle_RefusesTooManyFiles: the manifest's file count is bounded,
// not only its size.
func TestVerifyBundle_RefusesTooManyFiles(t *testing.T) {
	cs := connect(t)
	digest := strings.Repeat("ab", 64)
	for _, n := range []int{maxBundleManifestFiles, maxBundleManifestFiles + 1} {
		dir := t.TempDir()
		files := make([]bundle.FileEntry, n)
		for i := range files {
			files[i] = bundle.FileEntry{Path: fmt.Sprintf("f%05d", i), SHA512: digest}
		}
		writeJSON(t, filepath.Join(dir, "manifest.json"), bundleManifest{Files: files})

		got := callErr(t, cs, "verify_bundle", map[string]any{"dir": dir})
		refused := strings.Contains(got, fmt.Sprintf("at most %d", maxBundleManifestFiles))
		if n > maxBundleManifestFiles && !refused {
			t.Errorf("a manifest listing %d files was not refused: %q", n, got)
		}
		if n <= maxBundleManifestFiles && got != "" {
			t.Errorf("a manifest listing exactly %d files was refused: %q", n, got)
		}
	}
}

// TestVerifyBundle_EmptyManifestIsRefused: verifying nothing proves nothing.
func TestVerifyBundle_EmptyManifestIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "manifest.json"), bundleManifest{})
	if got := callErr(t, connect(t), "verify_bundle", map[string]any{"dir": dir}); !strings.Contains(got, "lists no files") {
		t.Errorf("an empty manifest was not refused as such: %q", got)
	}
}
