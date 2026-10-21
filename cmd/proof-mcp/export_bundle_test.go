// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/exportbundle"
)

// bundleVectors reads the bundle v2 conformance vectors: the same cases the
// CLI and both SDKs are held to.
type bundleVectors struct {
	Keys map[string]struct {
		PublicKeyPEM string `json:"public_key_pem"`
	} `json:"keys"`
	Cases []struct {
		Name      string `json:"name"`
		BundleB64 string `json:"bundle_b64"`
	} `json:"cases"`
}

func loadBundleVectors(t *testing.T) bundleVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "testdata", "bundle_v2_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v bundleVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// vectorBundle writes one case's bundle into dir and returns its path.
func (v bundleVectors) vectorBundle(t *testing.T, dir, name string) string {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name != name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(c.BundleB64)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Fatalf("no vector %q", name)
	return ""
}

func (v bundleVectors) key(t *testing.T, name string) exportbundle.PublicKey {
	t.Helper()
	k, err := exportbundle.ParsePublicKeyPEM([]byte(v.Keys[name].PublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyExportBundle_OKUnderLaunchKeys(t *testing.T) {
	v := loadBundleVectors(t)
	dir := t.TempDir()
	v.vectorBundle(t, dir, "ok_both_trusts")
	cs := connectWith(t, serverConfig{root: testRoot(t, dir), bundleTrust: exportbundle.Trust{
		Checkpoint: []exportbundle.PublicKey{v.key(t, "checkpoint")},
		Record:     []exportbundle.PublicKey{v.key(t, "record")},
	}})

	var out verifyExportBundleOut
	call(t, cs, "verify_export_bundle", map[string]any{"path": "ok_both_trusts.json"}, &out)
	if out.Verdict != "ok" || out.CheckpointTrust != "checked" || out.RecordTrust != "checked" {
		t.Fatalf("got %+v, want ok under both trusts", out)
	}
	if len(out.Chains) != 2 || out.Chains[0].Counts.Opened != 2 || out.Chains[1].Erasure != "anchored" {
		t.Fatalf("chains = %+v", out.Chains)
	}
	if out.NotProven == "" || !strings.Contains(out.NotProven, "every chain") {
		t.Fatalf("not_proven must state bundle-format §1: %q", out.NotProven)
	}
	// Chain ids are pseudonymous personal data: never in a model's context.
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "events.") {
		t.Fatalf("the result names a chain id: %s", raw)
	}
}

// TestVerifyExportBundle_NoLaunchKeyIsNeverOK: a bundle verifies under its own
// author's key, so without a key bound at launch nothing is OK.
func TestVerifyExportBundle_NoLaunchKeyIsNeverOK(t *testing.T) {
	v := loadBundleVectors(t)
	dir := t.TempDir()
	v.vectorBundle(t, dir, "ok_both_trusts")
	cs := connectWith(t, serverConfig{root: testRoot(t, dir)})

	var out verifyExportBundleOut
	call(t, cs, "verify_export_bundle", map[string]any{"path": "ok_both_trusts.json"}, &out)
	if out.Verdict != "unauthenticated" || out.CheckpointTrust != "not_checked" {
		t.Fatalf("got %+v, want unauthenticated", out)
	}
	if !strings.Contains(out.NotProven, "--bundle-checkpoint-key") {
		t.Fatalf("not_proven should say no key was bound: %q", out.NotProven)
	}
}

// TestVerifyExportBundle_KeyIsNotAnArgument: the schema has no key argument,
// and the SDK refuses one.
func TestVerifyExportBundle_KeyIsNotAnArgument(t *testing.T) {
	v := loadBundleVectors(t)
	dir := t.TempDir()
	v.vectorBundle(t, dir, "ok_both_trusts")
	cs := connectWith(t, serverConfig{root: testRoot(t, dir)})
	got := callErr(t, cs, "verify_export_bundle", map[string]any{
		"path": "ok_both_trusts.json", "checkpoint_key_path": "k.pem"})
	if got == "" {
		t.Fatal("a key named in the call was accepted")
	}
}

func TestVerifyExportBundle_ModifiedFails(t *testing.T) {
	v := loadBundleVectors(t)
	dir := t.TempDir()
	v.vectorBundle(t, dir, "modified")
	cs := connectWith(t, serverConfig{root: testRoot(t, dir), bundleTrust: exportbundle.Trust{
		Checkpoint: []exportbundle.PublicKey{v.key(t, "checkpoint")},
		Record:     []exportbundle.PublicKey{v.key(t, "record")},
	}})

	var out verifyExportBundleOut
	call(t, cs, "verify_export_bundle", map[string]any{"path": "modified.json"}, &out)
	if out.Verdict != "failed" {
		t.Fatalf("verdict %q, want failed", out.Verdict)
	}
	found := false
	for _, c := range out.Chains {
		for _, p := range c.Problems {
			found = found || p.Code == "modified"
		}
	}
	if !found {
		t.Fatalf("no `modified` problem: %+v", out.Chains)
	}
}

func TestVerifyExportBundle_Unreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out verifyExportBundleOut
	call(t, connectWith(t, serverConfig{root: testRoot(t, dir)}), "verify_export_bundle",
		map[string]any{"path": "b.json"}, &out)
	if out.Verdict != "unreadable" || out.Reason == "" || len(out.Chains) != 0 {
		t.Fatalf("got %+v, want unreadable with a reason", out)
	}
}

func TestVerifyExportBundle_OutsideRoot(t *testing.T) {
	inside, outside := t.TempDir(), t.TempDir()
	v := loadBundleVectors(t)
	path := v.vectorBundle(t, outside, "ok_both_trusts")
	got := callErr(t, connectWith(t, serverConfig{root: testRoot(t, inside)}), "verify_export_bundle",
		map[string]any{"path": path})
	if !strings.Contains(got, errOutsideRoot.Error()) {
		t.Fatalf("got %q, want the outside-the-root answer", got)
	}
}

func TestBundleKeyFlag_ReadsAtParse(t *testing.T) {
	v := loadBundleVectors(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(good, []byte(v.Keys["checkpoint"].PublicKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	var f bundleKeyFlag
	if err := f.Set(good); err != nil || len(f.keys) != 1 {
		t.Fatalf("Set(good) = %v, %d keys", err, len(f.keys))
	}
	if err := f.Set(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("a missing key file was accepted")
	}
}
