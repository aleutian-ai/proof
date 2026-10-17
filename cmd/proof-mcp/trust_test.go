// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/verify"
)

// =============================================================================
// Key trust is set at launch, never by a tool call
// =============================================================================

// launchKeys parses --trusted-key values as the server would at launch.
func launchKeys(t *testing.T, values ...string) []trustedKey {
	t.Helper()
	var f trustedKeyFlag
	for _, v := range values {
		if err := f.Set(v); err != nil {
			t.Fatalf("--trusted-key %s: %v", v, err)
		}
	}
	return f.keys
}

// newPublicKeyFile writes a fresh ML-DSA-65 public key, unrelated to any
// fixture, and returns its path.
func newPublicKeyFile(t *testing.T) string {
	t.Helper()
	pub, _, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other-public.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestVerifyAnchor_ToolSuppliedKeyIsOnlyEverProvided: with no key bound at
// launch, nothing a tool call sends yields platform or self.
//
// key_trust was once a tool argument echoed into the result, so the same key
// and anchor returned "a third party attests to this chain" on the caller's
// word alone. The argument is gone: the SDK REJECTS a call that sends it.
func TestVerifyAnchor_ToolSuppliedKeyIsOnlyEverProvided(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 4, 0)
	cs := connect(t)
	base := map[string]any{"entries_path": entries, "anchor_path": anchorPath, "public_key_path": keyPath}

	var out verifyAnchorOut
	call(t, cs, "verify_anchor", base, &out)
	if !out.Bound || !out.SignatureVerified {
		t.Fatalf("expected a bound, verified result: %+v", out)
	}
	if out.Trust != string(anchor.TrustProvided) || out.TrustEstablishes != anchor.TrustProvided.Establishes() {
		t.Errorf("trust = %q (%q), want provided", out.Trust, out.TrustEstablishes)
	}

	for _, level := range []string{"platform", "self", "provided"} {
		args := map[string]any{"key_trust": level}
		for k, v := range base {
			args[k] = v
		}
		got := callErr(t, cs, "verify_anchor", args)
		if !strings.Contains(got, "key_trust") {
			t.Errorf("key_trust=%s was not rejected as an unknown argument: %q", level, got)
		}
	}
}

// TestVerifyAnchor_LaunchBoundKeySetsTheLevel: a key the human bound with
// --trusted-key is reported at that level, whether the call names the same key
// or names none.
func TestVerifyAnchor_LaunchBoundKeySetsTheLevel(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 4, 0)

	for _, level := range []anchor.Trust{anchor.TrustPlatform, anchor.TrustSelf} {
		cs := connectWith(t, serverConfig{trusted: launchKeys(t, string(level)+"="+keyPath)})
		calls := map[string]map[string]any{
			"the call names the same key": {"entries_path": entries, "anchor_path": anchorPath, "public_key_path": keyPath},
			"the call names no key":       {"entries_path": entries, "anchor_path": anchorPath},
		}
		for name, args := range calls {
			t.Run(string(level)+"/"+name, func(t *testing.T) {
				var out verifyAnchorOut
				call(t, cs, "verify_anchor", args, &out)
				if !out.Bound || !out.SignatureVerified {
					t.Fatalf("expected a bound, verified result: %+v", out)
				}
				if out.Trust != string(level) || out.TrustEstablishes != level.Establishes() {
					t.Errorf("trust = %q (%q), want %s", out.Trust, out.TrustEstablishes, level)
				}
			})
		}
	}
}

// TestVerifyAnchor_AnotherLaunchKeyDoesNotRaiseTheLevel: binding one key at
// launch says nothing about a different key.
func TestVerifyAnchor_AnotherLaunchKeyDoesNotRaiseTheLevel(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 4, 0)
	cs := connectWith(t, serverConfig{trusted: launchKeys(t, "platform="+newPublicKeyFile(t))})

	t.Run("the call names the signing key", func(t *testing.T) {
		var out verifyAnchorOut
		call(t, cs, "verify_anchor", map[string]any{
			"entries_path": entries, "anchor_path": anchorPath, "public_key_path": keyPath,
		}, &out)
		if !out.SignatureVerified || out.Trust != string(anchor.TrustProvided) {
			t.Errorf("signature_verified = %v, trust = %q; want a verified signature at provided",
				out.SignatureVerified, out.Trust)
		}
	})

	t.Run("the call names no key", func(t *testing.T) {
		var out verifyAnchorOut
		call(t, cs, "verify_anchor", map[string]any{"entries_path": entries, "anchor_path": anchorPath}, &out)
		if out.SignatureVerified || out.Trust != "" {
			t.Fatalf("a key that did not sign this anchor verified it: %+v", out)
		}
		if !out.Bound {
			t.Errorf("the keyless bind should still hold: %+v", out)
		}
		if !strings.Contains(out.NotProven, "--trusted-key") {
			t.Errorf("the result does not say the launch keys were tried: %q", out.NotProven)
		}
	})
}

// TestVerifyAnchor_ReportsWhatAnErasedEntryLeavesUnbound: tombstones and
// entries_not_bound reach the tool result, with the library's wording.
func TestVerifyAnchor_ReportsWhatAnErasedEntryLeavesUnbound(t *testing.T) {
	entriesPath, anchorPath, _ := anchoredFixture(t, 5, 0)

	// Erase entry 1 the way the store does: the content hash is replaced and the
	// chain hash is kept as stored.
	raw, err := os.ReadFile(entriesPath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []verify.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	tomb, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatal(err)
	}
	entries[1].EntryType = chainformat.TombstoneEntryType
	entries[1].EntryID = chainformat.TombstoneEntryIDPrefix + "550e8400-e29b-41d4-a716-446655440000"
	entries[1].ContentHash = tomb
	writeJSON(t, entriesPath, entries)

	var out verifyAnchorOut
	call(t, connect(t), "verify_anchor", map[string]any{"entries_path": entriesPath, "anchor_path": anchorPath}, &out)
	if !out.Bound {
		t.Fatalf("an erased entry must not unbind the anchor: %+v", out)
	}
	if out.Tombstones != 1 || out.EntriesNotBound != 2 {
		t.Errorf("tombstones = %d, entries_not_bound = %d; want 1 and 2", out.Tombstones, out.EntriesNotBound)
	}

	want, err := verify.BindAnchor(mustLoadAnchor(t, anchorPath), entries, verify.Expect{PreviousAnchorHash: anchor.SeedAnchorHash})
	if err != nil {
		t.Fatal(err)
	}
	if out.Proven != want.Proven || out.NotProven != want.NotProven {
		t.Errorf("the tool reworded the library's claim:\nproven     %q\nnot_proven %q", out.Proven, out.NotProven)
	}
}

func mustLoadAnchor(t *testing.T, path string) anchor.Anchor {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestExplainTrustModel_SaysTheLevelIsNotAnArgument keeps the explanation in
// step with the tool.
func TestExplainTrustModel_SaysTheLevelIsNotAnArgument(t *testing.T) {
	var out explainTrustModelOut
	call(t, connect(t), "explain_trust_model", map[string]any{}, &out)
	if !strings.Contains(out.WhyNoTrustStore, "--trusted-key") {
		t.Errorf("the explanation does not say where a trust level comes from: %q", out.WhyNoTrustStore)
	}
	if strings.Contains(out.WhyNoTrustStore, "you say where they came from") {
		t.Errorf("the explanation still describes the level as the caller's to state: %q", out.WhyNoTrustStore)
	}
}

// TestParseFlags_TrustedKey covers --trusted-key LEVEL=PATH.
func TestParseFlags_TrustedKey(t *testing.T) {
	dir := t.TempDir()
	key, other := newPublicKeyFile(t), newPublicKeyFile(t)

	notAKey := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notAKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongAlg := filepath.Join(dir, "ml-dsa-44-public.pem")
	pem44, err := keyfile.MarshalPublicKey(keyfile.MLDSA44, make([]byte, 1312))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongAlg, pem44, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantKeys int
	}{
		{name: "none", args: nil},
		{name: "platform", args: []string{"--trusted-key", "platform=" + key}, wantKeys: 1},
		{name: "two keys, two levels", args: []string{"--trusted-key", "platform=" + key, "--trusted-key", "self=" + other}, wantKeys: 2},
		{name: "the same key twice at one level", args: []string{"--trusted-key", "self=" + key, "--trusted-key", "self=" + key}, wantKeys: 1},
		{name: "provided is not a launch level", args: []string{"--trusted-key", "provided=" + key}, wantErr: "level must be platform or self"},
		{name: "unknown level", args: []string{"--trusted-key", "root=" + key}, wantErr: `level must be platform or self, got "root"`},
		{name: "uppercase level", args: []string{"--trusted-key", "Platform=" + key}, wantErr: "level must be platform or self"},
		{name: "no level", args: []string{"--trusted-key", key}, wantErr: "want LEVEL=PATH"},
		{name: "no path", args: []string{"--trusted-key", "platform="}, wantErr: "want LEVEL=PATH"},
		{name: "missing file", args: []string{"--trusted-key", "platform=" + filepath.Join(dir, "absent.pem")}, wantErr: "no such file"},
		{name: "a directory", args: []string{"--trusted-key", "platform=" + dir}, wantErr: "directory"},
		{name: "not a key", args: []string{"--trusted-key", "platform=" + notAKey}, wantErr: "not a PEM-encoded public key"},
		{name: "wrong algorithm", args: []string{"--trusted-key", "platform=" + wrongAlg}, wantErr: "ML-DSA-65"},
		{name: "one key at two levels", args: []string{"--trusted-key", "platform=" + key, "--trusted-key", "self=" + key}, wantErr: "both platform and self"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseFlags(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.trusted) != tc.wantKeys {
				t.Errorf("%d keys bound, want %d", len(cfg.trusted), tc.wantKeys)
			}
		})
	}
}
