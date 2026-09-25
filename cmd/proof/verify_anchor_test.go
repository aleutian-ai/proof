// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/verify"
)

// verifyFixture holds an exported chain, an anchor over it, and the public key.
type verifyFixture struct {
	anchorFixture
	entriesPath string
	anchorPath  string
	pubPath     string
}

// newVerifyFixture produces the artefacts `proof verify --anchor` consumes,
// using the real verbs rather than hand-built files — so if `proof anchor`
// and `proof verify` ever disagree about a format, these tests fail.
func newVerifyFixture(t *testing.T, n int) verifyFixture {
	t.Helper()
	base := newAnchorFixture(t, n)
	f := verifyFixture{
		anchorFixture: base,
		entriesPath:   filepath.Join(base.dir, "entries.json"),
		anchorPath:    filepath.Join(base.dir, "anchor.json"),
		pubPath:       filepath.Join(base.dir, "signing-public.pem"),
	}

	if code, _, stderr := runAnchor(t, "--db", base.db, "--chain", base.chainID,
		"--subject", "acct-7f3a", "--key", base.key, "--out", f.anchorPath); code != exitOK {
		t.Fatalf("fixture anchor: %s", stderr)
	}

	// The public half, in the SPKI PEM form `proof keygen` writes.
	signer, err := loadSigner(base.key)
	if err != nil {
		t.Fatalf("loadSigner: %v", err)
	}
	defer signer.Close()
	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	pem, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	if err := os.WriteFile(f.pubPath, pem, 0o644); err != nil {
		t.Fatalf("write public: %v", err)
	}

	writeEntriesFile(t, f.entriesPath, readFixtureEntries(t, base))
	return f
}

func writeEntriesFile(t *testing.T, path string, entries []verify.Entry) {
	t.Helper()
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write entries: %v", err)
	}
}

// runVerify executes `proof verify`, capturing output.
func runVerify(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	outF, _ := os.CreateTemp(t.TempDir(), "stdout")
	errF, _ := os.CreateTemp(t.TempDir(), "stderr")
	code = cmdVerify(args, outF, errF)
	outF.Close()
	errF.Close()
	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return code, string(o), string(e)
}

// TestVerifyAnchor_ThreeClaims is the point of this verb: the CLI can make
// three DIFFERENT claims, and must not let a reader mistake the weak one for
// the strong one.
func TestVerifyAnchor_ThreeClaims(t *testing.T) {
	f := newVerifyFixture(t, 4)

	t.Run("linkage only", func(t *testing.T) {
		code, out, _ := runVerify(t, f.entriesPath)
		if code != exitOK {
			t.Fatalf("exit %d", code)
		}
		if strings.Contains(out, "ANCHOR") {
			t.Error("reported an anchor result when none was requested")
		}
	})

	t.Run("with an anchor, keyless", func(t *testing.T) {
		code, out, _ := runVerify(t, f.entriesPath, "--anchor", f.anchorPath)
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if !strings.Contains(out, "ANCHOR BOUND") {
			t.Errorf("the anchor did not bind:\n%s", out)
		}
		// The weaker claim must say so, loudly.
		if !strings.Contains(out, "signature NOT checked") {
			t.Error("a keyless bind did not say the signature was unchecked")
		}
	})

	t.Run("with an anchor and a key", func(t *testing.T) {
		code, out, _ := runVerify(t, f.entriesPath,
			"--anchor", f.anchorPath, "--key", f.pubPath, "--key-trust", "self")
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if !strings.Contains(out, "signature verified") {
			t.Errorf("the signature was not verified:\n%s", out)
		}
		// Never a bare "verified" — the trust level decides what it means.
		if !strings.Contains(out, "establishes:") {
			t.Error("the result does not state what the trust level establishes")
		}
		if !strings.Contains(out, "no third party is involved") {
			t.Error("a self-trust result did not say no third party is involved")
		}
	})
}

// TestVerifyAnchor_CatchesTruncation is the reason anchors exist. Linkage alone
// reports INTACT on a truncated, re-linked chain; the anchor must object.
func TestVerifyAnchor_CatchesTruncation(t *testing.T) {
	f := newVerifyFixture(t, 5)

	entries := readFixtureEntries(t, f.anchorFixture)
	kept := append([]verify.Entry(nil), entries[1:]...)
	prev := ""
	for i := range kept {
		ts, err := time.Parse(time.RFC3339Nano, kept[i].Timestamp)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		kept[i].ChainHash = chainformat.ComputeChainHashV3Unchecked(
			prev, kept[i].GlobalSeq, ts, kept[i].ContentHash)
		prev = kept[i].ChainHash
	}
	truncated := filepath.Join(f.dir, "truncated.json")
	writeEntriesFile(t, truncated, kept)

	// Control: linkage alone must find nothing wrong, or this proves nothing.
	code, out, _ := runVerify(t, truncated)
	if code != exitOK || !strings.Contains(out, "INTACT") {
		t.Fatalf("CONTROL FAILED — linkage should not detect a re-linked truncation "+
			"(exit %d):\n%s", code, out)
	}

	// The anchor catches it, and the exit code says broken.
	code, out, _ = runVerify(t, truncated, "--anchor", f.anchorPath)
	if code != exitBroken {
		t.Errorf("exit %d, want %d — an anchor that does not describe the chain is a "+
			"broken verdict, not a success", code, exitBroken)
	}
	if !strings.Contains(out, "range_start_mismatch") {
		t.Errorf("the truncation was not identified:\n%s", out)
	}
}

// TestVerifyAnchor_FlagsMayFollowTheFilename. Go's flag package stops at the
// first positional, so `proof verify entries.json --anchor a.json` — the
// natural form — would otherwise fail with a confusing message about the number
// of files.
func TestVerifyAnchor_FlagsMayFollowTheFilename(t *testing.T) {
	f := newVerifyFixture(t, 3)

	orders := map[string][]string{
		"flags after the filename":  {f.entriesPath, "--anchor", f.anchorPath},
		"flags before the filename": {"--anchor", f.anchorPath, f.entriesPath},
		"filename in the middle":    {"--anchor", f.anchorPath, f.entriesPath, "--key", f.pubPath},
	}
	for name, args := range orders {
		t.Run(name, func(t *testing.T) {
			code, out, stderr := runVerify(t, args...)
			if code != exitOK {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, stderr)
			}
			if !strings.Contains(out, "ANCHOR BOUND") {
				t.Errorf("the anchor was not checked:\n%s", out)
			}
		})
	}
}

// TestVerifyAnchor_AssumedGenesisIsReported is the `_51` lesson carried into the
// CLI: a missing predecessor must never masquerade as tamper evidence.
func TestVerifyAnchor_AssumedGenesisIsReported(t *testing.T) {
	f := newVerifyFixture(t, 3)

	// A second anchor, chained from the first.
	secondPath := filepath.Join(f.dir, "second.json")
	if code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "acct-7f3a", "--key", f.key,
		"--previous", f.anchorPath, "--out", secondPath); code != exitOK {
		t.Fatalf("second anchor: %s", stderr)
	}

	// Checked WITHOUT --previous: it cannot bind, and the output must explain
	// that the likely cause is the missing input rather than an attacker.
	code, out, _ := runVerify(t, f.entriesPath, "--anchor", secondPath)
	if code != exitBroken {
		t.Fatalf("exit %d, want broken", code)
	}
	for _, want := range []string{"no --previous was given", "rather than tampering"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not explain the assumption (%q):\n%s", want, out)
		}
	}

	// And with --previous it binds.
	code, out, _ = runVerify(t, f.entriesPath, "--anchor", secondPath, "--previous", f.anchorPath)
	if code != exitOK {
		t.Fatalf("a chained anchor did not verify with its predecessor (exit %d):\n%s", code, out)
	}
	if strings.Contains(out, "no --previous was given") {
		t.Error("the genesis-assumption note appeared when a predecessor WAS given")
	}
}

// TestVerifyAnchor_PreviousHashAlternative: a verifier who kept the hash but not
// the anchor file must still be able to check.
func TestVerifyAnchor_PreviousHashAlternative(t *testing.T) {
	f := newVerifyFixture(t, 3)
	secondPath := filepath.Join(f.dir, "second.json")
	if code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "acct-7f3a", "--key", f.key,
		"--previous", f.anchorPath, "--out", secondPath); code != exitOK {
		t.Fatalf("second anchor: %s", stderr)
	}
	first := readAnchorJSON(t, f.anchorPath)

	code, out, _ := runVerify(t, f.entriesPath, "--anchor", secondPath,
		"--previous-hash", first.ChainHash)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "ANCHOR BOUND") {
		t.Errorf("--previous-hash did not bind:\n%s", out)
	}
}

// TestVerifyAnchor_RejectsIncoherentFlags.
func TestVerifyAnchor_RejectsIncoherentFlags(t *testing.T) {
	f := newVerifyFixture(t, 2)
	first := readAnchorJSON(t, f.anchorPath)

	cases := []struct {
		name, want string
		args       []string
	}{
		{
			name: "--key without --anchor",
			want: "nothing for the key to verify",
			args: []string{f.entriesPath, "--key", f.pubPath},
		},
		{
			name: "--previous without --anchor",
			want: "no anchor was supplied",
			args: []string{f.entriesPath, "--previous", f.anchorPath},
		},
		{
			name: "both predecessor forms",
			want: "supply one",
			args: []string{f.entriesPath, "--anchor", f.anchorPath,
				"--previous", f.anchorPath, "--previous-hash", first.ChainHash},
		},
		{
			name: "unknown trust level",
			want: "platform, provided, self",
			args: []string{f.entriesPath, "--anchor", f.anchorPath,
				"--key", f.pubPath, "--key-trust", "totally"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runVerify(t, tc.args...)
			if code != exitUsage {
				t.Errorf("exit %d, want %d (usage)", code, exitUsage)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("error does not explain the problem (want %q): %q", tc.want, stderr)
			}
		})
	}
}

// TestVerifyAnchor_RefusesAWrongAlgorithmPublicKey.
func TestVerifyAnchor_RefusesAWrongAlgorithmPublicKey(t *testing.T) {
	f := newVerifyFixture(t, 2)

	wrong := filepath.Join(f.dir, "xwing-public.pem")
	pem, err := keyfile.MarshalPublicKey(keyfile.XWing, make([]byte, keyfile.XWing.PublicKeySize()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(wrong, pem, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	code, _, stderr := runVerify(t, f.entriesPath, "--anchor", f.anchorPath, "--key", wrong)
	if code == exitOK {
		t.Fatal("accepted a non-ML-DSA-65 public key")
	}
	if !strings.Contains(stderr, "X-Wing") || !strings.Contains(stderr, "ML-DSA-65") {
		t.Errorf("the error names neither what was supplied nor what is needed: %q", stderr)
	}
}

// TestVerifyAnchor_JSONCarriesBothResults, so a script does not have to scrape
// the human output.
func TestVerifyAnchor_JSONCarriesBothResults(t *testing.T) {
	f := newVerifyFixture(t, 3)

	code, out, _ := runVerify(t, f.entriesPath, "--anchor", f.anchorPath,
		"--key", f.pubPath, "--json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}

	var got struct {
		Verdict       string `json:"verdict"`
		AnchorChecked bool   `json:"anchor_checked"`
		Anchor        *struct {
			Anchor struct {
				Outcome           string `json:"outcome"`
				Bound             bool   `json:"bound"`
				SignatureVerified bool   `json:"signature_verified"`
				Trust             string `json:"trust"`
			} `json:"anchor"`
			AssumedGenesis bool `json:"assumed_genesis"`
		} `json:"anchor_check"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	// The verdict is PROMOTED when an anchor bound: that is the difference
	// between "nothing was edited" and "…and this is the same chain".
	if got.Verdict != string(verify.VerdictAnchored) {
		t.Errorf("verdict = %q, want %q once an anchor bound", got.Verdict, verify.VerdictAnchored)
	}
	if !got.AnchorChecked {
		t.Error("anchor_checked is false after an anchor was checked")
	}
	if got.Anchor == nil {
		t.Fatal("the anchor result is missing from the JSON")
	}
	if !got.Anchor.Anchor.Bound || !got.Anchor.Anchor.SignatureVerified {
		t.Errorf("the JSON anchor result is wrong: %+v", got.Anchor)
	}
	if !got.Anchor.AssumedGenesis {
		t.Error("assumed_genesis should be true when no predecessor was supplied")
	}

	// And without --anchor the block must be ABSENT rather than present-and-empty,
	// so a consumer can tell "not checked" from "checked and failed".
	//
	// Matched on the exact JSON key, not a substring: verify.Result already has
	// an "anchor_checked" field, which a Contains("anchor_check") test matches
	// by accident. That is how this assertion first failed — against correct
	// code.
	_, plain, _ := runVerify(t, f.entriesPath, "--json")
	var bare map[string]any
	if err := json.Unmarshal([]byte(plain), &bare); err != nil {
		t.Fatalf("plain output is not valid JSON: %v", err)
	}
	if _, present := bare["anchor_check"]; present {
		t.Error("anchor_check appears when no anchor was requested")
	}
	if checked, _ := bare["anchor_checked"].(bool); checked {
		t.Error("anchor_checked is true when no anchor was requested")
	}
	if bare["verdict"] != string(verify.VerdictIntact) {
		t.Errorf("verdict = %v, want %v without an anchor", bare["verdict"], verify.VerdictIntact)
	}
}
