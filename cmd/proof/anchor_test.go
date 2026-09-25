// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// anchorFixture is a temp dir holding a chain database and a signing key.
type anchorFixture struct {
	dir     string
	db      string
	key     string
	chainID string
}

// newAnchorFixture writes a bolt database containing n linked v3 entries and an
// ML-DSA-65 private key in the form `proof keygen` produces.
func newAnchorFixture(t *testing.T, n int) anchorFixture {
	t.Helper()
	dir := t.TempDir()
	f := anchorFixture{
		dir:     dir,
		db:      filepath.Join(dir, "chain.db"),
		key:     filepath.Join(dir, "signing-private.pem"),
		chainID: "chain-under-test",
	}

	s, err := boltstore.Open(f.db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rows := make([]store.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e := store.Entry{
			ChainID:       f.chainID,
			EntryID:       "ent_" + string(rune('a'+i)),
			EntryType:     "capture.request.v3",
			FormatVersion: chainformat.FormatV3,
			GlobalSeq:     int64(i),
			Timestamp:     ts,
			ContentHash:   strings.Repeat("0123456789abcdef", 8),
			PreviousHash:  prev,
		}
		e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, e.ContentHash)
		prev = e.ChainHash
		rows = append(rows, e)
	}
	if err := s.WriteBatch(context.Background(), rows); err != nil {
		t.Fatalf("write batch: %v", err)
	}

	seed := make([]byte, mldsa.MLDSA65.SeedSize())
	for i := range seed {
		seed[i] = byte(i * 5)
	}
	pem, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(f.key, pem, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return f
}

// runAnchor executes the verb, capturing stdout and stderr.
func runAnchor(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	outF, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	errF, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	code = cmdAnchor(args, outF, errF)
	outF.Close()
	errF.Close()

	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return code, string(o), string(e)
}

// TestAnchorVerb_ProducesAVerifiableAnchor is the end of the local loop: a chain
// in a database becomes a signed anchor a third party can check.
func TestAnchorVerb_ProducesAVerifiableAnchor(t *testing.T) {
	f := newAnchorFixture(t, 5)
	out := filepath.Join(f.dir, "anchor.json")

	code, stdout, stderr := runAnchor(t,
		"--db", f.db, "--chain", f.chainID,
		"--subject", "acct-pseudonym-7f3a",
		"--key", f.key, "--out", out)
	if code != exitOK {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, stderr)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("parse anchor: %v", err)
	}
	if a.Version != anchor.SubjectVersion {
		t.Errorf("version = %d, want v6", a.Version)
	}
	if a.EntryCount != 5 || a.VerifiedThrough != 5 {
		t.Errorf("count=%d verified=%d, want 5/5", a.EntryCount, a.VerifiedThrough)
	}
	if a.Signature == "" {
		t.Fatal("the anchor is unsigned")
	}

	// It must verify against the public half of the key on disk.
	entries := readFixtureEntries(t, f)
	signer, err := loadSigner(f.key)
	if err != nil {
		t.Fatalf("loadSigner: %v", err)
	}
	defer signer.Close()
	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{a.SigningKeyID: pub})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	res, err := verify.VerifyAnchor(a, entries, anchor.SeedAnchorHash, ring)
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !res.Bound || !res.SignatureVerified {
		t.Fatalf("the CLI's anchor did not verify: %+v", res)
	}

	// The human summary goes to stdout when --out is used, and must say what
	// the anchor does NOT establish.
	if !strings.Contains(stdout, "NOT proven") {
		t.Error("the summary omits what the anchor does not prove")
	}
}

// TestAnchorVerb_StdoutIsCleanJSON: without --out the anchor goes to stdout and
// the human report to stderr, so `proof anchor … > a.json` yields a usable file
// rather than one with a report pasted on top.
func TestAnchorVerb_StdoutIsCleanJSON(t *testing.T) {
	f := newAnchorFixture(t, 3)

	code, stdout, stderr := runAnchor(t,
		"--db", f.db, "--chain", f.chainID, "--subject", "s", "--key", f.key)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var a anchor.Anchor
	if err := json.Unmarshal([]byte(stdout), &a); err != nil {
		t.Fatalf("stdout is not clean JSON: %v\n%s", err, stdout)
	}
	if a.AnchorID == "" {
		t.Error("stdout JSON has no anchor id")
	}
	if !strings.Contains(stderr, "anchored 3 entries") {
		t.Errorf("the summary did not go to stderr: %q", stderr)
	}
}

// TestAnchorVerb_ChainsFromAPreviousAnchor, and reports the predecessor hash a
// verifier will need — it is not recoverable from the new anchor alone.
func TestAnchorVerb_ChainsFromAPreviousAnchor(t *testing.T) {
	f := newAnchorFixture(t, 4)
	firstPath := filepath.Join(f.dir, "first.json")

	if code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "s", "--key", f.key, "--out", firstPath); code != exitOK {
		t.Fatalf("first anchor: %s", stderr)
	}

	secondPath := filepath.Join(f.dir, "second.json")
	code, stdout, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "s", "--key", f.key,
		"--previous", firstPath, "--out", secondPath)
	if code != exitOK {
		t.Fatalf("second anchor: exit %d %s", code, stderr)
	}

	first := readAnchorJSON(t, firstPath)
	second := readAnchorJSON(t, secondPath)
	if second.PreviousAnchorID != first.AnchorID {
		t.Errorf("previous = %q, want %q", second.PreviousAnchorID, first.AnchorID)
	}
	if second.ChainHash == first.ChainHash {
		t.Error("the two anchors have the same chain hash; the second does not commit to the first")
	}

	// A verifier needs the predecessor's hash and cannot derive it. The CLI must
	// hand it over, or the operator has a file nobody can check.
	if !strings.Contains(stdout, first.ChainHash) {
		t.Error("the summary does not print the previous anchor's chain hash, which a verifier needs")
	}

	entries := readFixtureEntries(t, f)
	signer, _ := loadSigner(f.key)
	defer signer.Close()
	pub, _ := signer.Public().(*anchor.PublicKey).MarshalBinary()
	ring, _ := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{second.SigningKeyID: pub})

	res, err := verify.VerifyAnchor(second, entries, first.ChainHash, ring)
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !res.Bound || !res.SignatureVerified {
		t.Fatalf("the chained anchor did not verify: %+v", res)
	}
}

// TestAnchorVerb_RefusesABrokenChain, with the exit code a script needs.
func TestAnchorVerb_RefusesABrokenChain(t *testing.T) {
	f := newAnchorFixture(t, 4)

	// Corrupt one entry in place. bolt REPLACES an entry at an occupied
	// GlobalSeq, which is how erasure works, so this is a supported write.
	s, err := boltstore.Open(f.db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	rows, err := s.Range(context.Background(), f.chainID, 0, 1<<62, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	bad := rows[2]
	bad.ContentHash = strings.Repeat("ff", 64)
	if err := s.WriteBatch(context.Background(), []store.Entry{bad}); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.Close()

	code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "s", "--key", f.key)
	if code != exitBroken {
		t.Errorf("exit %d, want %d (the same code `proof verify` uses for a broken chain)",
			code, exitBroken)
	}
	if !strings.Contains(stderr, "entry 2") {
		t.Errorf("the refusal does not locate the break: %q", stderr)
	}
}

// TestAnchorVerb_RefusesAWrongAlgorithmKey, naming what was supplied.
func TestAnchorVerb_RefusesAWrongAlgorithmKey(t *testing.T) {
	f := newAnchorFixture(t, 2)

	wrong := filepath.Join(f.dir, "xwing-private.pem")
	seed := make([]byte, keyfile.XWing.SeedSize())
	pem, err := keyfile.MarshalPrivateKey(keyfile.XWing, seed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(wrong, pem, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "s", "--key", wrong)
	if code == exitOK {
		t.Fatal("signed an anchor with a non-ML-DSA-65 key")
	}
	if !strings.Contains(stderr, "X-Wing") || !strings.Contains(stderr, "ML-DSA-65") {
		t.Errorf("the error names neither what was supplied nor what is needed: %q", stderr)
	}
}

// TestAnchorVerb_RequiresItsArguments, with a subject message that explains the
// stakes rather than just naming the flag.
func TestAnchorVerb_RequiresItsArguments(t *testing.T) {
	f := newAnchorFixture(t, 2)
	full := []string{"--db", f.db, "--chain", f.chainID, "--subject", "s", "--key", f.key}

	drop := func(flag string) []string {
		out := []string{}
		for i := 0; i < len(full); i += 2 {
			if full[i] == flag {
				continue
			}
			out = append(out, full[i], full[i+1])
		}
		return out
	}
	for _, flag := range []string{"--db", "--chain", "--subject", "--key"} {
		t.Run(flag, func(t *testing.T) {
			code, _, stderr := runAnchor(t, drop(flag)...)
			if code != exitUsage {
				t.Errorf("exit %d, want %d (usage)", code, exitUsage)
			}
			if !strings.Contains(stderr, strings.TrimPrefix(flag, "--")) {
				t.Errorf("the error does not name %s: %q", flag, stderr)
			}
		})
	}

	// The subject refusal must explain WHY, because the consequence is permanent.
	_, _, stderr := runAnchor(t, drop("--subject")...)
	for _, want := range []string{"never be erased", "pseudonym"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the subject refusal does not mention %q: %q", want, stderr)
		}
	}
}

// TestAnchorVerb_NeverPrintsThePrivateKey is the _38 rule, applied here.
func TestAnchorVerb_NeverPrintsThePrivateKey(t *testing.T) {
	f := newAnchorFixture(t, 3)
	keyPEM, err := os.ReadFile(f.key)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	_, seed, err := keyfile.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	_, stdout, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
		"--subject", "s", "--key", f.key)

	body := strings.TrimSpace(string(keyPEM))
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if strings.Contains(out, body) {
			t.Errorf("%s contains the private key PEM", name)
		}
		assertNoSeedIn(t, name, out, seed)
	}
}

// TestAnchorVerb_RejectsAnUnusablePreviousAnchor.
func TestAnchorVerb_RejectsAnUnusablePreviousAnchor(t *testing.T) {
	f := newAnchorFixture(t, 2)

	cases := map[string]string{
		"not json":       "this is not an anchor",
		"no chain_hash":  `{"version":6,"anchor_id":"anchor_x"}`,
		"does not exist": "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(f.dir, "prev-"+strings.ReplaceAll(name, " ", "-")+".json")
			if content != "" {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			code, _, stderr := runAnchor(t, "--db", f.db, "--chain", f.chainID,
				"--subject", "s", "--key", f.key, "--previous", path)
			if code == exitOK {
				t.Fatal("accepted an unusable previous anchor")
			}
			if stderr == "" {
				t.Error("failed silently")
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------

func readFixtureEntries(t *testing.T, f anchorFixture) []verify.Entry {
	t.Helper()
	entries, err := readChain(f.db, f.chainID)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	return entries
}

func readAnchorJSON(t *testing.T, path string) anchor.Anchor {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return a
}

// assertNoSeedIn fails if out contains the seed under any rendering a Go program
// realistically produces.
//
// Built from the formatter's own output rather than from a guess at what a leak
// looks like — an earlier version of the equivalent check in `anchor` searched
// for a string no Go verb emits, and would have passed against a seed printed
// every way it is possible to print one.
func assertNoSeedIn(t *testing.T, where, out string, seed []byte) {
	t.Helper()
	renderings := map[string]string{
		"%x":     fmt.Sprintf("%x", seed),
		"%X":     fmt.Sprintf("%X", seed),
		"%q":     fmt.Sprintf("%q", seed),
		"%v":     fmt.Sprintf("%v", seed),
		"base64": base64.StdEncoding.EncodeToString(seed),
	}
	for name, r := range renderings {
		if len(r) >= 16 && strings.Contains(out, r[:16]) {
			t.Errorf("%s leaks the seed as %s", where, name)
		}
	}
}

// TestAnchorVerb_ZeroizesTheSeedAfterLoading.
//
// The CLI reads a private key off disk and hands it to the signer, which copies
// it. The copy this function holds must not outlive that, and "must not" is
// worth an assertion: deleting the scrub is invisible to every other test,
// which a mutation confirmed.
func TestAnchorVerb_ZeroizesTheSeedAfterLoading(t *testing.T) {
	f := newAnchorFixture(t, 2)

	var captured []byte
	original := zeroizeSeed
	zeroizeSeed = func(b []byte) {
		captured = b // hold the backing array so the scrub is observable
		original(b)
	}
	t.Cleanup(func() { zeroizeSeed = original })

	signer, err := loadSigner(f.key)
	if err != nil {
		t.Fatalf("loadSigner: %v", err)
	}
	defer signer.Close()

	if captured == nil {
		t.Fatal("the seed was never handed to the zeroizer; it is left readable in memory")
	}
	if len(captured) != mldsa.MLDSA65.SeedSize() {
		t.Fatalf("zeroized %d bytes, want the %d-byte seed", len(captured), mldsa.MLDSA65.SeedSize())
	}
	for i, b := range captured {
		if b != 0 {
			t.Fatalf("the seed was not scrubbed: byte %d is 0x%02x", i, b)
		}
	}

	// And the signer still works, so the scrub did not break the copy it made.
	if signer.KeyID() == "" {
		t.Error("the signer lost its identity")
	}
}
