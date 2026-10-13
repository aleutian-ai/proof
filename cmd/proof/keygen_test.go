// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
)

// readKeyPair reads the two files keygen wrote for an algorithm and slot.
func readKeyPair(t *testing.T, dir, base string) (privPEM, pubPEM []byte, privInfo, pubInfo os.FileInfo) {
	t.Helper()
	privPath := filepath.Join(dir, base+"-private.pem")
	pubPath := filepath.Join(dir, base+"-public.pem")

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	pubPEM, err = os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if privInfo, err = os.Stat(privPath); err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if pubInfo, err = os.Stat(pubPath); err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	return privPEM, pubPEM, privInfo, pubInfo
}

// TestKeygen_EveryAlgorithmRoundTrips is the central test: for each algorithm
// the command offers, the files it writes must parse back through keyfile as
// that same algorithm, with the right sizes and a public key that matches the
// private one.
func TestKeygen_EveryAlgorithmRoundTrips(t *testing.T) {
	cases := []struct {
		flag string
		base string
		alg  keyfile.Algorithm
	}{
		{"x-wing", "x-wing", keyfile.XWing},
		{"ml-kem-768", "ml-kem-768", keyfile.MLKEM768},
		{"ml-kem-1024", "ml-kem-1024", keyfile.MLKEM1024},
		{"ml-dsa-44", "ml-dsa-44", keyfile.MLDSA44},
		{"ml-dsa-65", "ml-dsa-65", keyfile.MLDSA65},
		{"ml-dsa-87", "ml-dsa-87", keyfile.MLDSA87},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			dir := t.TempDir()
			code, stdout, stderr := capture(t, "keygen", "--alg="+tc.flag, "--out-dir="+dir)
			if code != exitOK {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}

			privPEM, pubPEM, _, _ := readKeyPair(t, dir, tc.base)

			gotAlg, seed, err := keyfile.ParsePrivateKey(privPEM)
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			if gotAlg != tc.alg {
				t.Errorf("private key algorithm = %v, want %v", gotAlg, tc.alg)
			}
			if len(seed) != tc.alg.SeedSize() {
				t.Errorf("seed is %d bytes, want %d", len(seed), tc.alg.SeedSize())
			}

			gotAlg, pub, err := keyfile.ParsePublicKey(pubPEM)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			if gotAlg != tc.alg {
				t.Errorf("public key algorithm = %v, want %v", gotAlg, tc.alg)
			}
			if len(pub) != tc.alg.PublicKeySize() {
				t.Errorf("public key is %d bytes, want %d", len(pub), tc.alg.PublicKeySize())
			}

			// The public file must be the public key OF the private file, not
			// some other key that happens to be the right size.
			derived, err := derivePublic(tc.alg, seed)
			if err != nil {
				t.Fatalf("derive public key from the stored seed: %v", err)
			}
			if !bytes.Equal(derived, pub) {
				t.Error("the public key file does not match the private key file")
			}

			// And the key must actually work — the same proof the command makes
			// before writing anything.
			if err := selfTest(tc.alg, seed, pub); err != nil {
				t.Errorf("the written key fails its own self-test: %v", err)
			}

			// Reported key id and fingerprint must describe the key on disk.
			wantID, err := keyfile.KeyIDHex(tc.alg, pub)
			if err != nil {
				t.Fatalf("key id: %v", err)
			}
			if !strings.Contains(stdout, wantID) {
				t.Errorf("stdout does not report the key id %s:\n%s", wantID, stdout)
			}
			sum := sha512.Sum512(pub)
			fp := hex.EncodeToString(sum[:])
			if !strings.Contains(stdout, fp[:4]+" "+fp[4:8]) {
				t.Errorf("stdout does not report the SHA-512 fingerprint:\n%s", stdout)
			}
			if !strings.HasPrefix(fp, wantID) && tc.alg == keyfile.XWing {
				t.Error("X-Wing key id should be the first 32 hex characters of the fingerprint")
			}
		})
	}
}

// TestKeygen_PrivateKeyIsNotPrinted guards the worst possible bug in this
// command: a secret on stdout, where it lands in a terminal scrollback, a CI
// log, or a shell pipeline.
func TestKeygen_PrivateKeyIsNotPrinted(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	privPEM, _, _, _ := readKeyPair(t, dir, "ml-dsa-65")
	_, seed, err := keyfile.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	output := stdout + stderr
	if strings.Contains(output, string(privPEM)) {
		t.Error("the private key PEM was printed")
	}
	if strings.Contains(output, hex.EncodeToString(seed)) {
		t.Error("the private seed was printed in hex")
	}
	// A base64 fragment of the PEM body would leak just as well as the whole.
	for _, line := range strings.Split(string(privPEM), "\n") {
		if len(line) > 20 && !strings.HasPrefix(line, "-----") && strings.Contains(output, line) {
			t.Errorf("a line of the private key PEM appears in the output: %.20s…", line)
		}
	}
}

// TestKeygen_FilePermissions checks the private key is not world-readable. A
// 0644 private key on a shared machine is a silent compromise.
func TestKeygen_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	if code, _, stderr := capture(t, "keygen", "--alg=x-wing", "--out-dir="+dir); code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	_, _, privInfo, pubInfo := readKeyPair(t, dir, "x-wing")

	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %04o, want 0600", got)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("public key mode = %04o, want 0644", got)
	}
}

// TestKeygen_RefusesToOverwrite protects a key already in use: silently
// replacing it would orphan everything encrypted to it.
func TestKeygen_RefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if code, _, stderr := capture(t, "keygen", "--alg=ml-dsa-44", "--out-dir="+dir); code != exitOK {
		t.Fatalf("first keygen: exit %d, stderr: %s", code, stderr)
	}
	first, _, _, _ := readKeyPair(t, dir, "ml-dsa-44")

	code, _, stderr := capture(t, "keygen", "--alg=ml-dsa-44", "--out-dir="+dir)
	if code != exitUsage {
		t.Errorf("exit %d, want exitUsage (%d)", code, exitUsage)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("the refusal does not mention --force: %s", stderr)
	}
	after, _, _, _ := readKeyPair(t, dir, "ml-dsa-44")
	if !bytes.Equal(first, after) {
		t.Error("the existing private key was modified by a refused run")
	}

	code, _, stderr = capture(t, "keygen", "--alg=ml-dsa-44", "--out-dir="+dir, "--force")
	if code != exitOK {
		t.Fatalf("--force: exit %d, stderr: %s", code, stderr)
	}
	forced, _, _, _ := readKeyPair(t, dir, "ml-dsa-44")
	if bytes.Equal(first, forced) {
		t.Error("--force did not replace the key")
	}
}

// TestKeygen_DualSlotWritesTwoDistinctKeys covers the hot/cold pair: a backup
// that is a copy of the primary is not a backup.
func TestKeygen_DualSlotWritesTwoDistinctKeys(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := capture(t, "keygen", "--alg=x-wing", "--slot=dual", "--out-dir="+dir)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	primaryPriv, primaryPub, privInfo, _ := readKeyPair(t, dir, "x-wing-primary")
	backupPriv, backupPub, _, _ := readKeyPair(t, dir, "x-wing-backup")

	if bytes.Equal(primaryPriv, backupPriv) {
		t.Fatal("primary and backup private keys are identical")
	}
	if bytes.Equal(primaryPub, backupPub) {
		t.Fatal("primary and backup public keys are identical")
	}
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("primary private key mode = %04o, want 0600", got)
	}

	for _, pemBytes := range [][]byte{primaryPub, backupPub} {
		alg, pub, err := keyfile.ParsePublicKey(pemBytes)
		if err != nil {
			t.Fatalf("parse public key: %v", err)
		}
		id, err := keyfile.KeyIDHex(alg, pub)
		if err != nil {
			t.Fatalf("key id: %v", err)
		}
		if !strings.Contains(stdout, id) {
			t.Errorf("stdout does not report key id %s:\n%s", id, stdout)
		}
	}
	if !strings.Contains(stdout, "(primary)") || !strings.Contains(stdout, "(backup)") {
		t.Errorf("stdout does not label both slots:\n%s", stdout)
	}
}

// TestKeygen_RejectsBadArguments covers the refusals. ML-KEM-512 is the
// interesting one: keyfile can READ it, but nothing here encapsulates with it,
// so minting one would hand the operator a key with no capability.
func TestKeygen_RejectsBadArguments(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown algorithm", []string{"--alg=rsa-4096"}, "unknown algorithm"},
		{"ml-kem-512 is not offered", []string{"--alg=ml-kem-512"}, "unknown algorithm"},
		{"unknown slot", []string{"--alg=x-wing", "--slot=tertiary"}, "--slot must be"},
		{"unknown flag", []string{"--alg=x-wing", "--nonsense"}, "nonsense"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"keygen", "--out-dir=" + dir}, tc.args...)
			code, stdout, stderr := capture(t, args...)
			if code != exitUsage {
				t.Errorf("exit %d, want exitUsage (%d)", code, exitUsage)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr does not explain the refusal (want %q): %s", tc.want, stderr)
			}
			if stdout != "" {
				t.Errorf("a refused run wrote to stdout: %s", stdout)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("read out-dir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("a refused run wrote %d file(s) into the output directory", len(entries))
			}
		})
	}
}

// TestKeygen_AlgorithmIsCaseInsensitive: operators type ML-DSA-65 the way the
// standard writes it.
func TestKeygen_AlgorithmIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := capture(t, "keygen", "--alg=ML-DSA-65", "--slot=PRIMARY", "--out-dir="+dir)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "ml-dsa-65-primary-private.pem")); err != nil {
		t.Errorf("expected key file: %v", err)
	}
}

// TestKeygen_CreatesOutputDirectory: --out-dir naming a directory that does not
// exist yet is the common case (`proof keygen --out-dir=./keys`).
func TestKeygen_CreatesOutputDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys", "dev")
	code, _, stderr := capture(t, "keygen", "--alg=ml-kem-768", "--out-dir="+dir)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "ml-kem-768-private.pem")); err != nil {
		t.Errorf("expected key file: %v", err)
	}
}

// TestKeygen_SelfTestGuardsTheWrite is the reason for the generate → test →
// write order: a key that fails its pairwise consistency test must never reach
// disk. Here the failure is forced by pairing a seed with the WRONG public key,
// which is what a faulty generation would produce.
func TestKeygen_SelfTestGuardsTheWrite(t *testing.T) {
	cases := []keyfile.Algorithm{
		keyfile.XWing, keyfile.MLKEM768, keyfile.MLKEM1024,
		keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87,
	}
	for _, alg := range cases {
		t.Run(alg.String(), func(t *testing.T) {
			seedA := bytes.Repeat([]byte{0x01}, alg.SeedSize())
			seedB := bytes.Repeat([]byte{0x02}, alg.SeedSize())

			pubA, err := derivePublic(alg, seedA)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			pubB, err := derivePublic(alg, seedB)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if err := selfTest(alg, seedA, pubA); err != nil {
				t.Fatalf("a matched pair failed the self-test: %v", err)
			}
			if err := selfTest(alg, seedA, pubB); err == nil {
				t.Error("the self-test passed with a mismatched public key")
			}
		})
	}
}

// TestKeygen_AFailedSelfTestWritesNothing proves the guard is WIRED IN, not
// merely present: a key that fails its consistency test must leave no file
// behind, or an operator could later encrypt to a key that cannot decrypt.
func TestKeygen_AFailedSelfTestWritesNothing(t *testing.T) {
	original := selfTestFn
	t.Cleanup(func() { selfTestFn = original })
	selfTestFn = func(keyfile.Algorithm, []byte, []byte) error {
		return errForcedSelfTestFailure
	}

	dir := t.TempDir()
	code, stdout, stderr := capture(t, "keygen", "--alg=x-wing", "--out-dir="+dir)
	if code != exitIOError {
		t.Errorf("exit %d, want exitIOError (%d)", code, exitIOError)
	}
	if !strings.Contains(stderr, "nothing written") {
		t.Errorf("stderr does not say the key was discarded: %s", stderr)
	}
	if stdout != "" {
		t.Errorf("a discarded key was reported on stdout: %s", stdout)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read out-dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a key that failed its self-test reached disk: %v", entries)
	}
}

// errForcedSelfTestFailure stands in for a faulty key generation.
var errForcedSelfTestFailure = errors.New("forced self-test failure")

// TestKeygen_SelfTestDescriptionMatchesTheKeyKind: telling an operator their
// signing key "encrypted a secret to itself" teaches them the wrong thing about
// what they are holding.
func TestKeygen_SelfTestDescriptionMatchesTheKeyKind(t *testing.T) {
	signing := []keyfile.Algorithm{keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87}
	kems := []keyfile.Algorithm{keyfile.XWing, keyfile.MLKEM768, keyfile.MLKEM1024}

	for _, alg := range signing {
		if got := selfTestDescription(alg); !strings.Contains(got, "signature") {
			t.Errorf("%s: %q does not describe signing", alg, got)
		}
	}
	for _, alg := range kems {
		if got := selfTestDescription(alg); !strings.Contains(got, "encrypted") {
			t.Errorf("%s: %q does not describe encryption", alg, got)
		}
	}
}

// TestKeygen_GroupFingerprintIsReadableAndLossless: the grouping is for reading
// aloud, so it must not change the hex it groups.
func TestKeygen_GroupFingerprintIsReadableAndLossless(t *testing.T) {
	fp := strings.Repeat("0123456789abcdef", 8) // 128 hex characters
	got := groupFingerprint(fp)

	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' {
			return -1
		}
		return r
	}, got)
	if stripped != fp {
		t.Errorf("grouping changed the fingerprint:\n got %s\nwant %s", stripped, fp)
	}
	if !strings.Contains(got, "0123 4567") {
		t.Errorf("fingerprint is not grouped in fours: %s", got)
	}
	if strings.Count(got, "\n") != 3 {
		t.Errorf("want 4 lines of 32 hex characters, got %d newlines", strings.Count(got, "\n"))
	}
}

// TestKeygen_OpItemTitle covers the 1Password item naming, which is how an
// operator finds the key again a year later.
func TestKeygen_OpItemTitle(t *testing.T) {
	cases := []struct {
		alg  keyfile.Algorithm
		slot string
		name string
		want string
	}{
		{keyfile.XWing, "", "", "proof-x-wing"},
		{keyfile.XWing, "primary", "", "proof-x-wing-primary"},
		{keyfile.MLDSA65, "backup", "acme", "proof-ml-dsa-65-acme-backup"},
		{keyfile.MLKEM1024, "", "acme", "proof-ml-kem-1024-acme"},
	}
	for _, tc := range cases {
		if got := opItemTitle(tc.alg, tc.slot, tc.name); got != tc.want {
			t.Errorf("opItemTitle(%v, %q, %q) = %q, want %q", tc.alg, tc.slot, tc.name, got, tc.want)
		}
	}
}

// TestKeygen_OnePasswordFailureLeavesUsableFiles: if the vault upload fails,
// the operator still holds a valid key and must be told so, not left guessing.
// `op` is absent in the test environment, which is exactly the failure path.
func TestKeygen_OnePasswordFailureLeavesUsableFiles(t *testing.T) {
	if _, err := os.Stat("/usr/local/bin/op"); err == nil {
		t.Skip("the 1Password CLI is installed; this test needs it absent")
	}
	t.Setenv("PATH", t.TempDir())

	dir := t.TempDir()
	code, stdout, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir, "--op-vault=Nonexistent")
	if code != exitOK {
		t.Fatalf("a failed 1Password upload should not fail the command: exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "the key files above are valid") {
		t.Errorf("stderr does not tell the operator the files are still good: %s", stderr)
	}
	if !strings.Contains(stdout, "key id") {
		t.Errorf("stdout does not report the key that was written:\n%s", stdout)
	}

	privPEM, _, _, _ := readKeyPair(t, dir, "ml-dsa-65")
	if _, _, err := keyfile.ParsePrivateKey(privPEM); err != nil {
		t.Errorf("the key written before the failed upload does not parse: %v", err)
	}
}

// TestKeygen_ZeroClearsTheBuffer: the seed wipe is one line and easy to break
// silently.
func TestKeygen_ZeroClearsTheBuffer(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zero(b)
	if !bytes.Equal(b, make([]byte, 5)) {
		t.Errorf("zero left %v", b)
	}
}

// TestKeygen_ForceLeavesThePrivateKey0600: --force over an existing 0644 file
// once kept the old mode, because writing into an existing file does not
// change it, while the output said "(0600 …)". The key is now a new file.
func TestKeygen_ForceLeavesThePrivateKey0600(t *testing.T) {
	dir := t.TempDir()
	priv, pub := keyPaths(dir, keyfile.MLDSA65, "")
	for _, p := range []string{priv, pub} {
		if err := os.WriteFile(p, []byte("an older file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// WriteFile's mode passes through the umask; make it exact.
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir, "--force")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	privPEM, _, privInfo, _ := readKeyPair(t, dir, "ml-dsa-65")
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %04o after --force over a 0644 file, want 0600\n%s", got, stdout)
	}
	if _, _, err := keyfile.ParsePrivateKey(privPEM); err != nil {
		t.Errorf("the private key written by --force does not parse: %v", err)
	}
	assertNoTempFiles(t, dir)
}

// TestKeygen_NeverWritesThroughASymlink: a symlink at a key's path, dangling
// or not, is not followed. os.Stat reported a dangling one as absent, and the
// write then created the private key wherever the link pointed.
func TestKeygen_NeverWritesThroughASymlink(t *testing.T) {
	for _, which := range []string{"private", "public"} {
		for _, dangling := range []bool{true, false} {
			name := which + " key, link to an existing file"
			if dangling {
				name = which + " key, dangling link"
			}
			t.Run(name, func(t *testing.T) {
				dir, elsewhere := t.TempDir(), t.TempDir()
				target := filepath.Join(elsewhere, "target")
				if !dangling {
					if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				priv, pub := keyPaths(dir, keyfile.MLDSA65, "")
				link := priv
				if which == "public" {
					link = pub
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				targetUntouched := func(when string) {
					t.Helper()
					got, err := os.ReadFile(target)
					switch {
					case dangling && !os.IsNotExist(err):
						t.Fatalf("%s: the link's target now exists: a key was written through it", when)
					case !dangling && string(got) != "untouched":
						t.Fatalf("%s: the link's target was overwritten", when)
					}
				}

				// Without --force the link is something at the path: refused.
				code, _, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir)
				if code != exitUsage || !strings.Contains(stderr, "--force") {
					t.Errorf("exit %d, want %d and a mention of --force: %s", code, exitUsage, stderr)
				}
				targetUntouched("without --force")
				if which == "public" {
					if _, err := os.Lstat(priv); !os.IsNotExist(err) {
						t.Error("the private key was written by a refused run")
					}
				}

				// With --force the link itself is replaced by the key.
				code, _, stderr = capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir, "--force")
				if code != exitOK {
					t.Fatalf("--force: exit %d, stderr: %s", code, stderr)
				}
				targetUntouched("with --force")
				info, err := os.Lstat(link)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("the key at the link's path is not a regular file: %v, %v", info, err)
				}
				privPEM, pubPEM, privInfo, _ := readKeyPair(t, dir, "ml-dsa-65")
				if privInfo.Mode().Perm() != 0o600 {
					t.Errorf("private key mode = %04o, want 0600", privInfo.Mode().Perm())
				}
				if _, _, err := keyfile.ParsePrivateKey(privPEM); err != nil {
					t.Errorf("private key: %v", err)
				}
				if _, _, err := keyfile.ParsePublicKey(pubPEM); err != nil {
					t.Errorf("public key: %v", err)
				}
				assertNoTempFiles(t, dir)
			})
		}
	}
}

// assertNoTempFiles checks a key directory holds key files and nothing else.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "-private.pem") && !strings.HasSuffix(e.Name(), "-public.pem") {
			t.Errorf("%s was left in the key directory", e.Name())
		}
	}
}

// fakeVault stands in for the 1Password CLI. It keeps what `op item create`
// was given: the text fields, and the CONTENTS of the attached files, which is
// what a real vault stores and what a read returns.
type fakeVault struct {
	t      *testing.T
	fields map[string]string
	files  map[string][]byte
	calls  [][]string

	// afterCreate lets a case change what the vault holds, as a faulty upload
	// or a different item answering the read would.
	afterCreate func(v *fakeVault)
	createReply string
}

const (
	fakeItemID  = "abcdefghijklmnopqrstuvwxyz"
	fakeVaultID = "zyxwvutsrqponmlkjihgfedcba"
)

func (v *fakeVault) run(args ...string) ([]byte, error) {
	v.calls = append(v.calls, args)
	switch {
	case len(args) >= 2 && args[0] == "item" && args[1] == "create":
		v.fields, v.files = map[string]string{}, map[string][]byte{}
		for _, a := range args[2:] {
			name, value, ok := strings.Cut(a, "=")
			switch {
			case !ok || strings.HasPrefix(a, "--"):
			case strings.HasSuffix(name, "[file]"):
				data, err := os.ReadFile(value)
				if err != nil {
					v.t.Fatalf("the fake vault cannot read %s: %v", value, err)
				}
				v.files[strings.TrimSuffix(name, "[file]")] = data
			case strings.HasSuffix(name, "[text]"):
				v.fields[strings.TrimSuffix(name, "[text]")] = value
			}
		}
		if v.afterCreate != nil {
			v.afterCreate(v)
		}
		if v.createReply != "" {
			return []byte(v.createReply), nil
		}
		return []byte(`{"id":"` + fakeItemID + `","title":"t","vault":{"id":"` + fakeVaultID + `","name":"V"}}`), nil
	case len(args) == 2 && args[0] == "read":
		name, ok := strings.CutPrefix(args[1], "op://"+fakeVaultID+"/"+fakeItemID+"/")
		if !ok {
			return nil, errors.New("no such item")
		}
		data, ok := v.files[name]
		if !ok {
			return nil, errors.New("no such file")
		}
		return append([]byte(nil), data...), nil
	case len(args) >= 2 && args[0] == "item" && args[1] == "get":
		// The old read-back: the fingerprint text field, which is always what
		// was just written.
		return []byte(v.fields["fingerprint"] + "\n"), nil
	}
	return nil, errors.New("the fake vault does not implement: " + strings.Join(args, " "))
}

// TestKeygen_OnePasswordReadBackChecksTheStoredKeys: the read-back once
// compared the item's fingerprint TEXT field with the fingerprint it had just
// written there, so it passed whatever was attached. It now fetches the two
// attached key files and fingerprints those.
func TestKeygen_OnePasswordReadBackChecksTheStoredKeys(t *testing.T) {
	otherPair := func(t *testing.T) (priv, pub []byte) {
		t.Helper()
		dir := t.TempDir()
		if code, _, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir); code != exitOK {
			t.Fatalf("second key: exit %d: %s", code, stderr)
		}
		priv, pub, _, _ = readKeyPair(t, dir, "ml-dsa-65")
		return priv, pub
	}

	cases := []struct {
		name        string
		afterCreate func(t *testing.T) func(v *fakeVault)
		createReply string
		wantStderr  string // empty: the read-back must pass
	}{
		{name: "the vault holds this key"},
		{
			name: "another private key is attached",
			afterCreate: func(t *testing.T) func(v *fakeVault) {
				priv, _ := otherPair(t)
				return func(v *fakeVault) { v.files["privkey_pem"] = priv }
			},
			wantStderr: "the private key read back is not the key that was generated",
		},
		{
			name: "another public key is attached",
			afterCreate: func(t *testing.T) func(v *fakeVault) {
				_, pub := otherPair(t)
				return func(v *fakeVault) { v.files["pubkey_pem"] = pub }
			},
			wantStderr: "the public key read back is not the key that was generated",
		},
		{
			name: "the private key attachment is empty",
			afterCreate: func(t *testing.T) func(v *fakeVault) {
				return func(v *fakeVault) { v.files["privkey_pem"] = nil }
			},
			wantStderr: "the private key read back is not a key file",
		},
		{
			name: "the private key was not attached",
			afterCreate: func(t *testing.T) func(v *fakeVault) {
				return func(v *fakeVault) { delete(v.files, "privkey_pem") }
			},
			wantStderr: "reading the private key back failed",
		},
		{
			name:        "op does not say which item it created",
			createReply: `{"title":"t"}`,
			wantStderr:  "could not be read back",
		},
		{
			name:        "op names an item id that is not one",
			createReply: `{"id":"../../other/item?attribute=x","vault":{"id":"` + fakeVaultID + `"}}`,
			wantStderr:  "could not be read back",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &fakeVault{t: t, createReply: tc.createReply}
			if tc.afterCreate != nil {
				v.afterCreate = tc.afterCreate(t)
			}
			saved := opCommand
			opCommand = v.run
			defer func() { opCommand = saved }()

			dir := t.TempDir()
			code, stdout, stderr := capture(t, "keygen", "--alg=ml-dsa-65", "--out-dir="+dir, "--op-vault=V")
			if code != exitOK {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}
			// The fake's own old-style answer always matches: this is the
			// check that used to be the whole read-back.
			if v.fields["fingerprint"] == "" {
				t.Fatal("the fingerprint text field was not written")
			}

			verified := strings.Contains(stdout, "read back and verified")
			if tc.wantStderr == "" {
				if !verified || strings.Contains(stderr, "1Password") {
					t.Errorf("an honest vault was not verified.\nstdout: %s\nstderr: %s", stdout, stderr)
				}
			} else {
				if verified {
					t.Errorf("the read-back passed:\n%s", stdout)
				}
				if !strings.Contains(stderr, tc.wantStderr) || !strings.Contains(stderr, "check the item by hand") {
					t.Errorf("stderr does not say %q and to check by hand: %s", tc.wantStderr, stderr)
				}
			}
			// Whatever the vault did, the local files are this key, and no key
			// material reached the command line or the output.
			privPEM, _, _, _ := readKeyPair(t, dir, "ml-dsa-65")
			_, seed, err := keyfile.ParsePrivateKey(privPEM)
			if err != nil {
				t.Fatalf("local private key: %v", err)
			}
			assertNoSeedIn(t, "stdout", stdout, seed)
			assertNoSeedIn(t, "stderr", stderr, seed)
			for _, call := range v.calls {
				assertNoSeedIn(t, "op arguments", strings.Join(call, " "), seed)
				if call[0] == "item" && call[1] == "get" {
					t.Errorf("the read-back asked for a field of the item, not its files: %v", call)
				}
			}
		})
	}
}
