// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
)

// _75f: proof sink init.

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The default: four files beside the sink folder, the right modes, and the
// printed commands work end to end.
func TestSinkInit_TwoKeysAndTheyWork(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "sink-data")
	code, out, errs := sinkRun(t, "", "init", "--dir", dir)
	if code != exitOK {
		t.Fatalf("init: exit %d\n%s%s", code, out, errs)
	}
	keys := dir + ".keys"
	recPriv := filepath.Join(keys, "ml-dsa-65-record-private.pem")
	recPub := filepath.Join(keys, "ml-dsa-65-record-public.pem")
	cpPriv := filepath.Join(keys, "ml-dsa-65-checkpoint-private.pem")
	cpPub := filepath.Join(keys, "ml-dsa-65-checkpoint-public.pem")
	for p, want := range map[string]os.FileMode{recPriv: 0o600, cpPriv: 0o600, recPub: 0o644, cpPub: 0o644} {
		if got := mode(t, p); got != want {
			t.Fatalf("%s: mode %04o, want %04o", p, got, want)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("init created the sink folder")
	}
	for _, want := range []string{"--record-key " + recPriv, "--key " + cpPriv, "--record-trust " + recPub} {
		if !strings.Contains(out, want) {
			t.Fatalf("the next commands lack %q:\n%s", want, out)
		}
	}

	ev := "{\"user\":\"u-81\"}\n{\"user\":\"u-82\"}\n"
	if code, o, e := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user", "--record-key", recPriv); code != exitOK {
		t.Fatalf("commit: exit %d\n%s%s", code, o, e)
	}
	if code, o, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", cpPriv); code != exitOK || strings.Contains(e, "also signs") {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, o, e)
	}
	code, o, e := sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub, "--record-trust", recPub)
	if code != exitOK || !strings.Contains(o, "Record signatures: checked") || !strings.Contains(o, "all 2 chains verify") {
		t.Fatalf("verify: exit %d\n%s%s", code, o, e)
	}
}

func TestSinkInit_Refusals(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "sink-data")
	for _, kd := range []string{dir, filepath.Join(dir, "keys")} {
		if code, _, errs := sinkRun(t, "", "init", "--dir", dir, "--keys-dir", kd); code != exitUsage ||
			!strings.Contains(errs, "out of the folder you share") {
			t.Fatalf("keys in %s: exit %d\n%s", kd, code, errs)
		}
	}
	if code, _, _ := sinkRun(t, "", "init", "--dir", dir, "--one-key", "--op-vault", "V"); code != exitUsage {
		t.Fatalf("--one-key with --op-vault: exit %d", code)
	}
	if code, _, _ := sinkRun(t, "", "init", "--dir", dir); code != exitOK {
		t.Fatal("first init failed")
	}
	// Never silently replace a key that may have signed records.
	if code, _, errs := sinkRun(t, "", "init", "--dir", dir); code != exitUsage || !strings.Contains(errs, "--force") {
		t.Fatalf("second init: exit %d\n%s", code, errs)
	}
	before, _ := os.ReadFile(filepath.Join(dir+".keys", "ml-dsa-65-record-public.pem"))
	if code, _, _ := sinkRun(t, "", "init", "--dir", dir, "--force"); code != exitOK {
		t.Fatal("--force failed")
	}
	if after, _ := os.ReadFile(filepath.Join(dir+".keys", "ml-dsa-65-record-public.pem")); string(after) == string(before) {
		t.Fatal("--force did not replace the key")
	}
}

func TestSinkInit_OneKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink-data")
	code, out, _ := sinkRun(t, "", "init", "--dir", dir, "--one-key")
	shared := filepath.Join(dir+".keys", "ml-dsa-65-shared-private.pem")
	if code != exitOK || !strings.Contains(out, "weaker") || !strings.Contains(out, "--key "+shared) ||
		!strings.Contains(out, "--record-key "+shared) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	entries, _ := os.ReadDir(dir + ".keys")
	if len(entries) != 2 {
		t.Fatalf("%d files, want one pair", len(entries))
	}
	if code, _, errs := sinkRun(t, "", "init", "--dir", dir, "--one-key"); code != exitUsage || !strings.Contains(errs, "--force") {
		t.Fatalf("a second --one-key init replaced the key: exit %d\n%s", code, errs)
	}
}

// fakeOp puts a stub `op` on PATH: item create records the fingerprint and the
// private key it was given; item get reads the fingerprint back (or a wrong
// one); STUB_OP_FAIL makes create fail.
func fakeOp(t *testing.T) string {
	t.Helper()
	bin, store := t.TempDir(), t.TempDir()
	script := `#!/bin/sh
case "$1 $2" in
"item create")
  [ -n "$STUB_OP_FAIL" ] && { echo "op: not signed in" >&2; exit 1; }
  for a in "$@"; do
    case "$a" in
      "fingerprint[text]="*) printf '%s\n' "${a#fingerprint\[text\]=}" > "$STUB_OP_DIR/fp" ;;
      "privkey_pem[file]="*) cp "${a#privkey_pem\[file\]=}" "$STUB_OP_DIR/priv.pem" ;;
    esac
  done
  exit 0 ;;
"item get")
  [ -f "$STUB_OP_DIR/fp" ] || { echo "op: no item found" >&2; exit 1; }
  if [ -n "$STUB_OP_MISMATCH" ]; then echo wrong; else cat "$STUB_OP_DIR/fp"; fi
  exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "op"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("STUB_OP_DIR", store)
	return store
}

// --op-vault: the checkpoint key goes to 1Password and leaves the disk; the
// printed checkpoint command reads it from there. The stored key works.
func TestSinkInit_OpVault(t *testing.T) {
	store := fakeOp(t)
	dir := filepath.Join(t.TempDir(), "sink-data")
	code, out, errs := sinkRun(t, "", "init", "--dir", dir, "--op-vault", "Proof")
	if code != exitOK {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	keys := dir + ".keys"
	if _, err := os.Stat(filepath.Join(keys, "ml-dsa-65-checkpoint-private.pem")); err == nil {
		t.Fatal("the checkpoint private key was left on disk")
	}
	for _, f := range []string{"ml-dsa-65-checkpoint-public.pem", "ml-dsa-65-record-private.pem", "ml-dsa-65-record-public.pem"} {
		if _, err := os.Stat(filepath.Join(keys, f)); err != nil {
			t.Fatalf("%s is missing", f)
		}
	}
	if !strings.Contains(out, `--key <(op read op://Proof/proof-ml-dsa-65-checkpoint/privkey_pem)`) {
		t.Fatalf("the checkpoint command does not read from 1Password:\n%s", out)
	}
	// What 1Password holds is the checkpoint key (as `op read` would return it).
	ev := "{\"user\":\"u-81\"}\n"
	if code, o, e := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user",
		"--record-key", filepath.Join(keys, "ml-dsa-65-record-private.pem")); code != exitOK {
		t.Fatalf("commit: exit %d\n%s%s", code, o, e)
	}
	if code, o, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", filepath.Join(store, "priv.pem")); code != exitOK {
		t.Fatalf("checkpoint with the stored key: exit %d\n%s%s", code, o, e)
	}
	if code, o, e := sinkRun(t, "", "verify", "--dir", dir, "--key", filepath.Join(keys, "ml-dsa-65-checkpoint-public.pem"),
		"--record-trust", filepath.Join(keys, "ml-dsa-65-record-public.pem")); code != exitOK {
		t.Fatalf("verify: exit %d\n%s%s", code, o, e)
	}
}

// A 1Password failure, or a read-back that does not match, keeps every file
// (they may be the only copy) and fails.
func TestSinkInit_OpVaultFailureKeepsTheKey(t *testing.T) {
	for _, env := range []string{"STUB_OP_FAIL", "STUB_OP_MISMATCH"} {
		t.Run(env, func(t *testing.T) {
			fakeOp(t)
			t.Setenv(env, "1")
			dir := filepath.Join(t.TempDir(), "sink-data")
			code, _, errs := sinkRun(t, "", "init", "--dir", dir, "--op-vault", "Proof")
			if code != exitIOError || !strings.Contains(errs, "the key files are kept") {
				t.Fatalf("exit %d\n%s", code, errs)
			}
			if _, err := os.Stat(filepath.Join(dir+".keys", "ml-dsa-65-checkpoint-private.pem")); err != nil {
				t.Fatal("the checkpoint key was removed although 1Password did not hold it")
			}
		})
	}
}

// #1: keys can be put inside the sink folder through no path trick: a
// symlinked parent, a symlink to the folder, another letter case, or the
// folder itself.
func TestSinkInit_KeysNeverInsideTheSink(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "sink-data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	aliasLink := filepath.Join(other, "base-alias")
	if err := os.Symlink(base, aliasLink); err != nil {
		t.Fatal(err)
	}
	for name, kd := range map[string]string{
		"through a symlink to the folder": filepath.Join(base, "link", "keys"),
		"through a symlinked parent":      filepath.Join(aliasLink, "sink-data", "keys"),
		"in another letter case":          filepath.Join(base, "SINK-DATA", "keys"),
		"the folder itself, by a symlink": filepath.Join(base, "link"),
	} {
		code, _, errs := sinkRun(t, "", "init", "--dir", dir, "--keys-dir", kd)
		if code != exitUsage || !strings.Contains(errs, "out of the folder you share") {
			t.Fatalf("%s (%s): exit %d\n%s", name, kd, code, errs)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("something was written inside the sink folder: %v", entries)
	}
}

// #5: --dir . puts the keys beside the current folder, not refused.
func TestSinkInit_DirDot(t *testing.T) {
	work := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if code, out, errs := sinkRun(t, "", "init", "--dir", "."); code != exitOK || !strings.Contains(out, work+".keys") {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
}

// #7: a refusal leaves no half-written key set.
func TestSinkInit_RefusalWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink-data")
	keys := dir + ".keys"
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "ml-dsa-65-checkpoint-public.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := sinkRun(t, "", "init", "--dir", dir); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(keys, "ml-dsa-65-record-private.pem")); err == nil {
		t.Fatal("the record key was written before the refusal")
	}
}

// #2: an existing 1Password item of that title is refused before anything is
// generated.
func TestSinkInit_OpVaultExistingItem(t *testing.T) {
	store := fakeOp(t)
	if err := os.WriteFile(filepath.Join(store, "fp"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "sink-data")
	code, _, errs := sinkRun(t, "", "init", "--dir", dir, "--op-vault", "Proof")
	if code != exitUsage || !strings.Contains(errs, "already holds an item") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(dir + ".keys"); err == nil {
		t.Fatal("keys were generated before the refusal")
	}
}

// #4: printed commands are quoted for the shell when they need it.
func TestSinkInit_PrintedCommandsAreQuoted(t *testing.T) {
	fakeOp(t)
	dir := filepath.Join(t.TempDir(), "my sink")
	code, out, errs := sinkRun(t, "", "init", "--dir", dir, "--op-vault", "My Vault")
	if code != exitOK {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "--dir '"+dir+"'") || !strings.Contains(out, "<(op read 'op://My Vault/") {
		t.Fatalf("not quoted:\n%s", out)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

// #8: two keys alike (a broken random source) are both removed, and it fails.
func TestSinkInit_IdenticalKeys(t *testing.T) {
	real := generateKey
	generateKey = func(a keyfile.Algorithm, outDir, slot, name, opVault string, force bool, stdout, stderr *os.File) (string, error) {
		if _, err := real(a, outDir, slot, name, opVault, force, stdout, stderr); err != nil {
			return "", err
		}
		return "same", nil
	}
	t.Cleanup(func() { generateKey = real })
	dir := filepath.Join(t.TempDir(), "sink-data")
	code, _, errs := sinkRun(t, "", "init", "--dir", dir)
	if code != exitIOError || !strings.Contains(errs, "identical") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	entries, _ := os.ReadDir(dir + ".keys")
	if len(entries) != 0 {
		t.Fatalf("keys left behind: %v", entries)
	}
}
