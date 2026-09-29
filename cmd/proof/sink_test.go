// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	boltstore "github.com/aleutian-ai/proof/store/bolt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// sinkRun runs `proof sink <args>` with stdin.
func sinkRun(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runWithStdin(t, stdin, cmdSink, args...)
}

// sinkKeys writes an ML-DSA-65 key pair the way `proof keygen` does.
func sinkKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, pubRaw, err := anchor.KeyIDOf(s)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	priv, pub = filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(priv, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSink_Usage(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"no verb":                nil,
		"unknown verb":           {"append", "--dir", dir},
		"commit, no chain-field": {"commit", "--dir", dir},
		"checkpoint, no key":     {"checkpoint", "--dir", dir},
		"verify, no key":         {"verify", "--dir", dir},
		"erase, no chain":        {"erase", "--dir", dir},
		"stray argument":         {"erase", "--dir", dir, "--chain", "u-1", "extra"},
		"wrong verb's flag":      {"commit", "--dir", dir, "--chain", "u-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := sinkRun(t, "", args...); code != exitUsage {
				t.Fatalf("exit %d, want %d", code, exitUsage)
			}
		})
	}
	if code, out, _ := sinkRun(t, "", "help"); code != exitOK || !strings.Contains(out, "proof sink commit") {
		t.Fatalf("help: exit %d, %q", code, out)
	}
}

// TestSink_EndToEnd drives every verb the way docs/sink-format.md's walkthrough does.
func TestSink_EndToEnd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, pub := sinkKeys(t)
	events := `{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}

{"user":"u-81","event":"export","rows":120}
`
	code, out, errs := sinkRun(t, events, "commit", "--dir", dir, "--chain-field", "user")
	if code != exitOK || !strings.Contains(out, "   2 → chain u-81") || !strings.Contains(out, "   1 → chain u-82") {
		t.Fatalf("commit: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK ||
		strings.Count(out, "checkpoint anchors/") != 2 {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK ||
		!strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = sinkRun(t, "", "erase", "--dir", dir, "--chain", "u-81"); code != exitOK ||
		!strings.Contains(out, "erased 2 events on chain u-81") || !strings.Contains(out, "entry sink-") {
		t.Fatalf("erase: exit %d\n%s%s", code, out, errs)
	}
	code, out, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitOK || !strings.Contains(out, "0 opened, 2 erased") || !strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify after erase: exit %d\n%s%s", code, out, errs)
	}

	// Tampering: verify exits 1 (a finding, like a broken chain), naming the chain.
	files, err := os.ReadDir(filepath.Join(dir, "content", "u-82"))
	if err != nil || len(files) != 1 {
		t.Fatalf("u-82 content: %v %v", files, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "u-82", files[0].Name()), []byte(`{"user":"u-82"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitBroken || !strings.Contains(out, "chain u-82") || !strings.Contains(out, "MODIFIED") {
		t.Fatalf("verify after tampering: exit %d\n%s", code, out)
	}
}

// TestSink_CommitBadLine names the line, commits nothing from its batch, and
// never echoes a refused key.
func TestSink_CommitBadLine(t *testing.T) {
	for name, line := range map[string]string{
		"email as key": `{"user":"jo@example.com"}`,
		"no key field": `{"topic":"a"}`,
		"not JSON":     `user=u-1`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			code, _, errs := sinkRun(t, `{"user":"u-1"}`+"\n"+line+"\n", "commit", "--dir", dir, "--chain-field", "user")
			if code != exitIOError || !strings.Contains(errs, "line 2") {
				t.Fatalf("exit %d, stderr %q; want exit %d naming line 2", code, errs, exitIOError)
			}
			if strings.Contains(errs, "jo@example.com") {
				t.Fatalf("stderr echoes the refused key: %q", errs)
			}
			if _, err := os.Stat(filepath.Join(dir, "evidence.db")); !os.IsNotExist(err) {
				t.Fatal("line 1 was committed although its batch had a bad line")
			}
		})
	}
}

// TestSink_CommitBatches: input longer than one batch is committed in full, and
// a later bad line does not hide the batches already committed.
func TestSink_CommitBatches(t *testing.T) {
	var in strings.Builder
	n := sink.MaxBatch*2 + 7
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, `{"user":"u-%d","i":%d}`+"\n", i%2, i)
	}
	code, out, errs := sinkRun(t, in.String(), "commit", "--dir", t.TempDir(), "--chain-field", "user")
	if code != exitOK || !strings.Contains(out, fmt.Sprintf("%4d → chain u-0", (n+1)/2)) ||
		!strings.Contains(out, fmt.Sprintf("%4d → chain u-1", n/2)) {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}

	in.Reset()
	for i := 0; i < sink.MaxBatch; i++ {
		fmt.Fprintf(&in, `{"user":"u-1","i":%d}`+"\n", i)
	}
	in.WriteString(`{"user":"Not-Valid"}` + "\n")
	code, out, errs = sinkRun(t, in.String(), "commit", "--dir", t.TempDir(), "--chain-field", "user")
	if code != exitIOError || !strings.Contains(errs, fmt.Sprintf("line %d", sink.MaxBatch+1)) ||
		!strings.Contains(out, fmt.Sprintf("committed %4d → chain u-1", sink.MaxBatch)) {
		t.Fatalf("later bad line: exit %d\n%s%s", code, out, errs)
	}
}

func TestSink_CheckpointWrongKeyType(t *testing.T) {
	pemBytes, err := keyfile.MarshalPrivateKey(keyfile.XWing, make([]byte, keyfile.XWing.SeedSize()))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "xwing.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := sinkRun(t, "", "checkpoint", "--dir", t.TempDir(), "--key", p)
	if code != exitIOError || !strings.Contains(errs, "ML-DSA-65") {
		t.Fatalf("exit %d, %q", code, errs)
	}
}

// TestSink_BusyAndRefusedExits: a held folder exits 4 (retryable); a chain that
// cannot be checkpointed exits 1 (a finding), and the others are still signed.
func TestSink_BusyAndRefusedExits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, _ := sinkKeys(t)
	if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n"+`{"user":"u-2"}`+"\n", "commit", "--dir", dir, "--chain-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	if code, _, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("checkpoint: %d %s", code, e)
	}
	// u-1 gets a stray file in its checkpoint folder; both get a new event.
	if err := os.WriteFile(filepath.Join(dir, "anchors", "u-1", "stray.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, e := sinkRun(t, `{"user":"u-1","n":2}`+"\n"+`{"user":"u-2","n":2}`+"\n", "commit", "--dir", dir, "--chain-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv)
	if code != exitBroken || !strings.Contains(out, "chain u-1 NOT checkpointed") ||
		!strings.Contains(out, "anchors/u-2/0002.json") {
		t.Fatalf("exit %d\n%s", code, out)
	}

	holder, err := boltstore.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if code, _, _ := sinkRun(t, `{"user":"u-3"}`+"\n", "commit", "--dir", dir, "--chain-field", "user"); code != exitBusy {
		t.Fatalf("commit on a held folder: exit %d, want %d", code, exitBusy)
	}
}

// TestSink_TrustAfterRotation: a new key extends a series signed by the old one
// only when the old public key is passed with --trust.
func TestSink_TrustAfterRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	oldPriv, oldPub := sinkKeys(t)
	newPriv, newPub := sinkKeys(t)
	if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n", "commit", "--dir", dir, "--chain-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	if code, _, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", oldPriv); code != exitOK {
		t.Fatalf("checkpoint: %d %s", code, e)
	}
	if code, _, e := sinkRun(t, `{"user":"u-1","n":2}`+"\n", "commit", "--dir", dir, "--chain-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	if code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", newPriv); code != exitBroken ||
		!strings.Contains(out, "NOT checkpointed") {
		t.Fatalf("without --trust: exit %d\n%s", code, out)
	}
	if code, out, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", newPriv, "--trust", oldPub); code != exitOK ||
		!strings.Contains(out, "0002.json") {
		t.Fatalf("with --trust: exit %d\n%s%s", code, out, e)
	}
	_ = newPub
}
