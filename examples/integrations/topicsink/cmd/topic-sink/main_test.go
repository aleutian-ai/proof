// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/examples/integrations/topicsink"
	"github.com/aleutian-ai/proof/keyfile"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// writeKeys writes an ML-DSA-65 key pair the way `proof keygen` does.
func writeKeys(t *testing.T, dir string) (priv, pub string) {
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
	priv, pub = filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(priv, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestUsage(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"no command":       nil,
		"unknown command":  {"append", "-dir", dir},
		"commit, no -key":  {"commit", "-dir", dir},
		"verify, no -pub":  {"verify", "-dir", dir},
		"erase, no -chain": {"erase", "-dir", dir},
		"stray argument":   {"erase", "-dir", dir, "-chain", "u-1", "extra"},
		"unknown flag":     {"commit", "-dir", dir, "-topic", "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := runCmd(t, "", args...); code != exitUsage {
				t.Fatalf("exit %d, want %d", code, exitUsage)
			}
		})
	}
}

// TestEndToEnd drives every verb the way the README does.
func TestEndToEnd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, pub := writeKeys(t, t.TempDir())
	events := `{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}

{"user":"u-81","event":"export","rows":120}
`
	code, out, errs := runCmd(t, events, "commit", "-dir", dir, "-key", "user")
	if code != exitOK || !strings.Contains(out, "   2 → chain u-81") || !strings.Contains(out, "   1 → chain u-82") {
		t.Fatalf("commit: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = runCmd(t, "", "checkpoint", "-dir", dir, "-key-file", priv); code != exitOK ||
		strings.Count(out, "checkpoint anchors/") != 2 {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = runCmd(t, "", "verify", "-dir", dir, "-pub-file", pub); code != exitOK ||
		!strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = runCmd(t, "", "erase", "-dir", dir, "-chain", "u-81"); code != exitOK ||
		!strings.Contains(out, "erased 2 events on chain u-81") {
		t.Fatalf("erase: exit %d\n%s%s", code, out, errs)
	}
	code, out, errs = runCmd(t, "", "verify", "-dir", dir, "-pub-file", pub)
	if code != exitOK || !strings.Contains(out, "0 opened, 2 erased") || !strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify after erase: exit %d\n%s%s", code, out, errs)
	}

	// Tampering turns verify into exit 1 and names the chain.
	entries, err := os.ReadDir(filepath.Join(dir, "content", "u-82"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("u-82 content: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "u-82", entries[0].Name()), []byte(`{"user":"u-82"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCmd(t, "", "verify", "-dir", dir, "-pub-file", pub)
	if code != exitFailed || !strings.Contains(out, "chain u-82") || !strings.Contains(out, "MODIFIED") {
		t.Fatalf("verify after tampering: exit %d\n%s", code, out)
	}
}

// TestCommit_BadLine names the line and commits nothing from its batch.
func TestCommit_BadLine(t *testing.T) {
	dir := t.TempDir()
	for name, line := range map[string]string{
		"email as key": `{"user":"jo@example.com"}`,
		"no key field": `{"topic":"a"}`,
		"not JSON":     `user=u-1`,
	} {
		t.Run(name, func(t *testing.T) {
			sub := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
			code, _, errs := runCmd(t, `{"user":"u-1"}`+"\n"+line+"\n", "commit", "-dir", sub, "-key", "user")
			if code != exitFailed || !strings.Contains(errs, "line 2") {
				t.Fatalf("exit %d, stderr %q; want exit 1 naming line 2", code, errs)
			}
			if strings.Contains(errs, "jo@example.com") {
				t.Fatalf("stderr echoes the refused key: %q", errs)
			}
			if _, err := os.Stat(filepath.Join(sub, "evidence.db")); !os.IsNotExist(err) {
				t.Fatal("line 1 was committed although its batch had a bad line")
			}
		})
	}
}

// TestCommit_Batches: input longer than one batch is committed in full.
func TestCommit_Batches(t *testing.T) {
	var in strings.Builder
	n := topicsink.MaxBatch*2 + 7
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, `{"user":"u-%d","i":%d}`+"\n", i%2, i)
	}
	code, out, errs := runCmd(t, in.String(), "commit", "-dir", t.TempDir(), "-key", "user")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, fmt.Sprintf("%4d → chain u-0", (n+1)/2)) ||
		!strings.Contains(out, fmt.Sprintf("%4d → chain u-1", n/2)) {
		t.Fatalf("totals wrong:\n%s", out)
	}
}

func TestCheckpoint_WrongKeyType(t *testing.T) {
	seed := make([]byte, keyfile.XWing.SeedSize())
	pemBytes, err := keyfile.MarshalPrivateKey(keyfile.XWing, seed)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "xwing.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runCmd(t, "", "checkpoint", "-dir", t.TempDir(), "-key-file", p)
	if code != exitFailed || !strings.Contains(errs, "ML-DSA-65") {
		t.Fatalf("exit %d, %q", code, errs)
	}
}

// TestCommit_LaterBatchFails: batches before a bad line are committed, and the
// run says so rather than printing only the error.
func TestCommit_LaterBatchFails(t *testing.T) {
	var in strings.Builder
	for i := 0; i < topicsink.MaxBatch; i++ {
		fmt.Fprintf(&in, `{"user":"u-1","i":%d}`+"\n", i)
	}
	in.WriteString(`{"user":"Not-Valid"}` + "\n")
	code, out, errs := runCmd(t, in.String(), "commit", "-dir", t.TempDir(), "-key", "user")
	if code != exitFailed || !strings.Contains(errs, fmt.Sprintf("line %d", topicsink.MaxBatch+1)) {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, fmt.Sprintf("committed %4d → chain u-1", topicsink.MaxBatch)) {
		t.Fatalf("the committed first batch was not reported:\n%s", out)
	}
}
