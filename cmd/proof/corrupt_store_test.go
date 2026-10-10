// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// overwritePages replaces everything after a bbolt file's two meta pages, so
// the file still opens and its first page read finds the wrong contents.
func overwritePages(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := 2 * os.Getpagesize()
	if len(raw) <= start {
		t.Fatalf("%s is %d bytes: no pages after the meta pages", path, len(raw))
	}
	copy(raw[start:], bytes.Repeat([]byte{0xA5}, len(raw)-start))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runMain runs the whole command line through run, as main does.
func runMain(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer outF.Close()
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer errF.Close()
	code := run(args, outF, errF)
	out, _ := os.ReadFile(outF.Name())
	errOut, _ := os.ReadFile(errF.Name())
	return code, string(out), string(errOut)
}

// TestCorruptStore_SinkVerifyFails: `proof sink verify` on a folder whose
// evidence file has damaged pages exits 1, verification failed. It once
// panicked inside the storage layer, and the Go runtime's status for a panic is
// 2, this command's code for a usage error: tampering read as a typo.
func TestCorruptStore_SinkVerifyFails(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := sinkRun(t, `{"user":"u-1","n":1}`+"\n", "commit", "--dir", dir,
		"--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: exit %d: %s", code, errOut)
	}
	overwritePages(t, filepath.Join(dir, "evidence.db"))

	_, pub := sinkKeys(t)
	code, out, errOut := runMain(t, "sink", "verify", "--dir", dir, "--key", pub)
	if code != exitBroken {
		t.Fatalf("exit %d, want %d (verification failed)\nstdout: %s\nstderr: %.600s", code, exitBroken, out, errOut)
	}
	if strings.Contains(out, "all") && strings.Contains(out, "chains verify") {
		t.Fatalf("a damaged folder was reported as verifying:\n%s", out)
	}
	if !strings.Contains(errOut, "damaged") {
		t.Errorf("stderr does not say the file is damaged:\n%s", errOut)
	}
}

// TestCorruptStore_ExportIsAnIOError: `proof export` on a damaged database
// exits 3, never the runtime's 2.
func TestCorruptStore_ExportIsAnIOError(t *testing.T) {
	db := newDB(t, "chain")
	if code, _, errOut := runMain(t, "init", "--db", db); code != exitOK {
		t.Fatalf("init: exit %d: %s", code, errOut)
	}
	overwritePages(t, db)
	code, _, errOut := runMain(t, "export", "--db", db, "--chain", "c")
	if code != exitIOError {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitIOError, errOut)
	}
}
