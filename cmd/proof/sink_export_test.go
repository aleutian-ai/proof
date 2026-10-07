// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/sink"
)

// exportSink makes a sink with two subjects' events.
func exportSink(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sink-data")
	s, err := sink.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var recs []sink.Record
	for _, subj := range []string{"u-81", "u-81", "u-82"} {
		recs = append(recs, sink.Record{Class: "events", Subject: subj, Content: []byte(`{"e":"x"}`)})
	}
	if _, err := s.Commit(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runExport(args ...string) (int, string) {
	var out, errs bytes.Buffer
	code := cmdSinkExport(args, &out, &errs)
	return code, out.String() + errs.String()
}

// leftovers lists files in dir other than want: a failed or finished export
// leaves no temporary file behind.
func leftovers(t *testing.T, dir string, want ...string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var extra []string
	for _, e := range ents {
		keep := false
		for _, w := range want {
			keep = keep || e.Name() == w
		}
		if !keep {
			extra = append(extra, e.Name())
		}
	}
	return extra
}

func TestSinkExport_Usage(t *testing.T) {
	dir := exportSink(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "b.json")
	for name, args := range map[string][]string{
		"no --out":                {"--dir", dir, "--all"},
		"no selector":             {"--dir", dir, "--out", out},
		"two selectors":           {"--dir", dir, "--all", "--subject", "u-81", "--out", out},
		"--class without subject": {"--dir", dir, "--all", "--class", "events", "--out", out},
		"stray argument":          {"--dir", dir, "--all", "--out", out, "extra"},
	} {
		if code, msg := runExport(args...); code != exitUsage {
			t.Fatalf("%s: exit %d (%s)", name, code, msg)
		}
	}
	if extra := leftovers(t, outDir); len(extra) != 0 {
		t.Fatalf("left %v", extra)
	}
}

// A bundle is never written to an existing file, and never to stdout.
func TestSinkExport_RefusesExisting(t *testing.T) {
	dir := exportSink(t)
	out := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, msg := runExport("--dir", dir, "--all", "--out", out); code != exitUsage || !strings.Contains(msg, "never overwritten") {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if b, _ := os.ReadFile(out); string(b) != "keep" {
		t.Fatal("the existing file was changed")
	}
}

// Success: a 0600 bundle, no temporary file, the summary and warnings on
// stderr, nothing on stdout, and no subject in the bundle.
func TestSinkExport_Writes(t *testing.T) {
	dir := exportSink(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "b.json")
	var stdout, stderr bytes.Buffer
	code := cmdSinkExport([]string{"--dir", dir, "--subject", "u-81", "--disclose", "all", "--out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout: %q", stdout.String())
	}
	msg := stderr.String()
	for _, want := range []string{"1 chain(s), 2 entries", "2 event(s) disclosed", "PRIVACY: this bundle is about one subject",
		"Disclosure is permanent"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("stderr lacks %q: %s", want, msg)
		}
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("bundle: %v, mode %v", err, fi.Mode())
	}
	b, _ := os.ReadFile(out)
	if !bytes.HasPrefix(b, []byte(`{"format":"aleutian.proof.bundle.v1"`)) || bytes.Contains(b, []byte("u-81")) {
		t.Fatalf("bundle: %.80s", b)
	}
	if extra := leftovers(t, outDir, "b.json"); len(extra) != 0 {
		t.Fatalf("left %v", extra)
	}
}

// A failed export leaves no file and no temporary file; an impossible
// disclosure is the caller's to fix (exit 2).
func TestSinkExport_FailureLeavesNothing(t *testing.T) {
	dir := exportSink(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "b.json")
	code, msg := runExport("--dir", dir, "--all", "--disclose", "sink-"+strings.Repeat("0", 32), "--out", out)
	if code != exitUsage || !strings.Contains(msg, "disclosure") {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if extra := leftovers(t, outDir); len(extra) != 0 {
		t.Fatalf("left %v", extra)
	}
	code, msg = runExport("--dir", dir, "--subject", "u-99", "--out", out)
	if code != exitUsage || !strings.Contains(msg, "matched no chain") {
		t.Fatalf("empty selection: exit %d: %s", code, msg)
	}
	if extra := leftovers(t, outDir); len(extra) != 0 {
		t.Fatalf("left %v", extra)
	}
}

// Without --disclose there is no content, and no disclosure warning.
func TestSinkExport_NoDisclosureByDefault(t *testing.T) {
	dir := exportSink(t)
	out := filepath.Join(t.TempDir(), "b.json")
	code, msg := runExport("--dir", dir, "--all", "--out", out)
	if code != exitOK || strings.Contains(msg, "Disclosure is permanent") || strings.Contains(msg, "about one subject") {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if b, _ := os.ReadFile(out); bytes.Contains(b, []byte(`"disclosed"`)) {
		t.Fatal("content exported without --disclose")
	}
}

// Exit codes: a caller's mistake is 2; a folder that cannot be exported
// faithfully is 3.
func TestSinkExport_ExitCodes(t *testing.T) {
	dir := exportSink(t)
	out := filepath.Join(t.TempDir(), "b.json")
	if code, msg := runExport("--dir", dir, "--chain", "../x", "--out", out); code != exitUsage {
		t.Fatalf("invalid --chain: exit %d (%s)", code, msg)
	}
	if code, msg := runExport("--dir", dir, "--all", "--disclose", ",", "--out", out); code != exitUsage {
		t.Fatalf("empty --disclose list: exit %d (%s)", code, msg)
	}
	// A stray file among a chain's checkpoints: unrepresentable, exit 3.
	anchors := filepath.Join(dir, "anchors")
	ents, err := os.ReadDir(anchors)
	if err != nil || len(ents) == 0 {
		// No checkpoints yet: make the folder for one chain.
		s, _ := sink.Open(dir)
		subs, err := s.ChainSubjects(context.Background())
		if err != nil || len(subs) == 0 {
			t.Fatalf("chains: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(anchors, subs[0].Chain), 0o700); err != nil {
			t.Fatal(err)
		}
		ents, _ = os.ReadDir(anchors)
	}
	if err := os.WriteFile(filepath.Join(anchors, ents[0].Name(), "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, msg := runExport("--dir", dir, "--all", "--out", out); code != exitIOError || strings.Contains(msg, ents[0].Name()) {
		t.Fatalf("unrepresentable: exit %d (%s)", code, msg)
	}
}
