// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// _75d: record signing through the CLI.
func TestSink_RecordSigning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	cpPriv, cpPub := sinkKeys(t)
	recPriv, recPub := sinkKeys(t)
	_, otherPub := sinkKeys(t)
	events := "{\"user\":\"u-81\",\"e\":1}\n{\"user\":\"u-82\",\"e\":2}\n"
	commit := func(extra ...string) (int, string, string) {
		args := append([]string{"commit", "--dir", dir, "--class", "events", "--subject-field", "user"}, extra...)
		return sinkRun(t, events, args...)
	}

	if code, out, errs := commit("--record-key", recPriv); code != exitOK {
		t.Fatalf("signed commit: exit %d\n%s%s", code, out, errs)
	}
	// D6: a signing sink without --record-key: exit 2, with the fix.
	if code, _, errs := commit(); code != exitUsage || !strings.Contains(errs, "pass --record-key") {
		t.Fatalf("commit without --record-key: exit %d\n%s", code, errs)
	}
	if code, _, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81"); code != exitUsage ||
		!strings.Contains(errs, "pass --record-key") {
		t.Fatalf("erase without --record-key: exit %d\n%s", code, errs)
	}

	// D4: verified without record trust: passes, and says NOT CHECKED on its own line.
	code, out, errs := sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub)
	if code != exitOK || !strings.Contains(out, "\nRecord signatures: NOT CHECKED") {
		t.Fatalf("verify without --record-trust: exit %d\n%s%s", code, out, errs)
	}
	// With record trust: every record signed.
	code, out, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub, "--record-trust", recPub)
	if code != exitOK || strings.Count(out, "· 1 signed") != 2 || !strings.Contains(out, "Record signatures: checked") {
		t.Fatalf("verify with --record-trust: exit %d\n%s%s", code, out, errs)
	}
	// The wrong record key: every record fails (signed by a key not trusted).
	code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub, "--record-trust", otherPub)
	if code != exitBroken || !strings.Contains(out, "not trusted for records") {
		t.Fatalf("verify with the wrong record key: exit %d\n%s", code, out)
	}
	// Rotation: several --record-trust keys, any of them may have signed.
	code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub, "--record-trust", otherPub, "--record-trust", recPub)
	if code != exitOK {
		t.Fatalf("verify with two record keys: exit %d\n%s", code, out)
	}

	// Signed erasure; verified with record trust it is erased without a checkpoint (R6).
	if code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81", "--record-key", recPriv); code != exitOK {
		t.Fatalf("signed erase: exit %d\n%s%s", code, out, errs)
	}
	code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", cpPub, "--record-trust", recPub)
	if code != exitOK || !strings.Contains(out, "· 2 signed") || !strings.Contains(out, "subject erased\n") {
		t.Fatalf("verify after a signed erase: exit %d\n%s", code, out)
	}

	// R7: a separate checkpoint key is not warned about, on this signing sink.
	code, _, errs = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", cpPriv)
	if code != exitOK || strings.Contains(errs, "also signs") {
		t.Fatalf("checkpoint with a separate key: exit %d\n%s", code, errs)
	}
	// One signed with the record key warns, and goes on.
	code, _, errs = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", recPriv, "--trust", cpPub)
	if code != exitOK || !strings.Contains(errs, "also signs this sink's records") {
		t.Fatalf("checkpoint with the record key: exit %d\n%s", code, errs)
	}
}

// D6: an unsigned sink refuses --record-key, exit 2.
func TestSink_RecordKeyOnAnUnsignedSink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	recPriv, _ := sinkKeys(t)
	ev := "{\"user\":\"u-81\"}\n"
	if code, out, errs := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: exit %d\n%s%s", code, out, errs)
	}
	code, _, errs := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user", "--record-key", recPriv)
	if code != exitUsage || !strings.Contains(errs, "cannot start signing") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
}

// #11, #12: a group-readable record key, and one key given as both checkpoint
// and record trust, are warned about.
func TestSink_RecordKeyWarnings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	recPriv, recPub := sinkKeys(t)
	if err := os.Chmod(recPriv, 0o640); err != nil {
		t.Fatal(err)
	}
	ev := "{\"user\":\"u-81\"}\n"
	code, _, errs := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user", "--record-key", recPriv)
	if code != exitOK || !strings.Contains(errs, "readable by others") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	_, _, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", recPub, "--record-trust", recPub)
	if !strings.Contains(errs, "same key is given for checkpoints") {
		t.Fatalf("no same-key warning:\n%s", errs)
	}
}
