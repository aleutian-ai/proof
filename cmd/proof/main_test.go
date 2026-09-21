// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

const testChainID = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"

// capture runs the CLI with stdout and stderr redirected to temp files.
//
// The commands take *os.File rather than io.Writer so they can be handed the
// real os.Stdout in production without wrapping; the cost is that tests must
// give them files too.
func capture(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()

	outF, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	errF, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("temp stderr: %v", err)
	}
	code = run(args, outF, errF)
	outF.Close()
	errF.Close()

	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return code, string(o), string(e)
}

// seedChain writes n linked entries into a fresh database and returns its path.
func seedChain(t *testing.T, n int) string {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "chain.db")
	s, err := boltstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Date(2026, 1, 20, 12, 0, 0, 123456000, time.UTC)
	entries := make([]store.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)

		chainHash, err := chainformat.ComputeChainHash(prev, "run_cli", int64(i), ts, contentHash)
		if err != nil {
			t.Fatalf("link entry %d: %v", i, err)
		}
		entries = append(entries, store.Entry{
			ChainID: testChainID, EntryID: "entry_" + hex.EncodeToString([]byte{byte(i)}),
			EntryType: "request", GlobalSeq: int64(i), RunID: "run_cli",
			SequenceNum: int64(i), Timestamp: ts, ContentHash: contentHash,
			PreviousHash: prev, ChainHash: chainHash,
		})
		prev = chainHash
	}
	if err := s.WriteBatch(context.Background(), entries); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dbPath
}

// TestCLI_InitExportVerify is the round trip the CLI exists for.
func TestCLI_InitExportVerify(t *testing.T) {
	dbPath := seedChain(t, 5)
	outPath := filepath.Join(t.TempDir(), "entries.json")

	if code, _, stderr := capture(t, "export", "--db", dbPath,
		"--chain", testChainID, "--out", outPath); code != exitOK {
		t.Fatalf("export exited %d: %s", code, stderr)
	}
	code, stdout, stderr := capture(t, "verify", outPath)
	if code != exitOK {
		t.Fatalf("verify exited %d: %s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "INTACT") {
		t.Errorf("verify did not report INTACT:\n%s", stdout)
	}
}

// TestCLI_VerdictStatesWhatIsNotProven is the honesty check.
//
// A user reading "INTACT" will assume the chain is complete unless told
// otherwise. If this assertion is ever removed, the tool starts overclaiming.
func TestCLI_VerdictStatesWhatIsNotProven(t *testing.T) {
	dbPath := seedChain(t, 3)
	outPath := filepath.Join(t.TempDir(), "entries.json")
	capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", outPath)

	_, stdout, _ := capture(t, "verify", outPath)
	for _, want := range []string{"NOT proven", "anchor"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("an INTACT verdict must say what it does NOT prove; missing %q:\n%s",
				want, stdout)
		}
	}
}

// TestCLI_DetectsTampering asserts a broken chain exits 1, not 0 and not 3.
func TestCLI_DetectsTampering(t *testing.T) {
	dbPath := seedChain(t, 5)
	outPath := filepath.Join(t.TempDir(), "entries.json")
	capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", outPath)

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var entries []verify.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	entries[2].ContentHash = strings.Repeat("f", 128)
	tampered, _ := json.Marshal(entries)
	if err := os.WriteFile(outPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	code, stdout, _ := capture(t, "verify", outPath)
	if code != exitBroken {
		t.Fatalf("tampered chain exited %d, want %d", code, exitBroken)
	}
	if !strings.Contains(stdout, "first break at entry 2") {
		t.Errorf("verify did not point at entry 2:\n%s", stdout)
	}
}

// TestCLI_ErasedEntryIsNotABreak covers the case that shipped broken in three
// SDKs: a chain containing a tombstone must verify as INTACT.
func TestCLI_ErasedEntryIsNotABreak(t *testing.T) {
	dbPath := seedChain(t, 4)
	outPath := filepath.Join(t.TempDir(), "entries.json")
	capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", outPath)

	raw, _ := os.ReadFile(outPath)
	var entries []verify.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse export: %v", err)
	}

	// Erase entry 1 the producer's way: content replaced, chain hash PRESERVED.
	tombstoneHash, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("generate tombstone: %v", err)
	}
	entries[1].EntryType = chainformat.TombstoneEntryType
	entries[1].EntryID = chainformat.TombstoneEntryIDPrefix + "550e8400-e29b-41d4-a716-446655440000"
	entries[1].ContentHash = tombstoneHash

	erased, _ := json.Marshal(entries)
	os.WriteFile(outPath, erased, 0o600)

	code, stdout, _ := capture(t, "verify", outPath)
	if code != exitOK {
		t.Fatalf("a lawfully erased entry made verify exit %d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "1 erased") {
		t.Errorf("verify did not report the erasure:\n%s", stdout)
	}
}

// TestCLI_ExportTimestampRoundTripsThroughTheHash is the precision check.
//
// Export renders the timestamp as text. If that text is not the exact form the
// hash was computed over, a verifier re-parsing it computes a different hash —
// so this re-derives the chain hash from the EXPORTED strings rather than
// comparing timestamps.
func TestCLI_ExportTimestampRoundTripsThroughTheHash(t *testing.T) {
	dbPath := seedChain(t, 3)
	outPath := filepath.Join(t.TempDir(), "entries.json")
	capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", outPath)

	raw, _ := os.ReadFile(outPath)
	var entries []verify.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse export: %v", err)
	}

	prev := ""
	for i, e := range entries {
		ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			t.Fatalf("entry %d: exported timestamp %q is not RFC3339: %v", i, e.Timestamp, err)
		}
		got := chainformat.ComputeChainHashUnchecked(prev, e.RunID, e.SequenceNum, ts, e.ContentHash)
		if got != e.ChainHash {
			t.Fatalf("entry %d: chain hash could not be re-derived from the export.\n"+
				"  exported timestamp: %s\n  stored hash:  %s\n  re-derived:   %s\n"+
				"The export almost certainly lost timestamp precision.",
				i, e.Timestamp, e.ChainHash, got)
		}
		prev = got
	}
}

// TestCLI_ExportJSONLIsAlsoVerifiable pins that both output shapes round-trip.
func TestCLI_ExportJSONLIsAlsoVerifiable(t *testing.T) {
	dbPath := seedChain(t, 4)
	outPath := filepath.Join(t.TempDir(), "entries.jsonl")

	if code, _, stderr := capture(t, "export", "--db", dbPath, "--chain", testChainID,
		"--out", outPath, "--jsonl"); code != exitOK {
		t.Fatalf("export --jsonl exited %d: %s", code, stderr)
	}
	raw, _ := os.ReadFile(outPath)
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		t.Fatal("--jsonl emitted a JSON array")
	}
	if code, stdout, _ := capture(t, "verify", outPath); code != exitOK {
		t.Fatalf("verify of a JSONL export exited %d:\n%s", code, stdout)
	}
}

// TestCLI_ExitCodesAreDistinct asserts a broken chain and an unreadable file are
// reported differently.
//
// A script that cannot tell "the chain is broken" from "I could not open the
// file" will take the wrong action on one of them.
func TestCLI_ExitCodesAreDistinct(t *testing.T) {
	if code, _, _ := capture(t, "verify", filepath.Join(t.TempDir(), "nope.json")); code != exitIOError {
		t.Errorf("verify of a missing file exited %d, want %d", code, exitIOError)
	}
	if code, _, _ := capture(t, "verify"); code != exitUsage {
		t.Errorf("verify with no argument exited %d, want %d", code, exitUsage)
	}
	if code, _, _ := capture(t, "frobnicate"); code != exitUsage {
		t.Errorf("an unknown command exited %d, want %d", code, exitUsage)
	}

	empty := filepath.Join(t.TempDir(), "empty.json")
	os.WriteFile(empty, []byte("  \n"), 0o600)
	if code, _, _ := capture(t, "verify", empty); code != exitIOError {
		t.Errorf("verify of an empty file exited %d, want %d", code, exitIOError)
	}
}

// TestCLI_InitRefusesToOverwrite pins that init cannot destroy an existing chain.
func TestCLI_InitRefusesToOverwrite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chain.db")

	if code, _, stderr := capture(t, "init", "--db", dbPath); code != exitOK {
		t.Fatalf("init exited %d: %s", code, stderr)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("init did not create the database: %v", err)
	}
	code, _, stderr := capture(t, "init", "--db", dbPath)
	if code == exitOK {
		t.Fatal("init overwrote an existing database")
	}
	if !strings.Contains(stderr, "refusing") {
		t.Errorf("init should explain why it refused:\n%s", stderr)
	}
}
