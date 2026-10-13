// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

// seedV3Chain writes n linked v3 entries to chainID in the database at dbPath,
// a batch at a time, and returns nothing: the chain is the fixture.
func seedV3Chain(t *testing.T, dbPath, chainID string, n int) {
	t.Helper()
	s, err := boltstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	content := strings.Repeat("0123456789abcdef", 8)
	prev := ""
	const batch = 20_000
	rows := make([]store.Entry, 0, batch)
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e := store.Entry{
			ChainID: chainID, EntryID: fmt.Sprintf("ent_%07d", i), EntryType: "capture.request.v3",
			FormatVersion: chainformat.FormatV3, GlobalSeq: int64(i), Timestamp: ts,
			ContentHash: content, PreviousHash: prev,
		}
		e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, content)
		prev = e.ChainHash
		rows = append(rows, e)
		if len(rows) == batch || i == n-1 {
			if err := s.WriteBatch(context.Background(), rows); err != nil {
				t.Fatalf("write: %v", err)
			}
			rows = rows[:0]
		}
	}
}

// TestExport_AMistypedDatabaseIsAnErrorAndCreatesNothing: export only reads.
// It used to open the database for writing, so a --db that named nothing was
// created, and the command printed `[]` and exited 0.
func TestExport_AMistypedDatabaseIsAnErrorAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "chian.db")
	out := filepath.Join(dir, "out.json")

	code, stdout, stderr := capture(t, "export", "--db", missing, "--chain", testChainID)
	if code != exitIOError {
		t.Errorf("exit %d, want %d (stderr: %s)", code, exitIOError, stderr)
	}
	if stdout != "" {
		t.Errorf("export of a database that is not there printed: %q", stdout)
	}
	if code, _, _ := capture(t, "export", "--db", missing, "--chain", testChainID, "--out", out); code != exitIOError {
		t.Errorf("with --out: exit %d, want %d", code, exitIOError)
	}
	for _, p := range []string{missing, out} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s was created", filepath.Base(p))
		}
	}
	assertOnlyFiles(t, dir)
}

// TestExport_AChainThatIsNotThereIsAnError, not an empty file and exit 0: a
// mistyped --chain looked like a chain with nothing in it.
func TestExport_AChainThatIsNotThereIsAnError(t *testing.T) {
	dbPath := seedChain(t, 3)
	out := filepath.Join(t.TempDir(), "out.json")
	for _, extra := range [][]string{nil, {"--jsonl"}, {"--out", out}} {
		args := append([]string{"export", "--db", dbPath, "--chain", "no-such-chain"}, extra...)
		code, stdout, stderr := capture(t, args...)
		if code != exitIOError {
			t.Errorf("%v: exit %d, want %d", extra, code, exitIOError)
		}
		if stdout != "" {
			t.Errorf("%v: printed %q", extra, stdout)
		}
		if !strings.Contains(stderr, "no entries") || !strings.Contains(stderr, "no-such-chain") {
			t.Errorf("%v: the error does not say the chain has no entries: %q", extra, stderr)
		}
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Error("an output file was left for a chain that is not there")
	}
}

// TestExport_DoesNotChangeTheDatabase: every open used to run a write
// transaction, so an export changed the file it read and failed on read-only
// media. The bytes are the same afterwards, and a read-only file exports.
func TestExport_DoesNotChangeTheDatabase(t *testing.T) {
	dbPath := seedChain(t, 5)
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o400); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := capture(t, "export", "--db", dbPath, "--chain", testChainID, "--jsonl")
	if code != exitOK || strings.Count(stdout, "\n") != 5 {
		t.Fatalf("export of a read-only database: exit %d, %d lines: %s", code, strings.Count(stdout, "\n"), stderr)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("export changed the database file")
	}
}

// TestExport_OutIsNotOverwrittenWithoutForce: --out used to truncate whatever
// was there. An existing file, or a symlink, is now refused before anything is
// read; --force replaces it, and replaces a symlink itself, not its target.
func TestExport_OutIsNotOverwrittenWithoutForce(t *testing.T) {
	dbPath := seedChain(t, 3)
	dir := t.TempDir()
	out := filepath.Join(dir, "entries.json")
	if err := os.WriteFile(out, []byte("an earlier export"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", out)
	if code != exitUsage || !strings.Contains(stderr, "--force") {
		t.Fatalf("exit %d, want %d and a mention of --force: %s", code, exitUsage, stderr)
	}
	if got, _ := os.ReadFile(out); string(got) != "an earlier export" {
		t.Fatalf("the refused export changed the file: %q", got)
	}

	if code, _, stderr := capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", out, "--force"); code != exitOK {
		t.Fatalf("--force: exit %d: %s", code, stderr)
	}
	if code, stdout, _ := capture(t, "verify", out); code != exitOK {
		t.Errorf("the file --force wrote does not verify:\n%s", stdout)
	}

	// A symlink at --out: refused, and with --force replaced, never followed.
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", link); code != exitUsage {
		t.Errorf("a symlink at --out: exit %d, want %d", code, exitUsage)
	}
	if code, _, stderr := capture(t, "export", "--db", dbPath, "--chain", testChainID, "--out", link, "--force"); code != exitOK {
		t.Fatalf("--force over a symlink: exit %d: %s", code, stderr)
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Error("the export was written through the symlink")
	}
	if info, err := os.Lstat(link); err != nil || !info.Mode().IsRegular() {
		t.Error("--force did not replace the symlink with the export")
	}

	// A failed export leaves the file that was there, whole.
	if code, _, _ := capture(t, "export", "--db", dbPath, "--chain", "no-such-chain", "--out", out, "--force"); code != exitIOError {
		t.Errorf("unknown chain with --force: exit %d", code)
	}
	if code, _, _ := capture(t, "verify", out); code != exitOK {
		t.Error("a failed --force export damaged the file it would have replaced")
	}
	assertOnlyFiles(t, dir, "entries.json", "link.json")
}

// assertOnlyFiles checks dir holds exactly the named files: nothing was
// created by mistake and no temp file was left.
func assertOnlyFiles(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s holds %v, want %v", dir, got, want)
	}
}

// TestExport_StreamedBytesAreTheOnesTheEncoderWrote: export writes a page at a
// time, and the file is byte for byte what encoding the whole chain at once
// produced, around every page boundary.
func TestExport_StreamedBytesAreTheOnesTheEncoderWrote(t *testing.T) {
	for _, n := range []int{1, 2, exportPage - 1, exportPage, exportPage + 1, 2*exportPage + 3} {
		dbPath := filepath.Join(t.TempDir(), "chain.db")
		seedV3Chain(t, dbPath, "c", n)
		entries, err := readChain(dbPath, "c")
		if err != nil || len(entries) != n {
			t.Fatalf("n=%d: read %d entries, %v", n, len(entries), err)
		}

		var array, jsonl bytes.Buffer
		enc := json.NewEncoder(&array)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			t.Fatal(err)
		}
		lineEnc := json.NewEncoder(&jsonl)
		for _, e := range entries {
			if err := lineEnc.Encode(e); err != nil {
				t.Fatal(err)
			}
		}

		if _, got, _ := capture(t, "export", "--db", dbPath, "--chain", "c"); got != array.String() {
			t.Errorf("n=%d: the JSON array differs from the encoder's", n)
		}
		if _, got, _ := capture(t, "export", "--db", dbPath, "--chain", "c", "--jsonl"); got != jsonl.String() {
			t.Errorf("n=%d: the JSONL differs from the encoder's", n)
		}
	}
}

// peakHeld runs fn and returns the most heap fn HELD at any sample taken
// while it ran, above what was held before it started.
//
// Each sample collects first, so it counts what is still reachable and not
// garbage waiting for the collector: the figure does not depend on how the
// collector happened to pace itself, only on what the code under test keeps.
func peakHeld(fn func()) uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	base, peak := m.HeapAlloc, m.HeapAlloc

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				var s runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&s)
				if s.HeapAlloc > peak {
					peak = s.HeapAlloc
				}
			}
		}
	}()
	fn()
	close(stop)
	wg.Wait()
	if peak < base {
		return 0
	}
	return peak - base
}

// TestExportAndVerify_MemoryDoesNotGrowWithTheChain: 100,000 entries are
// exported, anchored and then verified against the anchor, and the heap in
// use never comes near the size of the data. Each verb used to hold the whole
// chain: the file, every decoded entry, and for export and anchor every row.
func TestExportAndVerify_MemoryDoesNotGrowWithTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 100,000-entry chain")
	}
	const n = 100_000
	f := newAnchorFixture(t, 1)
	seedV3Chain(t, f.db, "long", n)
	exported := filepath.Join(f.dir, "long.jsonl")

	var code int
	var stderr string
	exportPeak := peakHeld(func() {
		code, _, stderr = capture(t, "export", "--db", f.db, "--chain", "long", "--jsonl", "--out", exported)
	})
	if code != exitOK {
		t.Fatalf("export: exit %d: %s", code, stderr)
	}
	info, err := os.Stat(exported)
	if err != nil {
		t.Fatal(err)
	}
	size := uint64(info.Size())

	anchorPath := filepath.Join(f.dir, "long-anchor.json")
	anchorPeak := peakHeld(func() {
		code, _, stderr = runAnchor(t, "--db", f.db, "--chain", "long", "--subject", "acct-7f3a",
			"--key", f.key, "--out", anchorPath)
	})
	if code != exitOK {
		t.Fatalf("anchor: exit %d: %s", code, stderr)
	}

	var stdout string
	verifyPeak := peakHeld(func() {
		code, stdout, stderr = capture(t, "verify", exported, "--anchor", anchorPath)
	})
	if code != exitOK || !strings.Contains(stdout, fmt.Sprintf("INTACT, ANCHORED — %d entries", n)) ||
		!strings.Contains(stdout, "ANCHOR BOUND") {
		t.Fatalf("verify: exit %d\n%s%s", code, stdout, stderr)
	}

	t.Logf("%d entries, %d bytes exported: held at most %d bytes in export, %d in anchor, %d in verify",
		n, size, exportPeak, anchorPeak, verifyPeak)
	// Holding the chain costs more than its size; streaming costs a few
	// megabytes whatever its size. A twentieth of the data separates the two
	// with room on both sides.
	if limit := size / 20; exportPeak > limit || anchorPeak > limit || verifyPeak > limit {
		t.Errorf("held %d bytes (export), %d (anchor) and %d (verify) over %d bytes of data; "+
			"want each under %d", exportPeak, anchorPeak, verifyPeak, size, limit)
	}
}

// TestUsage_StatesTheExitCodesAndForce: the usage text is where a script's
// author reads the exit codes, busy among them.
func TestUsage_StatesTheExitCodesAndForce(t *testing.T) {
	code, stdout, _ := capture(t, "help")
	if code != exitOK {
		t.Fatalf("help exited %d", code)
	}
	for _, want := range []string{
		"0 ok · 1 chain broken · 2 usage · 3 io error · 4 chain busy",
		"[--out <path>] [--jsonl] [--force]",
		"[--previous <anchor.json>] [--out <path>] [--force]",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the usage text does not contain %q", want)
		}
	}
	if exitBusy != 4 {
		t.Errorf("exitBusy = %d; the usage text says 4", exitBusy)
	}
}
