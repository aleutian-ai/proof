// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// withStdin runs fn with os.Stdin replaced by the given content.
//
// The verbs read stdin directly, which is the right shape for a pipe-oriented
// CLI; this is how a test drives them without a subprocess.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	saved := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = saved; f.Close() }()
	fn()
}

// runWithStdin executes a verb with piped stdin, capturing both streams.
func runWithStdin(t *testing.T, stdin string, verb func([]string, *os.File, *os.File) int,
	args ...string) (code int, stdout, stderr string) {
	t.Helper()
	outF, _ := os.CreateTemp(t.TempDir(), "out")
	errF, _ := os.CreateTemp(t.TempDir(), "err")
	withStdin(t, stdin, func() { code = verb(args, outF, errF) })
	outF.Close()
	errF.Close()
	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return code, string(o), string(e)
}

// commitLines builds append-input JSONL for n entries.
func commitLines(t *testing.T, n, startAt int) string {
	t.Helper()
	base := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := startAt; i < startAt+n; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		line, err := json.Marshal(commitInput{
			EntryID:     fmt.Sprintf("ent_%03d", i),
			EntryType:   "capture.request.v3",
			Timestamp:   ts.Format(time.RFC3339Nano),
			ContentHash: strings.Repeat("0123456789abcdef", 8),
			IngestedAt:  ts.Add(time.Second).Format(time.RFC3339Nano),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func newDB(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name+".db")
}

// exportChain runs `proof export` and returns its bytes.
func exportChain(t *testing.T, db, chainID string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "export.jsonl")
	outF, _ := os.CreateTemp(t.TempDir(), "o")
	errF, _ := os.CreateTemp(t.TempDir(), "e")
	code := cmdExport([]string{"--db", db, "--chain", chainID, "--out", out, "--jsonl"}, outF, errF)
	outF.Close()
	errF.Close()
	if code != exitOK {
		e, _ := os.ReadFile(errF.Name())
		t.Fatalf("export exit %d: %s", code, e)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	return string(raw)
}

// storedRows counts a chain's rows in a database, reading the store itself. A
// database that was never created holds none.
//
// `proof export` used to answer this: it created a missing database and
// printed nothing for a chain that was not there. It now refuses both, so a
// test that means "nothing was written" asks the store.
func storedRows(t *testing.T, db, chainID string) int {
	t.Helper()
	if _, err := os.Lstat(db); os.IsNotExist(err) {
		return 0
	}
	s, err := boltstore.Open(db, boltstore.WithReadOnly())
	if err != nil {
		t.Fatalf("open %s: %v", db, err)
	}
	defer s.Close()
	rows, err := s.Range(context.Background(), chainID, 0, 1<<62, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	return len(rows)
}

// TestCommit_ThenVerifyIsIntact is the minimum bar: what append writes, verify
// accepts.
func TestCommit_ThenVerifyIsIntact(t *testing.T) {
	db := newDB(t, "a")
	code, out, stderr := runWithStdin(t, commitLines(t, 4, 0), cmdCommit, "--db", db, "--chain", "c")
	if code != exitOK {
		t.Fatalf("append exit %d: %s", code, stderr)
	}
	var res struct {
		Committed int    `json:"committed"`
		LastSeq   int64  `json:"last_seq"`
		RunID     string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("append output is not JSON: %v\n%s", err, out)
	}
	if res.Committed != 4 || res.LastSeq != 3 {
		t.Errorf("committed=%d last_seq=%d, want 4/3", res.Committed, res.LastSeq)
	}
	if res.RunID != "" {
		t.Errorf("v3 must not mint a run id, got %q", res.RunID)
	}

	entriesPath := filepath.Join(t.TempDir(), "e.jsonl")
	if err := os.WriteFile(entriesPath, []byte(exportChain(t, db, "c")), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code, vout, _ := runVerify(t, entriesPath); code != exitOK || !strings.Contains(vout, "INTACT") {
		t.Errorf("verify after append: exit %d\n%s", code, vout)
	}
}

// TestCommit_IsBatchIndependent pins v3's whole reason for existing, at the CLI
// level: two appends and one append of the concatenation must produce the same
// chain. Under --format-v2 they must NOT, since v2 binds the batch.
func TestCommit_IsBatchIndependent(t *testing.T) {
	split := func(t *testing.T, flags ...string) string {
		db := newDB(t, "split")
		for _, chunk := range []string{commitLines(t, 2, 0), commitLines(t, 2, 2)} {
			args := append([]string{"--db", db, "--chain", "c"}, flags...)
			if code, _, e := runWithStdin(t, chunk, cmdCommit, args...); code != exitOK {
				t.Fatalf("append: %s", e)
			}
		}
		return exportChain(t, db, "c")
	}
	single := func(t *testing.T, flags ...string) string {
		db := newDB(t, "single")
		args := append([]string{"--db", db, "--chain", "c"}, flags...)
		if code, _, e := runWithStdin(t, commitLines(t, 4, 0), cmdCommit, args...); code != exitOK {
			t.Fatalf("append: %s", e)
		}
		return exportChain(t, db, "c")
	}

	t.Run("v3 is batch-independent", func(t *testing.T) {
		if split(t) != single(t) {
			t.Error("two appends and one append produced different v3 chains; " +
				"v3 exists precisely so they do not")
		}
	})

	t.Run("v2 is NOT, and that is why v3 exists", func(t *testing.T) {
		if split(t, "--format-v2") == single(t, "--format-v2") {
			t.Error("v2 appears batch-independent; it binds run_id and a batch-local " +
				"sequence, so this test is no longer proving the difference")
		}
	})
}

// TestCommit_RejectsMintedFields: silently dropping a field the caller thought
// mattered is how someone ends up believing their hashes were preserved.
func TestCommit_RejectsMintedFields(t *testing.T) {
	for _, field := range mintedFields {
		t.Run(field, func(t *testing.T) {
			line := fmt.Sprintf(`{"entry_id":"e","entry_type":"t","timestamp":"2026-09-25T09:00:00Z",`+
				`"content_hash":"%s","ingested_at":"2026-09-25T09:00:01Z","%s":"x"}`,
				strings.Repeat("ab", 64), field)
			code, _, stderr := runWithStdin(t, line, cmdCommit, "--db", newDB(t, "m"), "--chain", "c")
			if code != exitUsage {
				t.Fatalf("exit %d, want usage", code)
			}
			if !strings.Contains(stderr, field) || !strings.Contains(stderr, "proof import") {
				t.Errorf("the refusal does not name the field or point at import: %q", stderr)
			}
		})
	}
}

// TestCommit_RejectsBadLinesByNumber, committing nothing.
func TestCommit_RejectsBadLinesByNumber(t *testing.T) {
	good := strings.TrimSpace(commitLines(t, 1, 0))
	cases := map[string]string{
		"malformed JSON":      good + "\n{not json\n",
		"missing ingested_at": good + "\n" + `{"entry_id":"e2","entry_type":"t","timestamp":"2026-09-25T09:00:00Z","content_hash":"` + strings.Repeat("ab", 64) + `"}` + "\n",
		"bad timestamp":       good + "\n" + `{"entry_id":"e2","entry_type":"t","timestamp":"yesterday","content_hash":"` + strings.Repeat("ab", 64) + `","ingested_at":"2026-09-25T09:00:01Z"}` + "\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			db := newDB(t, "bad")
			code, _, stderr := runWithStdin(t, input, cmdCommit, "--db", db, "--chain", "c")
			if code != exitUsage {
				t.Fatalf("exit %d, want usage", code)
			}
			if !strings.Contains(stderr, "line 2") {
				t.Errorf("the error does not name line 2: %q", stderr)
			}
			// time.Parse("") fails on its own, so asserting only "an error
			// happened" passes with the ingested_at guard deleted — a mutation
			// proved it. What the guard buys is a message saying WHY the field
			// matters, which is what stops someone reaching for the event
			// timestamp instead.
			if name == "missing ingested_at" && !strings.Contains(stderr, "orders the batch") {
				t.Errorf("the refusal does not explain what ingested_at is for: %q", stderr)
			}
			// Nothing committed: the good first line must not be there either.
			if n := storedRows(t, db, "c"); n != 0 {
				t.Errorf("a rejected batch left %d entries behind", n)
			}
		})
	}
}

// TestImport_RoundTripIsByteIdentical is the verb's contract: export → import →
// export must not change a byte, for v3 AND v2, since the field sets differ.
func TestImport_RoundTripIsByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
	}{
		{"v3", nil},
		{"v2", []string{"--format-v2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newDB(t, "src")
			args := append([]string{"--db", src, "--chain", "c"}, tc.flags...)
			if code, _, e := runWithStdin(t, commitLines(t, 5, 0), cmdCommit, args...); code != exitOK {
				t.Fatalf("append: %s", e)
			}
			exported := exportChain(t, src, "c")

			dst := newDB(t, "dst")
			code, out, stderr := runWithStdin(t, exported, cmdImport, "--db", dst, "--chain", "c")
			if code != exitOK {
				t.Fatalf("import exit %d: %s", code, stderr)
			}
			if !strings.Contains(out, "imported 5 entries") {
				t.Errorf("unexpected import summary: %q", out)
			}

			if got := exportChain(t, dst, "c"); got != exported {
				t.Errorf("round trip changed the bytes\n--- original ---\n%s\n--- after ---\n%s",
					exported, got)
			}
		})
	}
}

// TestImport_PreservesNumberingThatDoesNotStartAtZero is the case that proves
// the linker is correctly bypassed: re-linking would renumber from the target's
// tail, and v3 binds global_seq, so the hashes would change.
func TestImport_PreservesNumberingThatDoesNotStartAtZero(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 6, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	full := strings.Split(strings.TrimSpace(exportChain(t, src, "c")), "\n")
	tailSegment := strings.Join(full[3:], "\n") + "\n" // seq 3..5

	// A segment links from its predecessor, not from nothing. Without this the
	// verifier walks from an empty previous hash and reports a break on the
	// first entry of a perfectly good segment.
	var predecessor struct {
		ChainHash string `json:"chain_hash"`
	}
	if err := json.Unmarshal([]byte(full[2]), &predecessor); err != nil {
		t.Fatalf("unmarshal predecessor: %v", err)
	}

	dst := newDB(t, "dst")
	code, out, stderr := runWithStdin(t, tailSegment, cmdImport,
		"--db", dst, "--chain", "c", "--previous-hash", predecessor.ChainHash)
	if code != exitOK {
		t.Fatalf("import exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "seq 3..5") {
		t.Errorf("numbering was not preserved: %q", out)
	}
	if got := exportChain(t, dst, "c"); got != tailSegment {
		t.Errorf("the imported segment changed:\n%s", got)
	}

	// And without the predecessor it must be REFUSED, with an explanation that
	// points at the missing flag rather than at an imaginary attacker.
	code, _, stderr = runWithStdin(t, tailSegment, cmdImport,
		"--db", newDB(t, "nope"), "--chain", "c")
	if code != exitBroken {
		t.Errorf("a segment imported without its predecessor: exit %d", code)
	}
	if !strings.Contains(stderr, "--previous-hash") || !strings.Contains(stderr, "SEGMENT") {
		t.Errorf("the refusal does not explain that this is a segment: %q", stderr)
	}
}

// TestImport_RefusesAnOccupiedRange is the safety of the verb. bolt REPLACES an
// entry at an occupied GlobalSeq by design, and the damaged chain would still
// verify, because the survivors stay consistent with each other.
func TestImport_RefusesAnOccupiedRange(t *testing.T) {
	db := newDB(t, "occupied")
	if code, _, e := runWithStdin(t, commitLines(t, 4, 0), cmdCommit, "--db", db, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	before := exportChain(t, db, "c")

	// A DIFFERENT chain occupying the same sequence numbers.
	other := newDB(t, "other")
	if code, _, e := runWithStdin(t, commitLines(t, 4, 100), cmdCommit, "--db", other, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}

	code, _, stderr := runWithStdin(t, exportChain(t, other, "c"), cmdImport, "--db", db, "--chain", "c")
	if code == exitOK {
		t.Fatal("imported into an occupied range; entries were silently replaced")
	}
	if !strings.Contains(stderr, "already occupied") {
		t.Errorf("the refusal does not explain the conflict: %q", stderr)
	}
	if after := exportChain(t, db, "c"); after != before {
		t.Error("the refused import still modified the chain")
	}
}

// TestImport_RefusesABrokenChain: a broken chain is not stored "for later" —
// once written it is indistinguishable from one that broke in place.
func TestImport_RefusesABrokenChain(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 4, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	lines := strings.Split(strings.TrimSpace(exportChain(t, src, "c")), "\n")

	var e2 map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &e2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	e2["content_hash"] = strings.Repeat("ff", 64)
	tampered, _ := json.Marshal(e2)
	lines[2] = string(tampered)

	dst := newDB(t, "dst")
	code, _, stderr := runWithStdin(t, strings.Join(lines, "\n")+"\n", cmdImport, "--db", dst, "--chain", "c")
	if code != exitBroken {
		t.Fatalf("exit %d, want %d", code, exitBroken)
	}
	if !strings.Contains(stderr, "refusing to import a broken chain") {
		t.Errorf("unexpected error: %q", stderr)
	}
	if n := storedRows(t, dst, "c"); n != 0 {
		t.Errorf("a refused import wrote %d entries anyway", n)
	}
}

// TestImport_AcceptsBothInputShapes, the same sniffing `verify` does.
func TestImport_AcceptsBothInputShapes(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 3, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	jsonl := exportChain(t, src, "c")

	// The same entries as a JSON array.
	var arr []json.RawMessage
	for _, l := range strings.Split(strings.TrimSpace(jsonl), "\n") {
		arr = append(arr, json.RawMessage(l))
	}
	asArray, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for name, input := range map[string]string{"jsonl": jsonl, "json array": string(asArray)} {
		t.Run(name, func(t *testing.T) {
			dst := newDB(t, "dst")
			if code, _, stderr := runWithStdin(t, input, cmdImport, "--db", dst, "--chain", "c"); code != exitOK {
				t.Fatalf("import exit %d: %s", code, stderr)
			}
			if got := exportChain(t, dst, "c"); got != jsonl {
				t.Errorf("the %s import did not round trip", name)
			}
		})
	}
}

// TestCommitImport_RequireTheirArguments.
func TestCommitImport_RequireTheirArguments(t *testing.T) {
	for name, verb := range map[string]func([]string, *os.File, *os.File) int{
		"commit": cmdCommit, "import": cmdImport,
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := runWithStdin(t, "", verb, "--chain", "c"); code != exitUsage {
				t.Errorf("missing --db: exit %d, want usage", code)
			}
			if code, _, _ := runWithStdin(t, "", verb, "--db", newDB(t, "x")); code != exitUsage {
				t.Errorf("missing --chain: exit %d, want usage", code)
			}
			if code, _, stderr := runWithStdin(t, "", verb, "--db", newDB(t, "y"), "--chain", "c"); code != exitUsage {
				t.Errorf("empty stdin: exit %d, want usage (stderr: %s)", code, stderr)
			}
		})
	}
}

// TestImport_SetsPreviousHash reads the STORE, not the export.
//
// PreviousHash is descriptive — neither format hashes it, and `proof export`
// does not emit it — so the round-trip test cannot see it and a mutation
// leaving it empty survived. A store that recorded it empty for every entry
// would misreport the chain's shape to anything reading rows directly.
func TestImport_SetsPreviousHash(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 3, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	dst := newDB(t, "dst")
	if code, _, e := runWithStdin(t, exportChain(t, src, "c"), cmdImport, "--db", dst, "--chain", "c"); code != exitOK {
		t.Fatalf("import: %s", e)
	}

	s, err := boltstore.Open(dst)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	rows, err := s.Range(context.Background(), "c", 0, 1<<62, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].PreviousHash != "" {
		t.Errorf("the first entry has a previous hash: %q", rows[0].PreviousHash)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].PreviousHash != rows[i-1].ChainHash {
			t.Errorf("entry %d's previous hash does not point at its predecessor", i)
		}
	}
}

// TestVerbs_LockedDatabaseExitsBusyRatherThanHanging is the regression test for
// a verb that hung on a locked database.
//
// Before the fix, boltstore.Open passed no Timeout, so bbolt waited on its
// exclusive file lock FOREVER. A verb run against a database another process
// had open produced no output, no error and no exit code — it simply hung, with
// nothing to indicate a lock was the cause. Writing this very test is what
// exposed it: the test hung too.
//
// The bound is what makes exitBusy reachable at all from the CLI.
func TestVerbs_LockedDatabaseExitsBusyRatherThanHanging(t *testing.T) {
	db := newDB(t, "locked")

	// Seed it, then hold the lock the way a concurrent process would.
	if code, _, e := runWithStdin(t, commitLines(t, 2, 0), cmdCommit, "--db", db, "--chain", "c"); code != exitOK {
		t.Fatalf("seed append: %s", e)
	}
	// Import needs EXPORTED shape, not append-input shape, or it fails at
	// verification before ever reaching the store — which would make this test
	// pass for the wrong reason.
	exported := exportChain(t, db, "c")

	holder, err := boltstore.Open(db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer holder.Close()

	// A short timeout so the test is quick; the DEFAULT is what ships.
	verbs := map[string]struct {
		verb  func([]string, *os.File, *os.File) int
		stdin string
	}{
		"commit": {cmdCommit, commitLines(t, 1, 9)},
		"import": {cmdImport, exported},
	}
	for name, tc := range verbs {
		t.Run(name, func(t *testing.T) {
			done := make(chan int, 1)
			go func() {
				code, _, _ := runWithStdin(t, tc.stdin, tc.verb, "--db", db, "--chain", "c")
				done <- code
			}()
			select {
			case code := <-done:
				if code != exitBusy {
					t.Errorf("exit %d, want %d (busy)", code, exitBusy)
				}
			case <-time.After(boltstore.DefaultLockTimeout + 10*time.Second):
				t.Fatal("the verb HUNG on a locked database; the lock timeout is not in effect")
			}
		})
	}
}

// TestBoltOpen_LockTimeoutIsConfigurable: a caller that genuinely wants to wait
// can, and the error says what is wrong.
func TestBoltOpen_LockTimeoutIsConfigurable(t *testing.T) {
	db := newDB(t, "cfg")
	holder, err := boltstore.Open(db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer holder.Close()

	start := time.Now()
	_, err = boltstore.Open(db, boltstore.WithLockTimeout(200*time.Millisecond))
	elapsed := time.Since(start)

	if !errors.Is(err, boltstore.ErrLocked) {
		t.Fatalf("got %v, want ErrLocked", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("waited %s despite a 200ms timeout", elapsed)
	}
	// The message must say it is a LOCK, not a corruption or permission problem.
	for _, want := range []string{"another process", "locked"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestPrintResult_DoesNotPanicOnShortHashes is the regression test for a crash
// found while testing something else.
//
// printResult sliced b.Expected[:32] and b.Actual[:32] behind a check on
// Expected ALONE, so a break carrying one side and not the other — or a value
// shorter than 32 characters — panicked. That is `proof verify` crashing while
// describing a broken chain, which is the one path the verb exists for.
func TestPrintResult_DoesNotPanicOnShortHashes(t *testing.T) {
	cases := map[string]verify.Break{
		"both empty":    {Position: 0, Type: verify.BreakUnknownFormat, EntryID: "e"},
		"expected only": {Position: 0, EntryID: "e", Expected: strings.Repeat("a", 128)},
		"actual only":   {Position: 0, EntryID: "e", Actual: strings.Repeat("b", 128)},
		"both short":    {Position: 0, EntryID: "e", Expected: "abc", Actual: "de"},
		"exactly 32":    {Position: 0, EntryID: "e", Expected: strings.Repeat("a", 32), Actual: strings.Repeat("b", 32)},
		"one side 31":   {Position: 0, EntryID: "e", Expected: strings.Repeat("a", 31), Actual: strings.Repeat("b", 128)},
	}
	for name, brk := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "out")
			if err != nil {
				t.Fatalf("temp: %v", err)
			}
			defer f.Close()
			// A panic here fails the test, which is the whole assertion.
			printResult(f, verify.Result{
				Verdict:    verify.VerdictBroken,
				FirstBreak: 0,
				Breaks:     []verify.Break{brk},
			}, false)
		})
	}
}

// TestCommit_AShortContentHashIsAUsageError: a 64-hex content hash (SHA-256,
// where SHA-512 is wanted) is the caller's input being wrong. It was refused
// by the linker after the database had been opened, as an I/O error with no
// line number.
func TestCommit_AShortContentHashIsAUsageError(t *testing.T) {
	good := commitLines(t, 1, 0)
	short := strings.Replace(commitLines(t, 1, 1), strings.Repeat("0123456789abcdef", 8), strings.Repeat("ab", 32), 1)
	db := newDB(t, "short")
	code, _, stderr := runWithStdin(t, good+short, cmdCommit, "--db", db, "--chain", "c")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (usage): %s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "line 2") || !strings.Contains(stderr, "128 lowercase hex") {
		t.Errorf("the error does not name the line and the shape wanted: %q", stderr)
	}
	if _, err := os.Lstat(db); !os.IsNotExist(err) {
		t.Error("a refused commit created the database")
	}
}

// TestCommit_RefusesARepeatedEntryID: an entry id names one entry. Given twice
// on stdin, or once on stdin and already on the chain, the commit is refused
// whole. Piping the same file twice once appended every entry twice.
func TestCommit_RefusesARepeatedEntryID(t *testing.T) {
	t.Run("twice on stdin", func(t *testing.T) {
		db := newDB(t, "twice")
		lines := commitLines(t, 3, 0) + commitLines(t, 1, 1)
		code, _, stderr := runWithStdin(t, lines, cmdCommit, "--db", db, "--chain", "c")
		if code != exitUsage {
			t.Fatalf("exit %d, want %d (usage): %s", code, exitUsage, stderr)
		}
		if !strings.Contains(stderr, "line 4 repeats") || !strings.Contains(stderr, "line 2") {
			t.Errorf("the error does not name both lines: %q", stderr)
		}
		if n := storedRows(t, db, "c"); n != 0 {
			t.Errorf("a refused commit wrote %d entries", n)
		}
	})

	t.Run("already on the chain", func(t *testing.T) {
		db := newDB(t, "held")
		lines := commitLines(t, 3, 0)
		if code, _, e := runWithStdin(t, lines, cmdCommit, "--db", db, "--chain", "c"); code != exitOK {
			t.Fatalf("first commit: %s", e)
		}
		before := exportChain(t, db, "c")

		// The same file again, and a batch in which only the last line is old.
		for name, again := range map[string]string{
			"the same input": lines,
			"one old id":     commitLines(t, 2, 10) + commitLines(t, 1, 2),
		} {
			code, _, stderr := runWithStdin(t, again, cmdCommit, "--db", db, "--chain", "c")
			if code != exitUsage {
				t.Fatalf("%s: exit %d, want %d (usage): %s", name, code, exitUsage, stderr)
			}
			if !strings.Contains(stderr, "already holds entry_id") {
				t.Errorf("%s: the refusal does not say why: %q", name, stderr)
			}
			if after := exportChain(t, db, "c"); after != before {
				t.Errorf("%s: the refused commit changed the chain", name)
			}
		}

		// The same ids on another chain of the same database are that chain's own.
		if code, _, e := runWithStdin(t, lines, cmdCommit, "--db", db, "--chain", "d"); code != exitOK {
			t.Errorf("the same ids on another chain were refused: %s", e)
		}
	})
}

// TestCommit_BoundsStdin: one endless line, or endless input, is refused and
// not read into memory. Nothing is committed.
func TestCommit_BoundsStdin(t *testing.T) {
	two := commitLines(t, 2, 0)
	lineLen := len(strings.SplitAfter(two, "\n")[0])

	if got, err := readAppendInputsBounded(strings.NewReader(two), lineLen, int64(len(two))); err != nil || len(got) != 2 {
		t.Fatalf("input exactly at both bounds: %d entries, %v", len(got), err)
	}
	if _, err := readAppendInputsBounded(strings.NewReader(two), lineLen, int64(len(two))-1); err == nil ||
		!strings.Contains(err.Error(), "stdin is larger than") {
		t.Errorf("input one byte over the total bound: %v", err)
	}
	long := strings.Replace(commitLines(t, 1, 5), `{`, `{"pad":"`+strings.Repeat("x", lineLen)+`",`, 1)
	if _, err := readAppendInputsBounded(strings.NewReader(two+long), lineLen, 1<<20); err == nil ||
		!strings.Contains(err.Error(), "line 3 is longer than") {
		t.Errorf("a line over the line bound: %v", err)
	}
	// Input cut off at the bound in the middle of a line is reported as too
	// large, not as a line that is not JSON.
	if _, err := readAppendInputsBounded(strings.NewReader(two), lineLen, int64(lineLen)+10); err == nil ||
		!strings.Contains(err.Error(), "stdin is larger than") {
		t.Errorf("input cut off inside its second line: %v", err)
	}

	// Through the verb, at the real line bound.
	db := newDB(t, "bounded")
	huge := strings.Replace(commitLines(t, 1, 5), `{`, `{"pad":"`+strings.Repeat("x", commitMaxLine)+`",`, 1)
	code, _, stderr := runWithStdin(t, commitLines(t, 1, 0)+huge, cmdCommit, "--db", db, "--chain", "c")
	if code != exitUsage || !strings.Contains(stderr, "line 2 is longer than") {
		t.Fatalf("exit %d, want %d and the line named: %.200s", code, exitUsage, stderr)
	}
	if len(stderr) > 500 {
		t.Errorf("the error is %d bytes: it carries the line", len(stderr))
	}
	if n := storedRows(t, db, "c"); n != 0 {
		t.Errorf("a refused commit wrote %d entries", n)
	}
}

// TestCommit_BatchesMatchOneAppend: a commit is written in batches, and the
// chain is the one a single Append of the whole input writes. The input is in
// no order and has ties on ingested_at, so the order the batches are cut in
// is the linker's or the hashes differ.
func TestCommit_BatchesMatchOneAppend(t *testing.T) {
	saved := commitBatch
	commitBatch = 7
	defer func() { commitBatch = saved }()

	const n = 50
	base := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	var lines []string
	var inputs []linker.Input
	for i := 0; i < n; i++ {
		// Arrival runs against input order, three entries to an instant.
		ingested := base.Add(time.Duration((n-i)/3) * time.Second)
		ts := base.Add(time.Duration(i) * time.Minute)
		in := commitInput{
			EntryID:     fmt.Sprintf("ent_%03d", (i*37)%n),
			EntryType:   "capture.request.v3",
			Timestamp:   ts.Format(time.RFC3339Nano),
			ContentHash: strings.Repeat(fmt.Sprintf("%02x", i), 64),
			IngestedAt:  ingested.Format(time.RFC3339Nano),
		}
		line, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(line))
		li, err := in.toLinkerInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, li)
	}

	batched := newDB(t, "batched")
	code, out, stderr := runWithStdin(t, strings.Join(lines, "\n")+"\n", cmdCommit, "--db", batched, "--chain", "c")
	if code != exitOK {
		t.Fatalf("commit: exit %d: %s", code, stderr)
	}
	var res struct {
		Committed int    `json:"committed"`
		FirstSeq  int64  `json:"first_seq"`
		LastSeq   int64  `json:"last_seq"`
		HeadHash  string `json:"head_hash"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("result: %v\n%s", err, out)
	}

	single := newDB(t, "single")
	s, err := boltstore.Open(single)
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(s)
	if err != nil {
		t.Fatal(err)
	}
	want, err := l.Append(context.Background(), "c", inputs)
	s.Close()
	if err != nil {
		t.Fatalf("one Append: %v", err)
	}

	if res.Committed != n || res.FirstSeq != 0 || res.LastSeq != n-1 || res.HeadHash != want.HeadHash {
		t.Errorf("result = %+v, want %d entries, seq 0..%d, head %s", res, n, n-1, shortHash(want.HeadHash))
	}
	if got, one := exportChain(t, batched, "c"), exportChain(t, single, "c"); got != one {
		t.Error("the batched commit wrote a different chain from one Append of the same input")
	}

	// v2 binds the run into every hash: one invocation stays one run, however
	// small a batch is.
	v2 := newDB(t, "v2")
	if code, _, e := runWithStdin(t, strings.Join(lines, "\n")+"\n", cmdCommit,
		"--db", v2, "--chain", "c", "--format-v2"); code != exitOK {
		t.Fatalf("v2 commit: %s", e)
	}
	runs := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSpace(exportChain(t, v2, "c")), "\n") {
		var e verify.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		runs[e.RunID] = true
		if e.SequenceNum != int64(i) {
			t.Fatalf("v2 entry %d has sequence_num %d: the run was split", i, e.SequenceNum)
		}
	}
	if len(runs) != 1 {
		t.Errorf("a v2 commit was written as %d runs, want 1", len(runs))
	}
}

// TestImport_StoresThePreviousHashItWasGiven: --previous-hash is what the
// first imported entry links from. It was used to verify the segment and then
// dropped: the first row was stored linking from nothing, as if the segment
// began a chain.
func TestImport_StoresThePreviousHashItWasGiven(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 6, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	full := strings.Split(strings.TrimSpace(exportChain(t, src, "c")), "\n")
	hashOf := func(line string) string {
		var e verify.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		return e.ChainHash
	}

	dst := newDB(t, "dst")
	if code, _, e := runWithStdin(t, strings.Join(full[3:], "\n")+"\n", cmdImport,
		"--db", dst, "--chain", "c", "--previous-hash", hashOf(full[2])); code != exitOK {
		t.Fatalf("import: %s", e)
	}
	s, err := boltstore.Open(dst, boltstore.WithReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Range(context.Background(), "c", 0, 1<<62, 0)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows: %d, %v", len(rows), err)
	}
	if rows[0].PreviousHash != hashOf(full[2]) {
		t.Errorf("the first imported row's previous hash is %q, want the --previous-hash given",
			shortHash(rows[0].PreviousHash))
	}
	if rows[1].PreviousHash != rows[0].ChainHash {
		t.Error("the second row does not link from the first")
	}
}

// TestImport_MustContinueTheChainItIsImportedInto: a free range is not enough.
// Into a chain that has entries, the only import is the one that continues it:
// the next sequence number, linking from the tail. Anything else left one
// chain id over rows that do not link.
func TestImport_MustContinueTheChainItIsImportedInto(t *testing.T) {
	src := newDB(t, "src")
	if code, _, e := runWithStdin(t, commitLines(t, 8, 0), cmdCommit, "--db", src, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	full := strings.Split(strings.TrimSpace(exportChain(t, src, "c")), "\n")
	hashOf := func(line string) string {
		var e verify.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		return e.ChainHash
	}
	segment := func(from, to int) string { return strings.Join(full[from:to], "\n") + "\n" }
	importInto := func(db, stdin string, args ...string) (int, string) {
		code, _, stderr := runWithStdin(t, stdin, cmdImport, append([]string{"--db", db, "--chain", "c"}, args...)...)
		return code, stderr
	}

	// Another chain with the same numbering: its entries 4.. verify against
	// its own entry 3, and do not link from this chain's.
	other := newDB(t, "other")
	if code, _, e := runWithStdin(t, commitLines(t, 8, 100), cmdCommit, "--db", other, "--chain", "c"); code != exitOK {
		t.Fatalf("append: %s", e)
	}
	foreign := strings.Split(strings.TrimSpace(exportChain(t, other, "c")), "\n")

	dst := newDB(t, "dst")
	if code, e := importInto(dst, segment(0, 4)); code != exitOK {
		t.Fatalf("import 0..3: %s", e)
	}
	before := exportChain(t, dst, "c")

	refused := []struct {
		name, stdin, previous, want string
	}{
		{"after a gap", segment(5, 8), hashOf(full[4]), "must continue it"},
		{"from another chain's entry", strings.Join(foreign[4:6], "\n") + "\n", hashOf(foreign[3]),
			"does not link from the last of them"},
	}
	for _, tc := range refused {
		code, stderr := importInto(dst, tc.stdin, "--previous-hash", tc.previous)
		if code != exitIOError || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, want %d and %q: %s", tc.name, code, exitIOError, tc.want, stderr)
		}
		if after := exportChain(t, dst, "c"); after != before {
			t.Fatalf("%s: the refused import changed the chain", tc.name)
		}
	}

	// The import that continues the chain is taken, and the whole verifies.
	if code, e := importInto(dst, segment(4, 8), "--previous-hash", hashOf(full[3])); code != exitOK {
		t.Fatalf("the adjacent import was refused: %s", e)
	}
	if got := exportChain(t, dst, "c"); got != strings.Join(full, "\n")+"\n" {
		t.Error("two adjacent imports did not rebuild the chain")
	}

	// Before the chain's first entry: the range is free, and it is refused.
	late := newDB(t, "late")
	if code, e := importInto(late, segment(4, 8), "--previous-hash", hashOf(full[3])); code != exitOK {
		t.Fatalf("import 4..7 into an empty database: %s", e)
	}
	if code, stderr := importInto(late, segment(0, 4)); code != exitIOError || !strings.Contains(stderr, "must continue it") {
		t.Errorf("an import before the chain's first entry: exit %d: %s", code, stderr)
	}
	if n := storedRows(t, late, "c"); n != 4 {
		t.Errorf("the refused import left %d rows, want 4", n)
	}
}
