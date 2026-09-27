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
			if got := exportChain(t, db, "c"); strings.TrimSpace(got) != "" {
				t.Errorf("a rejected batch left entries behind:\n%s", got)
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
	if got := exportChain(t, dst, "c"); strings.TrimSpace(got) != "" {
		t.Error("a refused import wrote entries anyway")
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
// `_53`.
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
