// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// crashAfterSecrets is an appender that panics, as a process dying between
// writing a commit's content and appending its entries does.
type crashAfterSecrets struct{}

func (crashAfterSecrets) AppendChains(context.Context, []linker.ChainInputs) ([]linker.Result, error) {
	panic("the process died before the append")
}

// crashCommit runs one Commit that dies after its content, nonces, signatures
// and source positions were written and before its entries were appended.
func crashCommit(t *testing.T, s *Sink, recs []Record) {
	t.Helper()
	s.wrapAppender = func(chainsAppender) chainsAppender { return crashAfterSecrets{} }
	defer func() {
		s.wrapAppender = nil
		if recover() == nil {
			t.Fatal("the commit did not die")
		}
	}()
	_, _ = s.Commit(context.Background(), recs)
}

// TestRepair_RemovesWhatACrashedCommitLeft: a commit that crashed after its
// content was written, retried, leaves the first attempt's rows for good:
// Verify reported them until the subject was erased. Repair removes them, in
// every file, and the sink verifies again.
func TestRepair_RemovesWhatACrashedCommitLeft(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	dir := t.TempDir()
	s := openSigning(t, dir, rs)
	_, ring := newSigner(t)
	if _, err := s.Commit(ctx, sourced("u-1", 2, 1)); err != nil {
		t.Fatal(err)
	}
	// An existing pair, and a pair that has never committed.
	crashCommit(t, s, append(sourced("u-1", 1, 10), sourced("u-9", 1, 20)...))
	s = openSigning(t, dir, rs) // the process restarts
	// The retry of the existing pair's record commits it under a new entry id.
	if out, err := s.Commit(ctx, sourced("u-1", 1, 10)); err != nil || pattern(out) != "N" {
		t.Fatalf("retry: %s, %v", pattern(out), err)
	}

	rep, err := s.Verify(ctx, ring, WithRecordTrust(recordRing(t, rs)))
	if err != nil || rep.OK() {
		t.Fatalf("verify after the crash: %+v, %v; want the leftovers reported", rep, err)
	}
	sum, err := s.Repair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// u-1: one content row, nonce and signature (its position was replaced by
	// the retry). u-9 has no entries and has signature rows, which a chain whose
	// signed entries were removed has too: left alone, and counted.
	want := RepairSummary{Chains: 1, Content: 1, Nonces: 1, Signatures: 1, Skipped: 1}
	if sum != want {
		t.Fatalf("Repair = %+v, want %+v", sum, want)
	}
	// Once the pair has committed, what its first attempt left is an ordinary
	// leftover, and goes.
	if out, err := s.Commit(ctx, sourced("u-9", 1, 20)); err != nil || pattern(out) != "N" {
		t.Fatalf("u-9's retry: %s, %v", pattern(out), err)
	}
	sum, err = s.Repair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (RepairSummary{Chains: 1, Content: 1, Nonces: 1, Signatures: 1}); sum != want {
		t.Fatalf("second Repair = %+v, want %+v", sum, want)
	}
	rep, err = s.Verify(ctx, ring, WithRecordTrust(recordRing(t, rs)))
	if err != nil || !rep.OK() {
		t.Fatalf("verify after repair: %+v, %v", rep, err)
	}
	for _, cr := range rep.Chains {
		if cr.OrphanSignatures != 0 {
			t.Fatalf("an orphan signature is left: %+v", cr)
		}
	}
	// Nothing committed was touched.
	if n := len(entryIDs(t, s, cid(t, s, "u-1"))); n != 3 {
		t.Fatalf("u-1 holds %d entries, want 3", n)
	}
	if sum, err := s.Repair(ctx); err != nil || sum != (RepairSummary{}) {
		t.Fatalf("a third Repair = %+v, %v; want nothing to do", sum, err)
	}
}

// TestRepair_AFirstCommitThatStopped: on a sink that does not sign, the rows of
// a pair's first commit that never appended are removed, the index row kept,
// and the removed content leaves the live file.
func TestRepair_AFirstCommitThatStopped(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, sourced("u-1", 1, 1)); err != nil {
		t.Fatal(err)
	}
	crashCommit(t, s, sourced("u-9", 1, 20))
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	sum, err := s.Repair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (RepairSummary{Chains: 1, Content: 1, Nonces: 1, Sources: 1}); sum != want {
		t.Fatalf("Repair = %+v, want %+v", sum, want)
	}
	raw, err := os.ReadFile(s.secretsPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"u-9"`)) {
		t.Fatal("the removed content is still in the secrets file")
	}
	_, ring := newSigner(t)
	mustVerify(t, s, ring)
	if out, err := s.Commit(ctx, sourced("u-9", 1, 20)); err != nil || pattern(out) != "N" {
		t.Fatalf("u-9 after repair: %s, %v", pattern(out), err)
	}
}

// removeEntries deletes every entry of a chain from the evidence file, as
// someone with write access (or an older copy of the file restored) does.
func removeEntries(t *testing.T, s *Sink, chain string) {
	t.Helper()
	for {
		st, err := s.openStore(true)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = st.ReadTail(context.Background(), chain)
		st.Close()
		if err != nil {
			return
		}
		truncateTail(t, s, chain)
	}
}

// contentRowCount counts a chain's content rows.
func contentRowCount(t *testing.T, s *Sink, chain string) int {
	t.Helper()
	sec, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()
	ids, err := sec.contentIDs(chain)
	if err != nil {
		t.Fatal(err)
	}
	return len(ids)
}

// TestRepair_NeverDeletesForAChainThatHeldEntries: a chain whose entries are
// gone from the evidence file, with its index row and its content still there,
// looks like a first commit that stopped. Repair once deleted all its content
// and nonces, although a checkpoint in the folder said it had held three
// entries: the only copy of a removed chain's events. Anything that says the
// chain held entries now stops it.
func TestRepair_NeverDeletesForAChainThatHeldEntries(t *testing.T) {
	ctx := context.Background()
	t.Run("a checkpoint exists", func(t *testing.T) {
		s, _, ring := setup(t)
		chain := cid(t, s, "u-81")
		removeEntries(t, s, chain)
		rep, err := s.Verify(ctx, ring)
		if err != nil || !strings.Contains(strings.Join(chainReport(t, rep, chain).Problems, "\n"), "REMOVED") {
			t.Fatalf("verify: %+v, %v; want the chain reported removed", rep, err)
		}
		sum, err := s.Repair(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 {
			t.Fatalf("Repair = %+v; want nothing removed and the chain skipped", sum)
		}
		if n := contentRowCount(t, s, chain); n != 3 {
			t.Fatalf("%d of the removed chain's 3 content rows are left", n)
		}
	})
	t.Run("only a recorded head exists", func(t *testing.T) {
		// Entries and checkpoints both removed: inside the folder nothing says
		// the chain existed. The head kept outside does.
		s, signer, _ := setup(t)
		chain := cid(t, s, "u-81")
		heads := FileHeads(filepath.Join(t.TempDir(), "heads.json"))
		if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(heads)); err != nil {
			t.Fatal(err)
		}
		removeEntries(t, s, chain)
		if err := os.RemoveAll(s.anchorDir(chain)); err != nil {
			t.Fatal(err)
		}
		sum, err := s.Repair(ctx, RepairHeads(heads))
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 || contentRowCount(t, s, chain) != 3 {
			t.Fatalf("Repair = %+v, %d content rows left; want the chain skipped", sum, contentRowCount(t, s, chain))
		}
	})
	t.Run("checkpoints removed from a chain cut short, with a recorded head", func(t *testing.T) {
		s, signer, _ := setup(t)
		chain := cid(t, s, "u-81")
		heads := FileHeads(filepath.Join(t.TempDir(), "heads.json"))
		if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(heads)); err != nil {
			t.Fatal(err)
		}
		truncateTail(t, s, chain)
		if err := os.RemoveAll(s.anchorDir(chain)); err != nil {
			t.Fatal(err)
		}
		sum, err := s.Repair(ctx, RepairHeads(heads))
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 || contentRowCount(t, s, chain) != 3 {
			t.Fatalf("Repair = %+v, %d content rows left; want the chain skipped", sum, contentRowCount(t, s, chain))
		}
	})
	t.Run("the index does not bind it", func(t *testing.T) {
		// Never checkpointed, entries removed, index row removed: rows of a
		// chain nothing accounts for are never guessed at.
		s, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
			t.Fatal(err)
		}
		chain := cid(t, s, "u-1")
		removeEntries(t, s, chain)
		dropIndexRows(t, s, "u-1")
		sum, err := s.Repair(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 || contentRowCount(t, s, chain) != 2 {
			t.Fatalf("Repair = %+v, %d content rows left; want the chain skipped", sum, contentRowCount(t, s, chain))
		}
	})
	t.Run("its erasure is pending", func(t *testing.T) {
		// With entries and without: an erasure in progress owns the rows.
		s, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
			t.Fatal(err)
		}
		chain := cid(t, s, "u-1")
		if err := writeContent(s, chain, "sink-"+strings.Repeat("d", 32), []byte("left over")); err != nil {
			t.Fatal(err)
		}
		subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := subj.forget("u-1", ""); err != nil {
			t.Fatal(err)
		}
		subj.Close()
		sum, err := s.Repair(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 || contentRowCount(t, s, chain) != 3 {
			t.Fatalf("with entries: Repair = %+v, %d content rows; want the pending chain skipped", sum, contentRowCount(t, s, chain))
		}
		removeEntries(t, s, chain)
		sum, err = s.Repair(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Removed() != 0 || sum.Skipped != 1 || contentRowCount(t, s, chain) != 3 {
			t.Fatalf("without entries: Repair = %+v, %d content rows; want the pending chain skipped", sum, contentRowCount(t, s, chain))
		}
	})
}

// TestRepair_OneUnreadableChainDoesNotStopTheRest: a chain that cannot be read
// to its end is left alone and counted, and the chains after it are repaired.
func TestRepair_OneUnreadableChainDoesNotStopTheRest(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, append(events("u-1", 1), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	a, b := cid(t, s, "u-1"), cid(t, s, "u-2")
	if a > b {
		a, b = b, a // a is walked first
	}
	for _, chain := range []string{a, b} {
		if err := writeContent(s, chain, "sink-"+strings.Repeat("d", 32), []byte("left over")); err != nil {
			t.Fatal(err)
		}
	}
	// An entry that does not decode, on the first chain.
	db, err := bolt.Open(s.DBPath(), 0o600, &bolt.Options{Timeout: DefaultLockTimeout})
	if err != nil {
		t.Fatal(err)
	}
	key := append(append([]byte(a), 0), 0, 0, 0, 0, 0, 0, 0, 9)
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("entries")).Put(key, []byte("not an entry")) }); err != nil {
		t.Fatal(err)
	}
	db.Close()
	sum, err := s.Repair(ctx)
	if err != nil {
		t.Fatalf("Repair stopped at the unreadable chain: %v", err)
	}
	if want := (RepairSummary{Chains: 1, Content: 1, Skipped: 1}); sum != want {
		t.Fatalf("Repair = %+v, want %+v", sum, want)
	}
	if contentRowCount(t, s, a) != 2 || contentRowCount(t, s, b) != 1 {
		t.Fatalf("content rows: %d on the unreadable chain (want 2 kept), %d on the other (want 1)",
			contentRowCount(t, s, a), contentRowCount(t, s, b))
	}
}

// TestRepair_LeavesATruncatedChainAlone: rows that match no entry are also what
// removing entries from the end of a chain leaves. Where a checkpoint shows the
// chain held more entries, those rows are evidence, and repair keeps them.
func TestRepair_LeavesATruncatedChainAlone(t *testing.T) {
	ctx := context.Background()
	s, _, ring := setup(t)
	chain := cid(t, s, "u-81")
	truncateTail(t, s, chain) // the checkpoint covers 3 entries; 2 are left
	before, err := os.ReadFile(s.secretsPath())
	if err != nil {
		t.Fatal(err)
	}
	sum, err := s.Repair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Removed() != 0 || sum.Skipped != 1 {
		t.Fatalf("Repair = %+v; want the chain skipped and nothing removed", sum)
	}
	ids, err := func() ([]string, error) {
		sec, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
		if err != nil {
			return nil, err
		}
		defer sec.Close()
		return sec.rowIDs(chain)
	}()
	if err != nil || len(ids) != 3 {
		t.Fatalf("the chain has %d content rows, want all 3 kept (%v); the file was %d bytes", len(ids), err, len(before))
	}
	if rep, err := s.Verify(ctx, ring); err != nil || rep.OK() {
		t.Fatalf("verify: %+v, %v; want the truncation still reported", rep, err)
	}
}

// TestRepair_NotASink: repair creates nothing.
func TestRepair_NotASink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nothing")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Repair(context.Background()); !errors.Is(err, errNoSink) {
		t.Fatalf("Repair = %v; want no sink", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repair created the folder")
	}
}

// TestRequireRecordSigning: a sink put in signing mode before its first commit
// refuses a commit without a signer. Without this a first unsigned commit made
// the sink unsigned for good.
func TestRequireRecordSigning(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "sink")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecordSigning(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); !errors.Is(err, ErrRecordSignerRequired) {
		t.Fatalf("an unsigned first commit = %v; want ErrRecordSignerRequired", err)
	}
	rs := testRecordSigner(t, 7)
	signing := openSigning(t, dir, rs)
	if _, err := signing.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecordSigning(ctx); err != nil {
		t.Fatalf("on a sink that already signs: %v", err)
	}
	// A sink that already holds unsigned entries cannot start: nothing changes.
	unsigned, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsigned.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := unsigned.RequireRecordSigning(ctx); !errors.Is(err, ErrSinkNotSigning) {
		t.Fatalf("on an unsigned sink with entries = %v; want ErrSinkNotSigning", err)
	}
	if _, err := unsigned.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatalf("the unsigned sink no longer commits: %v", err)
	}
}

// TestRecordFromJSON_SourceField: a line's source comes from a field, as a
// string or a whole number, and a line without one is refused.
func TestRecordFromJSON_SourceField(t *testing.T) {
	f := JSONFields{Class: "events", SubjectField: "user", SourceField: "id"}
	for line, want := range map[string]string{
		`{"user":"u-1","id":"m-7"}`: "m-7",
		`{"user":"u-1","id":42}`:    "42",
	} {
		r, err := RecordFromJSON([]byte(line), f)
		if err != nil || r.Source != want {
			t.Errorf("%s: source %q, %v; want %q", line, r.Source, err, want)
		}
	}
	for _, line := range []string{`{"user":"u-1"}`, `{"user":"u-1","id":""}`, `{"user":"u-1","id":1.5}`,
		`{"user":"u-1","id":null}`, `{"user":"u-1","id":-3}`, `{"user":"u-1","id":{"a":1}}`} {
		if _, err := RecordFromJSON([]byte(line), f); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("%s: %v; want ErrInvalidRecord", line, err)
		} else if strings.Contains(err.Error(), "u-1") {
			t.Errorf("the error repeats a value: %v", err)
		}
	}
	if _, err := RecordFromJSON([]byte(`{"user":"u-1"}`), JSONFields{Class: "events", SubjectField: "user", SourceField: "user"}); err == nil {
		t.Error("the subject field was accepted as the source field")
	}
}
