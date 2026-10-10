// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
)

// The erasure recovery invariant (ticket _69b, "Erasure recovery invariant"),
// exercised as one state machine: forget → partial erasure → compaction fails →
// resume → resume.

// failCompaction makes compaction of files whose name ends in suffix fail, and
// returns a function that restores the real compactor.
func failCompaction(s *Sink, suffix string) func() {
	s.compact = func(path string, d time.Duration) error {
		if strings.HasSuffix(path, suffix) {
			return errors.New("injected: compaction failed")
		}
		return compactFile(path, d)
	}
	return func() { s.compact = compactFile }
}

// stick makes a chain's erasure fail, by putting a directory where only content
// files belong. unstick undoes it.
func stick(t *testing.T, s *Sink, chain string) (unstick func()) {
	t.Helper()
	// An entry that cannot be decoded, just past the chain's tail: the chain can
	// no longer be read to its end, so it cannot be erased.
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	next := int64(entryCount(t, st, chain))
	st.Close()
	key := append(append([]byte(chain), 0), make([]byte, 8)...)
	binary.BigEndian.PutUint64(key[len(chain)+1:], uint64(next))
	put := func(fn func(b *bolt.Bucket) error) {
		db, err := bolt.Open(s.DBPath(), 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.Update(func(tx *bolt.Tx) error { return fn(tx.Bucket([]byte("entries"))) }); err != nil {
			t.Fatal(err)
		}
	}
	put(func(b *bolt.Bucket) error { return b.Put(key, []byte("not an entry")) })
	return func() { put(func(b *bolt.Bucket) error { return b.Delete(key) }) }
}

// chainErased asserts condition 2 of the invariant for one chain: it ends with
// a genuine erasure entry, and no content except erasure records, no nonce and
// no source position remain.
func chainErased(t *testing.T, s *Sink, chain string) {
	t.Helper()
	ctx := context.Background()
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var entries []store.Entry
	if err := forEachEntry(ctx, st, chain, func(e store.Entry) { entries = append(entries, e) }); err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("chain %s has %d entries; want events and an erasure", chain, len(entries))
	}
	last, prev := entries[len(entries)-1], entries[len(entries)-2]
	if last.EntryType != EntryTypeErasure || last.ContentHash != erasureHash(erasureRecord(prev.GlobalSeq)) {
		t.Fatalf("chain %s does not end with a genuine erasure entry", chain)
	}
	sec, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := sec.contentIDs(chain)
	sec.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		raw, err := readContent(s, chain, id)
		if err != nil || !bytes.HasPrefix(raw, []byte(`{"erased":`)) {
			t.Fatalf("chain %s kept %s, which is not an erasure record", chain, id)
		}
	}
	sec2, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer sec2.Close()
	for _, e := range entries {
		if _, nonce, _, err := sec2.get(chain, e.EntryID); err != nil || nonce != nil {
			t.Fatalf("chain %s: nonce of %s still stored (%v)", chain, e.EntryID, err)
		}
	}
}

func pendingChains(t *testing.T, s *Sink) []string {
	t.Helper()
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	p, err := subj.pending()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(p)
	return p
}

func incomplete(t *testing.T, err error) *ErasureIncompleteError {
	t.Helper()
	var ie *ErasureIncompleteError
	if !errors.As(err, &ie) {
		t.Fatalf("err = %v; want *ErasureIncompleteError", err)
	}
	return ie
}

// countCompactions counts the successful compactions of path from here on, by
// wrapping the sink's compactor. It is how a test sees that a file was
// rewritten: a rewritten file's inode is not evidence, because a second
// compaction in the same call can be handed the inode the first one freed.
func countCompactions(s *Sink, path string) func() int {
	n, inner := 0, s.compact
	s.compact = func(p string, d time.Duration) error {
		err := inner(p, d)
		if err == nil && p == path {
			n++
		}
		return err
	}
	return func() int { return n }
}

func TestErasureRecovery_StateMachine(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	if _, err := s.Commit(ctx, []Record{{Class: "payments", Subject: "u-3", Content: []byte(`{"amount":3}`)}}); err != nil {
		t.Fatal(err)
	}
	u3 := cidIn(t, s, "payments", "u-3")

	// State 1: a crash after u-3 was forgotten, and u-3's chain cannot be erased.
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-3", ""); err != nil {
		t.Fatal(err)
	}
	subj.Close()
	unstick := stick(t, s, u3)

	// State 2: erase u-1 while the subject index cannot be rewritten. u-3's stuck
	// chain must not block u-1, and u-1's chains are erased. But the files were
	// not all rewritten, so u-1's chains STAY PENDING (E1): the pending rows are
	// what says, across a crash, that a rewrite is still owed.
	restore := failCompaction(s, ".subjects")
	res, err := s.EraseSubject(ctx, "u-1")
	ie := incomplete(t, err)
	u1Chains := []string{chains["payments/u-1"], chains["auth/u-1"]}
	wantPending := append([]string{u3}, u1Chains...)
	slices.Sort(wantPending)
	gotPending := append([]string(nil), ie.Pending...)
	slices.Sort(gotPending)
	if !ie.Forgotten || ie.Compacted || !slices.Equal(gotPending, wantPending) {
		t.Fatalf("incomplete = {Forgotten:%v Compacted:%v Pending:%v}; want {true false %v}",
			ie.Forgotten, ie.Compacted, ie.Pending, wantPending)
	}
	if len(res.Erased) != 2 {
		t.Fatalf("erased %d of u-1's chains, want 2 (a stuck earlier chain must not block them)", len(res.Erased))
	}
	chainErased(t, s, chains["payments/u-1"])
	chainErased(t, s, chains["auth/u-1"])
	if got := pendingChains(t, s); !slices.Equal(got, wantPending) {
		t.Fatalf("pending = %v, want u-3's and u-1's chains (the rewrite is owed)", got)
	}
	if strings.Contains(err.Error(), "u-1") {
		t.Fatal("the incomplete-erasure error names the subject")
	}
	restore()

	// State 3: resume while u-3's chain is still stuck. Nothing is re-linked, the
	// index is rewritten this time (the compaction the last call owed), and u-1's
	// chains are completed (already erased: nothing appended) and cleared.
	compactions := countCompactions(s, s.subjectsPath())
	resumed, err := s.ResumeErasures(ctx)
	ie = incomplete(t, err)
	if ie.Forgotten || !ie.Compacted || !slices.Equal(ie.Pending, []string{u3}) || len(resumed) != 2 {
		t.Fatalf("resume = %v, {Forgotten:%v Compacted:%v Pending:%v}", resumed, ie.Forgotten, ie.Compacted, ie.Pending)
	}
	if compactions() == 0 {
		t.Fatal("resume did not rewrite the subject index after the failed compaction")
	}
	raw := subjectsBytes(t, s)
	if bytes.Contains(raw, []byte("u-1")) || bytes.Contains(raw, []byte("u-3")) {
		t.Fatal("a forgotten subject is still in the subject index's bytes")
	}

	// State 4: the chain is repairable again: resume completes it.
	unstick()
	resumed, err = s.ResumeErasures(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].Chain != u3 {
		t.Fatalf("resume = %+v, %v; want u-3's chain completed", resumed, err)
	}
	chainErased(t, s, u3)
	if got := pendingChains(t, s); len(got) != 0 {
		t.Fatalf("still pending: %v", got)
	}
	invariant(t, s)

	// State 5: nothing left; resume succeeds, and still compacts (D1).
	compactions = countCompactions(s, s.subjectsPath())
	if again, err := s.ResumeErasures(ctx); err != nil || len(again) != 0 {
		t.Fatalf("resume with nothing pending = %+v, %v", again, err)
	}
	if compactions() == 0 {
		t.Fatal("resume with nothing pending did not compact")
	}
	if c := cidIn(t, s, "payments", "u-2"); c != chains["payments/u-2"] {
		t.Fatalf("u-2's binding changed: %s", c)
	}
}

// A chain of THIS subject that cannot be erased is found before the subject is
// forgotten: the call refuses, and nothing changes.
func TestEraseSubject_PreflightRefusesBeforeForgetting(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	stick(t, s, chains["auth/u-1"])
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	payments := entryCount(t, st, chains["payments/u-1"])
	st.Close()

	_, err = s.EraseSubject(ctx, "u-1")
	var ie *ErasureIncompleteError
	if err == nil || errors.As(err, &ie) {
		t.Fatalf("err = %v; want a plain refusal, before anything was forgotten", err)
	}
	if cidIn(t, s, "auth", "u-1") != chains["auth/u-1"] || cidIn(t, s, "payments", "u-1") != chains["payments/u-1"] {
		t.Fatal("the subject was (partly) forgotten by a refused erasure")
	}
	if got := pendingChains(t, s); len(got) != 0 {
		t.Fatalf("a refused erasure left pending chains: %v", got)
	}
	st, err = s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if entryCount(t, st, chains["payments/u-1"]) != payments {
		t.Fatal("a refused erasure erased the subject's other chain")
	}
}

// An empty subject is invalid, never "resume only" (A3).
func TestEraseSubject_EmptySubjectIsInvalid(t *testing.T) {
	ctx := context.Background()
	s, _ := multi(t)
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-2", ""); err != nil { // a pending chain an empty call must not touch
		t.Fatal(err)
	}
	subj.Close()
	if _, err := s.EraseSubject(ctx, ""); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("EraseSubject(\"\") = %v; want ErrInvalidSubject", err)
	}
	if _, err := s.EraseSubjectClass(ctx, "", "payments"); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("EraseSubjectClass(\"\", …) = %v; want ErrInvalidSubject", err)
	}
	if got := pendingChains(t, s); len(got) != 1 {
		t.Fatalf("an invalid call resumed erasures: pending = %v", got)
	}
}

// A pending row holding an id this sink never mints cannot be erased. It is
// reported once and cleared, so it cannot block every later erasure.
func TestEraseSubject_InvalidPendingRowIsClearedAndReported(t *testing.T) {
	ctx := context.Background()
	s, _ := multi(t)
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).Put([]byte("NOT-A-CHAIN"), pendingMarker)
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	res, err := s.EraseSubject(ctx, "u-1")
	ie := incomplete(t, err)
	if !ie.Forgotten || !ie.Compacted || len(ie.Pending) != 0 || len(res.Erased) != 2 {
		t.Fatalf("got %+v, {Forgotten:%v Compacted:%v Pending:%v}", res, ie.Forgotten, ie.Compacted, ie.Pending)
	}
	if again, err := s.ResumeErasures(ctx); err != nil || len(again) != 0 {
		t.Fatalf("the invalid row was not cleared: %+v, %v", again, err)
	}
}

// writeRawEntries writes entries straight into the evidence file, keyed by
// position, with whatever stored global_seq the test wants (A4: a crafted file).
func writeRawEntries(t *testing.T, s *Sink, chain string, n int, storedSeq func(i int) int64) {
	t.Helper()
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		for i := 0; i < n; i++ {
			k := append(append([]byte(chain), 0), make([]byte, 8)...)
			binary.BigEndian.PutUint64(k[len(chain)+1:], uint64(i))
			raw, _ := json.Marshal(store.Entry{ChainID: chain, EntryID: "sink-" + strings.Repeat("0", 32),
				EntryType: EntryTypeEvent, GlobalSeq: storedSeq(i)})
			if err := b.Put(k, raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A crafted evidence file whose stored sequence does not advance must be
// refused, not paged forever (A4).
func TestForEachEntry_RefusesNonAdvancingSequence(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	chain := testClass + "." + strings.Repeat("c", 32)
	writeRawEntries(t, s, chain, entryPage+5, func(int) int64 { return 0 })
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	done := make(chan error, 1)
	go func() { done <- forEachEntry(context.Background(), st, chain, func(store.Entry) {}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a non-advancing sequence was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forEachEntry looped on a crafted evidence file")
	}
}

// An event relabelled as an erasure (wrong hash) is not an erasure: its content
// is deleted, and a genuine erasure entry is appended (A5).
func TestEraseSubject_RelabelledEventIsNotAnErasure(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["payments/u-1"]
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	fake := "sink-" + strings.Repeat("d", 32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: fake, EntryType: EntryTypeErasure,
		Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := writeContent(s, chain, fake, []byte(`{"amount":"plaintext"}`)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := statContent(s, chain, fake); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the relabelled event's content was kept as an erasure record: %v", err)
	}
	chainErased(t, s, chain)
}

// The subject index is checked when it is used: a forward row that points at
// another class's chain, or whose reverse row disagrees, is refused (A6).
func TestSubjectIndex_RefusesInconsistentRows(t *testing.T) {
	cases := map[string]func(tx *bolt.Tx, chains map[string]string) error{
		"forward row points at another class's chain": func(tx *bolt.Tx, c map[string]string) error {
			return tx.Bucket(forwardBucket).Put(forwardKey("u-1", "payments"), []byte(c["auth/u-1"]))
		},
		"forward row points at another subject's chain": func(tx *bolt.Tx, c map[string]string) error {
			return tx.Bucket(forwardBucket).Put(forwardKey("u-1", "payments"), []byte(c["payments/u-2"]))
		},
		"forward row holds an invalid id": func(tx *bolt.Tx, _ map[string]string) error {
			return tx.Bucket(forwardBucket).Put(forwardKey("u-1", "payments"), []byte("payments.XYZ"))
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			s, chains := multi(t)
			db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Update(func(tx *bolt.Tx) error { return corrupt(tx, chains) }); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if _, err := s.Commit(context.Background(), []Record{{Class: "payments", Subject: "u-1",
				Content: []byte(`{"amount":1}`)}}); err == nil {
				t.Fatal("commit followed an inconsistent index row")
			}
			if _, err := s.EraseSubject(context.Background(), "u-1"); err == nil {
				t.Fatal("erase followed an inconsistent index row")
			}
			if got := pendingChains(t, s); len(got) != 0 {
				t.Fatalf("erase forgot through an inconsistent row: pending %v", got)
			}
		})
	}
}

// A reverse row that starts with NUL but is not the pending marker is refused,
// not read as a class (A6).
func TestSubjectIndex_OwnerRefusesMalformedRow(t *testing.T) {
	subj, err := openSubjects(filepath.Join(t.TempDir(), "subjects"), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	chain := testClass + "." + strings.Repeat("a", 32)
	for _, v := range []string{"\x00u-1", "\x00pending", "EVENTS\x00u-1", "events\x00"} {
		if err := subj.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(reverseBucket).Put([]byte(chain), []byte(v))
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := subj.owner(chain); err == nil || ok {
			t.Fatalf("owner accepted the malformed row %q", v)
		}
	}
}

// A minted id that is not a valid id of the class is never bound (A6).
func TestResolveChain_RefusesInvalidMint(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"events", "auth." + strings.Repeat("f", 32), "events." + strings.Repeat("F", 32)} {
		s.mintChainID = func(string) (string, error) { return bad, nil }
		if _, err := s.Commit(context.Background(), events("u-9", 1)); err == nil {
			t.Fatalf("a minted id %q was bound", bad)
		}
	}
}

// Erasing a chain whose first commit never reached it removes its (empty)
// content folder, so Verify does not report a removed chain forever (A7).
func TestEraseSubject_RemovesLeftoverContentOfAnEmptyChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	chain := bindChain(t, s, "u-1")
	stray := "sink-" + strings.Repeat("5", 32)
	if err := writeContent(s, chain, stray, []byte(`{"user":"u-1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := statContent(s, chain, stray); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover content survived the erasure: %v", err)
	}
}

// A first commit that fails leaves no content or nonce rows behind.
func TestCommitPairs_FailedFirstCommitLeavesNoRows(t *testing.T) {
	fx := newFixture(t)
	err := fx.s.commitPairs(context.Background(), failingAppend{errors.New("injected")},
		fx.st, fx.sec, fx.src, nil, []pairPlan{{chain: fx.chain, recs: sourced("u-1", 2, 1)}})
	if err == nil {
		t.Fatal("the injected failure was not reported")
	}
	if chains, _ := fx.sec.chainsWithRowsAfter(nil, 1<<30); len(chains) != 0 {
		t.Fatalf("the failed first commit left content or nonces for %v", chains)
	}
}

// Compaction writes to a fresh, unpredictable file, never through a planted
// link, and removes copies an interrupted compaction left (A8). (Whether the
// temp file is created exclusively is a race this test cannot stage; it pins
// the leftover cleanup and the outcome.)
func TestCompactFile_IgnoresPlantedTempLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("b"))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), []byte("the secret"))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// A copy an interrupted compaction left behind: secret, and must go.
	if err := os.WriteFile(path+".compact-123", []byte("the secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "captured")
	if err := os.Symlink(elsewhere, path+".compact"); err != nil {
		t.Fatal(err)
	}
	if err := compactFile(path, DefaultLockTimeout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(elsewhere); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("compaction wrote through a planted link")
	}
	left, _ := filepath.Glob(path + ".compact*")
	for _, p := range left {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			t.Fatalf("compaction left a copy of the secret file: %s", p)
		}
	}
}

// Commit returns one outcome per record, in the order given, and never the
// subject. When any pair fails, the call commits NOTHING (all-or-none on a
// returned error, _74a): every outcome says not committed, and a consumer acks
// none of them.
func TestCommit_OutcomesPerRecordOnPartialFailure(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	taken := cid(t, s, "u-1")
	recs := []Record{events("u-1", 1)[0], events("u-2", 1)[0], events("u-1", 1)[0], events("u-3", 1)[0]}
	recs[2].Content = []byte(`{"user":"u-1","i":9}`)
	s.mintChainID = func(string) (string, error) { return taken, nil } // u-2 cannot get a chain
	out, err := s.Commit(ctx, recs)
	var pe *PairError
	if !errors.As(err, &pe) || len(pe.Records) != 1 || pe.Records[0] != 1 || !strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("err = %v; want a *PairError naming record 1, and nothing committed", err)
	}
	if len(out) != len(recs) || pattern(out) != "----" {
		t.Fatalf("outcomes = %s (%+v); want ----: nothing committed", pattern(out), out)
	}
	if n := len(entryIDs(t, s, taken)); n != 1 {
		t.Fatalf("u-1's chain holds %d entries, want only the earlier 1", n)
	}
	raw, err := json.Marshal(out)
	if err != nil || bytes.Contains(raw, []byte("u-")) || bytes.Contains(raw, []byte(testClass+".")) {
		t.Fatalf("an outcome carries a subject or a chain: %s, %v", raw, err)
	}
}

// EraseSubject completes an earlier pending erasure too, and reports it apart,
// under Resumed.
func TestEraseSubject_CompletesEarlierPending(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-2", ""); err != nil { // a crash after u-2 was forgotten
		t.Fatal(err)
	}
	subj.Close()
	res, err := s.EraseSubject(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resumed) != 1 || res.Resumed[0].Chain != chains["payments/u-2"] || len(res.Erased) != 2 {
		t.Fatalf("got %+v; want u-2's chain under Resumed and u-1's two under Erased", res)
	}
	for _, c := range []string{chains["payments/u-2"], chains["payments/u-1"], chains["auth/u-1"]} {
		chainErased(t, s, c)
	}
	invariant(t, s)
}

// A crash after the erasure entry was appended but before the nonces and
// content went: resuming finishes them, without a second erasure entry.
func TestEraseSubject_CrashAfterErasureEntry(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-1", "auth"); err != nil {
		t.Fatal(err)
	}
	subj.Close()

	// eraseChain's step 1 alone: the record file and the entry.
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	_, tail, err := st.ReadTail(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	id := "sink-" + strings.Repeat("e", 32)
	record := erasureRecord(tail)
	if err := writeContent(s, chain, id, record); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
		Timestamp: now, IngestedAt: now, ContentHash: erasureHash(record)}}); err != nil {
		t.Fatal(err)
	}
	before := entryCount(t, st, chain)
	st.Close()

	resumed, err := s.ResumeErasures(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].ErasureEntryID != id {
		t.Fatalf("resume = %+v, %v; want the existing erasure entry %s reused", resumed, err, id)
	}
	st, err = s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	after := entryCount(t, st, chain)
	st.Close()
	if after != before {
		t.Fatalf("resume appended a second erasure entry: %d → %d", before, after)
	}
	chainErased(t, s, chain)
	if _, err := statContent(s, chain, id); err != nil {
		t.Fatalf("the genuine erasure record was removed: %v", err)
	}
}

// A class-scoped erasure removes exactly that class's rows from the index's
// bytes, and keeps the subject's other class.
func TestEraseSubjectClass_RemovesOnlyThatRow(t *testing.T) {
	s, chains := multi(t)
	if _, err := s.EraseSubjectClass(context.Background(), "u-1", "payments"); err != nil {
		t.Fatal(err)
	}
	raw := subjectsBytes(t, s)
	if bytes.Contains(raw, forwardKey("u-1", "payments")) || bytes.Contains(raw, []byte(chains["payments/u-1"])) {
		t.Fatal("the erased class's rows are still in the index's bytes")
	}
	if !bytes.Contains(raw, forwardKey("u-1", "auth")) || !bytes.Contains(raw, []byte(chains["auth/u-1"])) {
		t.Fatal("control: the kept class's rows are missing")
	}
}

// Erasing two subjects one after the other gives each chain exactly one
// erasure entry: the second call does not erase the first's chains again.
func TestEraseSubject_NoDoubleErasure(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	count := func(chain string) int {
		st, err := s.openStore(true)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		return entryCount(t, st, chain)
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	after1 := count(chains["payments/u-1"])
	if _, err := s.EraseSubject(ctx, "u-2"); err != nil {
		t.Fatal(err)
	}
	if got := count(chains["payments/u-1"]); got != after1 {
		t.Fatalf("erasing u-2 changed u-1's erased chain: %d → %d entries", after1, got)
	}
	chainErased(t, s, chains["payments/u-2"])
}

// A genuine erasure's record file is kept only if it still holds exactly the
// record: plaintext put in its place is deleted when the chain is erased again.
func TestEraseChain_KeepsOnlyExactErasureRecords(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	res, err := s.EraseSubjectClass(ctx, "u-1", "auth")
	if err != nil {
		t.Fatal(err)
	}
	record := res.Erased[0].ErasureEntryID
	if err := writeContent(s, chain, record, []byte(`{"login":"plaintext"}`)); err != nil {
		t.Fatal(err)
	}
	// Pending again (as after a crash), so the next call erases it again.
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).Put([]byte(chain), pendingMarker)
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	// The plaintext is gone, and the genuine record is back in its place (a
	// missing record is restored: it is public and fixed).
	got, err := readContent(s, chain, record)
	if err != nil || bytes.Contains(got, []byte("plaintext")) || !bytes.HasPrefix(got, []byte(`{"erased":`)) {
		t.Fatalf("the row in the erasure record's place = %q, %v; want the record, not the plaintext", got, err)
	}
}

// A failure in the WRITE phase (after every chain resolved) commits nothing, for
// any pair: not the pair before it, not a duplicate, not a later pair.
func TestCommit_OutcomesWhenAnAppendFails(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	// u-2's chain gets a known id, and a FILE where its content folder must go.
	doomed := testClass + "." + strings.Repeat("d", 32)
	ids := []string{doomed, testClass + "." + strings.Repeat("e", 32)} // u-2, then u-3
	s.mintChainID = func(string) (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	failAppends(s)
	u2 := sourced("u-2", 1, 70)[0]
	recs := []Record{sourced("u-1", 1, 60)[0], u2, u2, sourced("u-3", 1, 80)[0]}
	out, err := s.Commit(ctx, recs)
	if err == nil || strings.Contains(err.Error(), doomed) || !strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("err = %v; want an error that names no chain, and nothing committed", err)
	}
	if pattern(out) != "----" {
		t.Fatalf("outcomes %s; want ----: nothing committed", pattern(out))
	}
	if n := len(entryIDs(t, s, cid(t, s, "u-1"))); n != 1 {
		t.Fatalf("u-1's chain holds %d entries, want only the earlier 1", n)
	}
}

// A context already cancelled: nothing is committed, and the outcomes (one per
// record) say so.
func TestCommit_CancelledContext(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := s.Commit(ctx, events("u-1", 2))
	if !errors.Is(err, context.Canceled) || pattern(out) != "--" {
		t.Fatalf("out %s, err %v; want -- and context.Canceled", pattern(out), err)
	}
}
