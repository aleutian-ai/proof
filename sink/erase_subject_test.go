// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
)

// multi commits u-1 in two classes and u-2 in one, and returns the sink and the
// chains, by "class/subject".
func multi(t *testing.T) (*Sink, map[string]string) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Class: "payments", Subject: "u-1", Content: []byte(`{"amount":42}`)},
		{Class: "auth", Subject: "u-1", Content: []byte(`{"login":true}`)},
		{Class: "payments", Subject: "u-2", Content: []byte(`{"amount":7}`)},
	}
	if _, err := s.Commit(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	chains := map[string]string{}
	for _, r := range recs {
		chains[r.Class+"/"+r.Subject] = cidIn(t, s, r.Class, r.Subject)
	}
	return s, chains
}

// invariant asserts the index invariant of the design: every chain in the
// evidence file has a reverse row (live or pending), or has none and ends with
// an erasure entry.
func invariant(t *testing.T, s *Sink) {
	t.Helper()
	ctx := context.Background()
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	chains, err := st.Chains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	for _, c := range chains {
		taken, err := subj.taken(c)
		if err != nil {
			t.Fatal(err)
		}
		if taken {
			continue
		}
		last := ""
		if err := forEachEntry(ctx, st, c, func(e store.Entry) { last = e.EntryType }); err != nil {
			t.Fatal(err)
		}
		if last != EntryTypeErasure {
			t.Fatalf("chain %s is not accounted for: no index row, and it does not end with an erasure", c)
		}
	}
}

func subjectsBytes(t *testing.T, s *Sink) []byte {
	t.Helper()
	raw, err := os.ReadFile(s.subjectsPath())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// EraseSubject reaches every class of the subject, only that subject, and
// leaves no trace of it in the (rewritten) index.
func TestEraseSubject_AllClasses(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	res, err := s.EraseSubject(ctx, "u-1")
	if err != nil || res.Class != "" || len(res.Erased) != 2 {
		t.Fatalf("EraseSubject = %+v, %v; want both of u-1's chains", res, err)
	}
	got := map[string]bool{}
	for _, e := range res.Erased {
		got[e.Chain] = true
	}
	if !got[chains["payments/u-1"]] || !got[chains["auth/u-1"]] || got[chains["payments/u-2"]] {
		t.Fatalf("erased %v; want exactly u-1's payments and auth chains", res.Erased)
	}
	raw := subjectsBytes(t, s)
	if bytes.Contains(raw, []byte("u-1")) {
		t.Fatal("the erased subject is still in the subject index's bytes")
	}
	if !bytes.Contains(raw, []byte("u-2")) { // control: the scan can find a subject
		t.Fatal("control: u-2 not found in the index")
	}
	invariant(t, s)
	if c := cidIn(t, s, "payments", "u-2"); c != chains["payments/u-2"] {
		t.Fatalf("u-2's binding changed: %s", c)
	}
}

// EraseSubjectClass erases one class and keeps the subject's others.
func TestEraseSubjectClass_KeepsOtherClasses(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	res, err := s.EraseSubjectClass(ctx, "u-1", "payments")
	if err != nil || res.Class != "payments" || len(res.Erased) != 1 || res.Erased[0].Chain != chains["payments/u-1"] {
		t.Fatalf("EraseSubjectClass = %+v, %v", res, err)
	}
	if c := cidIn(t, s, "auth", "u-1"); c != chains["auth/u-1"] {
		t.Fatalf("u-1's auth binding changed: %s", c)
	}
	if !bytes.Contains(subjectsBytes(t, s), []byte("u-1")) {
		t.Fatal("a class-scoped erasure forgot the subject, which still has auth evidence")
	}
	// A new payments event for u-1 is a new chain; auth still goes to the old one.
	if _, err := s.Commit(ctx, []Record{
		{Class: "payments", Subject: "u-1", Content: []byte(`{"amount":1}`)},
		{Class: "auth", Subject: "u-1", Content: []byte(`{"login":false}`)},
	}); err != nil {
		t.Fatal(err)
	}
	if cidIn(t, s, "payments", "u-1") == chains["payments/u-1"] {
		t.Fatal("new payments evidence rejoined the erased payments chain")
	}
	if cidIn(t, s, "auth", "u-1") != chains["auth/u-1"] {
		t.Fatal("auth evidence moved chain after an unrelated class was erased")
	}
	invariant(t, s)
}

// A crash right after "forget": the subject is gone from the index, its chains
// are pending, nothing is erased yet. A new event must not rejoin those chains,
// and the next erase call must complete them.
func TestEraseSubject_CrashAfterForget(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := subj.forget("u-1", "")
	subj.Close()
	if err != nil || len(pending) != 2 {
		t.Fatalf("forget: %v, %v", pending, err)
	}
	invariant(t, s) // pending rows still account for both chains

	if _, err := s.Commit(ctx, []Record{{Class: "payments", Subject: "u-1", Content: []byte(`{"amount":9}`)}}); err != nil {
		t.Fatal(err)
	}
	if cidIn(t, s, "payments", "u-1") == chains["payments/u-1"] {
		t.Fatal("a new event after the crash rejoined a pending (half-erased) chain")
	}

	resumed, err := s.ResumeErasures(ctx)
	if err != nil || len(resumed) != 2 {
		t.Fatalf("ResumeErasures = %+v, %v; want the two pending chains", resumed, err)
	}
	for _, r := range resumed {
		if r.ErasureEntryID == "" {
			t.Fatalf("resumed chain %s got no erasure entry", r.Chain)
		}
	}
	if again, err := s.ResumeErasures(ctx); err != nil || len(again) != 0 {
		t.Fatalf("a second resume = %+v, %v; want nothing pending", again, err)
	}
	invariant(t, s)
}

// A crash after a chain was erased but before its pending row was cleared:
// completing it again must not append a second erasure entry.
func TestEraseSubject_CrashBeforeClearIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]

	// Forget, then erase the chain by hand, and "crash" before clear.
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-1", "auth"); err != nil {
		t.Fatal(err)
	}
	subj.Close()
	f, err := s.openFolder(false)
	if err != nil {
		t.Fatal(err)
	}
	st, ns, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.eraseChain(ctx, st, ns, l, chain); err != nil {
		t.Fatal(err)
	}
	before := entryCount(t, st, chain)
	ns.Close()
	st.Close()
	f.Close()

	resumed, err := s.ResumeErasures(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].Chain != chain || resumed[0].Events != 0 {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	st2, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if after := entryCount(t, st2, chain); after != before {
		t.Fatalf("re-completing an erased chain appended entries: %d → %d", before, after)
	}
	invariant(t, s)
}

func entryCount(t *testing.T, st interface {
	Range(ctx context.Context, chain string, a, b int64, limit int) ([]store.Entry, error)
}, chain string) int {
	t.Helper()
	rows, err := st.Range(context.Background(), chain, 0, 1<<62, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// cidIn looks up a subject's chain in a given class.
func cidIn(t *testing.T, s *Sink, class, subject string) string {
	t.Helper()
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	c, ok, err := subj.lookup(subject, class)
	if err != nil || !ok {
		t.Fatalf("no %s chain for %s: %v", class, subject, err)
	}
	return c
}

// TestEraseSubject_RewritesTheIndex: erasure rewrites the subject index into a
// fresh file. Whether bbolt happens to overwrite freed pages first depends on
// page allocation (it did for the nonce file in _68's finding, and may not
// here); the rewrite is what guarantees it, so the test checks the rewrite
// happened: the index is a different file after the erasure.
func TestEraseSubject_RewritesTheIndex(t *testing.T) {
	s, _ := multi(t)
	before, err := os.Stat(s.subjectsPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseSubject(context.Background(), "u-1"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(s.subjectsPath())
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the subject index was not rewritten after an erasure")
	}
	// Nothing to erase: rewritten all the same. Every call compacts, so a
	// compaction an earlier call failed (or crashed in) is always redone (D1).
	if _, err := s.EraseSubject(context.Background(), "u-nobody"); err != nil {
		t.Fatal(err)
	}
	again, _ := os.Stat(s.subjectsPath())
	if os.SameFile(after, again) {
		t.Fatal("an erasure of nothing did not rewrite the index")
	}
}
