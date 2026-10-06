// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/store"
)

// _74b: Verify a page at a time.

// tinyPages makes every page one chain (or one key) for the test.
func tinyPages(t *testing.T) {
	t.Helper()
	c, k, b, g := pageMaxChains, pageMaxKeys, pageBudget, pageGap
	pageMaxChains, pageMaxKeys, pageBudget, pageGap = 1, 1, -time.Second, 0
	t.Cleanup(func() { pageMaxChains, pageMaxKeys, pageBudget, pageGap, betweenPages = c, k, b, g, nil })
}

// VerifyEach streams one report per chain, in chain-id order, and the summary
// counts them; an error from fn stops the run and is returned.
func TestVerifyEach_Streams(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	var got []string
	sum, err := s.VerifyEach(context.Background(), ring, func(cr ChainReport) error {
		got = append(got, cr.Chain)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || sum.Reports != 3 || !sum.OK() {
		t.Fatalf("got %v, summary %+v", got, sum)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not in chain-id order: %v", got)
		}
	}
	stop := errors.New("stop")
	n := 0
	if _, err := s.VerifyEach(context.Background(), ring, func(ChainReport) error {
		n++
		return stop
	}); !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err %v after %d reports; want fn's error after 1", err, n)
	}
	if _, err := s.VerifyEach(context.Background(), ring, nil); err == nil {
		t.Fatal("a nil fn was accepted")
	}
}

// The point of _74b: between pages the files are released, so a writer with
// a SHORT lock timeout commits while Verify is still running.
func TestVerifyEach_WriterGetsTheLockBetweenPages(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	writer, err := Open(s.dir, WithLockTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	betweenPages = func() {
		if _, err := writer.Commit(context.Background(), events("u-99", 1)); err != nil {
			t.Errorf("a writer could not commit between pages: %v", err)
			return
		}
		commits++
	}
	if _, err := s.VerifyEach(context.Background(), ring, func(ChainReport) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if commits < 3 {
		t.Fatalf("only %d commits between pages", commits)
	}
}

// Commits during the run: a chain whose id sorts AFTER the page being read is
// reported, one that sorts BEFORE is not; neither is ever reported REMOVED,
// and every report stays consistent.
func TestVerifyEach_CommitsDuringTheRun(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	writer, _ := Open(s.dir)
	pages := 0
	betweenPages = func() {
		pages++
		if pages == 1 {
			// New chains for two classes: "aaa" sorts before every "events." chain,
			// "zzz" after.
			if _, err := writer.Commit(context.Background(), []Record{
				{Class: "aaa", Subject: "u-1", Content: []byte("{}")},
				{Class: "zzz", Subject: "u-1", Content: []byte("{}")},
			}); err != nil {
				t.Error(err)
			}
		}
	}
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	sawZ, sawA := false, false
	for _, cr := range r.Chains {
		if strings.HasPrefix(cr.Chain, "zzz.") {
			sawZ = true
		}
		if strings.HasPrefix(cr.Chain, "aaa.") {
			sawA = true
		}
		if cr.Anomaly == "removed" {
			t.Fatalf("a chain committed during the run was reported REMOVED: %+v", cr)
		}
	}
	if !sawZ || sawA {
		t.Fatalf("sorting after the cursor: seen %t (want true); before it: seen %t (want false)", sawZ, sawA)
	}
	for _, cr := range r.Chains {
		if strings.HasPrefix(cr.Chain, "events.") && len(cr.Problems) > 0 {
			t.Fatalf("a chain verified during commits reports problems: %+v", cr)
		}
	}
}

// An erasure during the run: no false finding, and every chain is reported
// either as it was or as erased.
func TestVerifyEach_ErasureDuringTheRun(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	writer, _ := Open(s.dir)
	done := false
	betweenPages = func() {
		if !done {
			done = true
			if _, err := writer.EraseSubject(context.Background(), "u-90"); err != nil {
				t.Error(err)
			}
		}
	}
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range r.Chains {
		if len(cr.Problems) > 0 {
			t.Fatalf("an erasure during the run produced a finding: %+v", cr)
		}
	}
}

// The sweep checks against the evidence file at sweep time: a bound chain with
// no entries during the walk that gets its first commit before the sweep is
// not reported as index-only (nor REMOVED).
func TestVerifyEach_SweepSeesTheStoreNow(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	idx, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	fresh := "events." + strings.Repeat("4", 32)
	if err := idx.bindAll([]binding{{subject: "u-7", class: testClass, chain: fresh}}); err != nil {
		t.Fatal(err)
	}
	idx.Close()
	writer, _ := Open(s.dir)
	pages := 0
	betweenPages = func() {
		pages++
		if pages == 3 { // after the last chain page, before the sweep
			if _, err := writer.Commit(context.Background(), events("u-7", 1)); err != nil {
				t.Error(err)
			}
		}
	}
	var reports []ChainReport
	if _, err := s.VerifyEach(context.Background(), ring, func(cr ChainReport) error {
		reports = append(reports, cr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, cr := range reports {
		if cr.Chain == fresh && (cr.Index == IndexOnly || cr.Anomaly == "removed") {
			t.Fatalf("the sweep used a stale view: %+v", cr)
		}
	}
}

// Checkpoint is paged too: a writer commits between its pages, and every
// chain present at its page still gets its checkpoint.
func TestCheckpoint_WriterGetsTheLockBetweenPages(t *testing.T) {
	tinyPages(t)
	s, signer, _ := setup(t)
	if _, err := s.Commit(context.Background(), events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(s.dir, WithLockTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	betweenPages = func() {
		if _, err := writer.Commit(context.Background(), events("u-98", 1)); err != nil {
			t.Errorf("a writer could not commit between checkpoint pages: %v", err)
			return
		}
		commits++
	}
	done, err := s.Checkpoint(context.Background(), signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if commits < 2 {
		t.Fatalf("only %d commits between pages", commits)
	}
	wrote := 0
	for _, c := range done {
		if c.Problem != "" {
			t.Fatalf("a checkpoint problem: %+v", c)
		}
		if c.File != "" {
			wrote++
		}
	}
	if wrote < 1 {
		t.Fatalf("no checkpoint written: %+v", done)
	}
}

// The 60 ms gap, for real: bbolt retries a held lock every 50 ms and never
// blocks, so only a gap longer than that lets a waiting writer in. A writer
// with a 150 ms lock timeout commits every 100 ms (a consumer between
// batches) while Verify runs over many small pages; every commit gets in.
func TestVerifyEach_GapLetsARetryingWriterIn(t *testing.T) {
	// The real gap and budget, whatever SINK_TINY_PAGES set: this tests them.
	c, g, b := pageMaxChains, pageGap, pageBudget
	pageMaxChains, pageGap, pageBudget = 4, 60*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { pageMaxChains, pageGap, pageBudget = c, g, b })
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var recs []Record
	for i := 0; i < 60; i++ {
		recs = append(recs, events("u-"+string(rune('a'+i%26))+strings.Repeat("x", i/26), 1)...)
	}
	if _, err := s.Commit(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	_, ring := newSigner(t)
	writer, err := Open(s.dir, WithLockTimeout(150*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	commits := 0
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := writer.Commit(context.Background(), events("w-"+string(rune('a'+i%26)), 1)); err != nil {
				done <- err
				return
			}
			commits++
		}
	}()
	if _, err := s.VerifyEach(context.Background(), ring, func(ChainReport) error { return nil }); err != nil {
		t.Fatal(err)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatalf("a writer with a 150 ms lock timeout failed during Verify: %v", err)
	}
	if commits < 3 {
		t.Fatalf("only %d commits during Verify", commits)
	}
}

// A crafted chain id of "" (an evidence key starting with NUL) is reported
// once, and the paged walk moves past it.
func TestVerifyEach_EmptyChainIDEnds(t *testing.T) {
	tinyPages(t)
	s, _, ring := setup(t)
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(store.Entry{EntryID: "x", EntryType: "x", ContentHash: "00"})
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("entries")).Put(append([]byte{0}, make([]byte, 8)...), raw)
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	invalid := 0
	if _, err := s.VerifyEach(ctx, ring, func(cr ChainReport) error {
		if cr.Anomaly == "invalid-id" {
			invalid++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if invalid != 1 {
		t.Fatalf("the empty chain id was reported %d times, want once", invalid)
	}
}

// A forward row that disagrees with a chain the walk already reported comes as
// ONE second row (however many such rows), counted as the same chain.
func TestVerifyEach_IndexDisagreementCountedOnce(t *testing.T) {
	s, _, ring := setup(t)
	chain := cid(t, s, "u-81")
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(forwardBucket)
		for _, subj := range []string{"u-500", "u-501"} { // two other subjects claim the chain
			if err := b.Put([]byte(subj+"\x00"+testClass), []byte(chain)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	rows := 0
	sum, err := s.VerifyEach(context.Background(), ring, func(cr ChainReport) error {
		if cr.Chain == chain {
			rows++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("%d rows for the chain, want its report plus ONE index row", rows)
	}
	if sum.Reports != 3 || sum.Failed != 1 {
		t.Fatalf("summary %+v; want 3 chains, 1 failed", sum)
	}
	r, _ := s.Verify(context.Background(), ring)
	if cr := chainReport(t, r, chain); cr.Index != IndexMalformed || strings.Count(strings.Join(cr.Problems, "|"), "inconsistent") != 1 {
		t.Fatalf("merged report: %+v", cr)
	}
}

// anchors/ swapped for a symlink between the sweep's check and its open is
// refused, not listed: to a folder inside the sink (SameFile catches it) or
// outside it (os.Root refuses to follow).
func TestVerifyEach_AnchorsSwappedWhileRead(t *testing.T) {
	for _, inside := range []bool{true, false} {
		s, _, ring := setup(t)
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		if inside {
			elsewhere = filepath.Join(s.dir, "elsewhere")
		}
		if err := os.MkdirAll(filepath.Join(elsewhere, "events."+strings.Repeat("7", 32)), 0o755); err != nil {
			t.Fatal(err)
		}
		anchors := filepath.Join(s.dir, "anchors")
		target := elsewhere
		if inside {
			target = "elsewhere" // relative: os.Root follows it, so only SameFile catches the swap
		}
		beforeAnchorsOpen = func() {
			_ = os.Rename(anchors, anchors+".moved")
			_ = os.Symlink(target, anchors)
		}
		r, err := s.Verify(context.Background(), ring)
		beforeAnchorsOpen = nil
		if err != nil {
			t.Fatalf("inside=%t: %v", inside, err)
		}
		if cr := chainReport(t, r, "anchors/"); cr.Anomaly != "invalid-folder" {
			t.Fatalf("inside=%t: the swap was not refused: %+v", inside, cr)
		}
		for _, cr := range r.Chains {
			if strings.HasPrefix(cr.Chain, "events.7777") {
				t.Fatalf("inside=%t: the swapped-in folder was listed", inside)
			}
		}
	}
}

// A folder in anchors/ named with an id the sink never mints is reported by
// number, its name never shown.
func TestVerifyEach_InvalidAnchorsFolderName(t *testing.T) {
	s, _, ring := setup(t)
	if err := os.Mkdir(filepath.Join(s.dir, "anchors", "Jo Smith"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReport(t, r, "<invalid anchors folder #1>").Problems) == 0 {
		t.Fatal("not reported")
	}
	for _, cr := range r.Chains {
		if strings.Contains(cr.Chain+strings.Join(cr.Problems, " "), "Jo Smith") {
			t.Fatalf("the name was shown: %+v", cr)
		}
	}
}
