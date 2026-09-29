// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSource_RedeliveryIsNotCommittedTwice(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, ring := newSigner(t)
	batch := append(sourced("u-1", 3, 1), sourced("u-2", 2, 4)...)
	if _, err := s.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}

	// The whole batch again, plus one new record: only the new one lands.
	again := append(batch, sourced("u-1", 1, 6)...)
	got, err := s.Commit(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	want := []Committed{{Chain: "u-1", Entries: 1, Duplicates: 3}, {Chain: "u-2", Entries: 0, Duplicates: 2}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("redelivery: %v, want %v", got, want)
	}
	r := mustVerify(t, s, ring)
	if a, b := chainReport(t, r, "u-1"), chainReport(t, r, "u-2"); a.Entries != 4 || b.Entries != 2 {
		t.Fatalf("chains hold %d and %d entries, want 4 and 2", a.Entries, b.Entries)
	}
}

func TestSource_RepeatedWithinABatch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := sourced("u-1", 1, 7)[0]
	got, err := s.Commit(context.Background(), []Record{r, r, r})
	if err != nil || len(got) != 1 || got[0].Entries != 1 || got[0].Duplicates != 2 {
		t.Fatalf("got %v, %v; want 1 committed, 2 duplicates", got, err)
	}
}

// TestSource_RecordedButNotAppended is the crash the design exists for: the
// position was written, the append never happened. The record must be
// committed — once.
func TestSource_RecordedButNotAppended(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// u-1 already has one entry at seq 0, committed without a source.
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	src, err := openSources(s.sourcesPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	stale := map[string]position{
		"EVIDENCE:1": {entryID: "sink-" + strings.Repeat("a", 32), seq: 1}, // past the tail
		"EVIDENCE:2": {entryID: "sink-" + strings.Repeat("b", 32), seq: 0}, // another entry sits there
	}
	if err := src.putBatch("u-1", stale); err != nil {
		t.Fatal(err)
	}
	src.Close()

	recs := sourced("u-1", 2, 1)
	got, err := s.Commit(ctx, recs)
	if err != nil || got[0].Entries != 2 || got[0].Duplicates != 0 {
		t.Fatalf("stale positions: %v, %v; want both committed", got, err)
	}
	got, err = s.Commit(ctx, recs)
	if err != nil || got[0].Entries != 0 || got[0].Duplicates != 2 {
		t.Fatalf("after commit: %v, %v; want both recognised", got, err)
	}
	if n := len(entryIDs(t, s, "u-1")); n != 3 {
		t.Fatalf("u-1 holds %d entries, want 3", n)
	}
}

func TestSource_PerChain(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, b := sourced("u-1", 1, 1)[0], sourced("u-2", 1, 1)[0] // same Source, different chains
	got, err := s.Commit(context.Background(), []Record{a, b})
	if err != nil || got[0].Entries != 1 || got[1].Entries != 1 {
		t.Fatalf("got %v, %v; the same source on two chains is two records", got, err)
	}
}

func TestSource_Limits(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := events("u-1", 1)[0]
	r.Source = strings.Repeat("x", MaxSourceBytes+1)
	if _, err := s.Commit(context.Background(), []Record{r}); err == nil {
		t.Fatal("an oversized source was accepted")
	}
	// Without any Source, no sources file is created.
	if _, err := s.Commit(context.Background(), events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.sourcesPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a sources file was created with no sourced record: %v", err)
	}
}

// TestSource_MixedBatchOnANonEmptyChain: sourced records at later indexes, among
// unsourced ones, on a chain that already has entries. The predicted positions
// must be exact, or the redelivery below would be committed again.
func TestSource_MixedBatchOnANonEmptyChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 3)); err != nil { // seq 0..2
		t.Fatal(err)
	}
	plain := events("u-1", 2)
	src := sourced("u-1", 2, 50)
	batch := []Record{plain[0], src[0], plain[1], src[1]} // sourced at seq 4 and 6
	if _, err := s.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}
	got, err := s.Commit(ctx, src)
	if err != nil || got[0].Entries != 0 || got[0].Duplicates != 2 {
		t.Fatalf("redelivery of the sourced records: %v, %v; want 2 duplicates", got, err)
	}
	if n := len(entryIDs(t, s, "u-1")); n != 7 {
		t.Fatalf("u-1 holds %d entries, want 7", n)
	}
}
