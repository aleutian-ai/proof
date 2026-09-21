// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package storetest is the conformance suite every store adapter must pass.
//
// # Why this exists
//
// Without a shared suite, each adapter is tested against its author's reading of
// the port, and the adapters drift until the port is a suggestion rather than a
// contract. Worse, the drift is invisible: both adapters pass their own tests
// while disagreeing about what ordering, atomicity, or "not found" mean.
//
// Building this against the simplest adapter means later adapters inherit a
// ready-made acceptance test rather than inventing one — and a bolt adapter that
// passes the same suite as the in-memory one is interchangeable with it in a way
// that can be checked rather than asserted.
//
// # Usage
//
//	func TestConformance(t *testing.T) {
//	    storetest.Run(t, func(t *testing.T) store.Store { return memory.New() })
//	}
package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// Factory returns a fresh, empty store for one subtest.
//
// Each subtest gets its own store so ordering between them cannot matter — a
// suite whose tests must run in sequence hides state leaks between them.
type Factory func(t *testing.T) store.Store

const testChain = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"

// entryAt builds a deterministic entry at the given global sequence.
//
// The timestamp deliberately carries non-zero microseconds: it is hash input, so
// a fixture using whole seconds would never exercise the precision requirement
// the port states.
func entryAt(seq int64, prevHash string) store.Entry {
	// Exactly 128 lowercase hex chars, distinct per sequence number.
	contentHash := fmt.Sprintf("%0128x", seq)

	ts := time.Date(2026, 1, 20, 12, 0, 0, 123456000, time.UTC).
		Add(time.Duration(seq) * time.Second)

	return store.Entry{
		ChainID:      testChain,
		EntryID:      fmt.Sprintf("entry_%d", seq),
		EntryType:    "request",
		GlobalSeq:    seq,
		RunID:        "run_550e8400-e29b-41d4-a716-446655440000",
		SequenceNum:  seq,
		Timestamp:    ts,
		ContentHash:  contentHash,
		PreviousHash: prevHash,
		ChainHash: chainformat.ComputeChainHashUnchecked(
			prevHash, "run_550e8400-e29b-41d4-a716-446655440000", seq, ts, contentHash),
	}
}

// chainOf builds n linked entries.
func chainOf(n int64) []store.Entry {
	out := make([]store.Entry, 0, n)
	prev := ""
	for i := int64(0); i < n; i++ {
		e := entryAt(i, prev)
		out = append(out, e)
		prev = e.ChainHash
	}
	return out
}

// Run executes the full conformance suite against an adapter.
func Run(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("EmptyChain", func(t *testing.T) { testEmptyChain(t, newStore(t)) })
	t.Run("AppendAndReadTail", func(t *testing.T) { testAppendAndReadTail(t, newStore(t)) })
	t.Run("RangeIsAscending", func(t *testing.T) { testRangeIsAscending(t, newStore(t)) })
	t.Run("RangeOrderingTorture", func(t *testing.T) { testRangeOrderingTorture(t, newStore(t)) })
	t.Run("Bounds", func(t *testing.T) { testBounds(t, newStore(t)) })
	t.Run("ByID", func(t *testing.T) { testByID(t, newStore(t)) })
	t.Run("Predecessor", func(t *testing.T) { testPredecessor(t, newStore(t)) })
	t.Run("State", func(t *testing.T) { testState(t, newStore(t)) })
	t.Run("Lease", func(t *testing.T) { testLease(t, newStore(t)) })
	t.Run("TimestampFidelity", func(t *testing.T) { testTimestampFidelity(t, newStore(t)) })
	t.Run("ChainsAreIndependent", func(t *testing.T) { testChainsAreIndependent(t, newStore(t)) })
	t.Run("WriteIsUpsert", func(t *testing.T) { testWriteIsUpsert(t, newStore(t)) })
}

// testWriteIsUpsert asserts that writing an entry at an existing
// (ChainID, GlobalSeq) REPLACES it rather than adding a duplicate.
//
// # Why this is contract, not an implementation detail
//
// Erasure works by rewriting an entry in place: same position, same chain hash,
// content hash replaced by a tombstone value. An adapter that appends instead of
// replacing leaves BOTH rows in the chain, and a verifier then walks an entry
// that no longer exists — reporting a break on an intact chain, one position
// later than the real problem.
//
// This gap was found by the cross-adapter integration matrix, not by this suite:
// every other test here writes each sequence exactly once, so an append-only
// adapter passed all of them.
func testWriteIsUpsert(t *testing.T, s store.Store) {
	ctx := context.Background()

	original := chainOf(3)
	if err := s.WriteBatch(ctx, original); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	// Rewrite the middle entry in place, exactly as erasure does.
	revised := original[1]
	revised.EntryType = "tombstone"
	revised.EntryID = "tomb_" + revised.EntryID
	revised.ContentHash = "TOMBSTONE:00000000000000000000000000000000000000000000000000000000000000ab"
	if err := s.WriteBatch(ctx, []store.Entry{revised}); err != nil {
		t.Fatalf("WriteBatch rewrite: %v", err)
	}

	got, err := s.Range(ctx, testChain, 0, 100, 0)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("chain has %d entries after rewriting one in place, want 3 — the "+
			"adapter appended a duplicate instead of replacing it", len(got))
	}
	if got[1].EntryType != "tombstone" {
		t.Errorf("entry at position 1 is %q, want the rewritten tombstone", got[1].EntryType)
	}
	// The chain hash survives the rewrite, and neighbours are undisturbed.
	if got[1].ChainHash != original[1].ChainHash {
		t.Errorf("rewriting the entry changed its chain hash")
	}
	if got[0].GlobalSeq != 0 || got[2].GlobalSeq != 2 {
		t.Errorf("rewriting one entry disturbed its neighbours")
	}

	// The replacement is reachable by its NEW id.
	if _, err := s.ByID(ctx, revised.EntryID); err != nil {
		t.Errorf("ByID(%s) after the rewrite: %v", revised.EntryID, err)
	}

	// And the OLD id must be gone.
	//
	// Erasure swaps entry_* for a fresh tomb_* id. If the old id still resolved,
	// anyone holding it could look it up, receive the tombstone, and confirm that
	// THAT specific entry was erased. The tombstone's content hash is random
	// precisely to prevent that correlation, so a surviving id would undo the
	// design — an anti-correlation property enforced in the index, not just the
	// hash.
	if _, err := s.ByID(ctx, original[1].EntryID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ByID(%s) after that id was replaced = %v, want ErrNotFound — a "+
			"stale id lets a holder confirm which entry was erased",
			original[1].EntryID, err)
	}
}

// testEmptyChain asserts an empty chain is a normal condition, not an error.
func testEmptyChain(t *testing.T, s store.Store) {
	ctx := context.Background()

	if _, _, err := s.ReadTail(ctx, testChain); !errors.Is(err, store.ErrEmptyChain) {
		t.Errorf("ReadTail on an empty chain = %v, want ErrEmptyChain", err)
	}
	if _, _, err := s.Bounds(ctx, testChain); !errors.Is(err, store.ErrEmptyChain) {
		t.Errorf("Bounds on an empty chain = %v, want ErrEmptyChain", err)
	}
	if _, err := s.GetState(ctx, testChain); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetState with no state = %v, want ErrNotFound", err)
	}
	if _, err := s.ByID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ByID for a missing entry = %v, want ErrNotFound", err)
	}
}

func testAppendAndReadTail(t *testing.T, s store.Store) {
	ctx := context.Background()
	entries := chainOf(5)

	if err := s.WriteBatch(ctx, entries); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	hash, seq, err := s.ReadTail(ctx, testChain)
	if err != nil {
		t.Fatalf("ReadTail: %v", err)
	}
	last := entries[len(entries)-1]
	if hash != last.ChainHash || seq != last.GlobalSeq {
		t.Errorf("ReadTail = (%s, %d), want (%s, %d)", hash, seq, last.ChainHash, last.GlobalSeq)
	}
}

// testRangeIsAscending pins that Range returns entries in sequence order, across
// a batch boundary.
//
// Verification links each entry to the one before it, so an out-of-order result
// reports breaks on an intact chain.
func testRangeIsAscending(t *testing.T, s store.Store) {
	ctx := context.Background()
	all := chainOf(6)

	// Two batches, so an adapter that only orders within a batch fails here.
	if err := s.WriteBatch(ctx, all[:3]); err != nil {
		t.Fatalf("WriteBatch 1: %v", err)
	}
	if err := s.WriteBatch(ctx, all[3:]); err != nil {
		t.Fatalf("WriteBatch 2: %v", err)
	}

	got, err := s.Range(ctx, testChain, 0, 5, 0)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("Range returned %d entries, want 6", len(got))
	}
	for i, e := range got {
		if e.GlobalSeq != int64(i) {
			t.Fatalf("Range not ascending: position %d has GlobalSeq %d", i, e.GlobalSeq)
		}
	}
}

// testRangeOrderingTorture is the test that catches a wrong key encoding.
//
// An adapter over a byte-ordered store that encodes sequence numbers as decimal
// strings sorts "10" before "9". Every other test here uses small contiguous
// sequences and would pass; this one does not.
func testRangeOrderingTorture(t *testing.T, s store.Store) {
	ctx := context.Background()

	seqs := []int64{1, 2, 9, 10, 11, 100, 101, 255, 256, 1000}
	entries := make([]store.Entry, 0, len(seqs))
	prev := ""
	for _, seq := range seqs {
		e := entryAt(seq, prev)
		entries = append(entries, e)
		prev = e.ChainHash
	}
	if err := s.WriteBatch(ctx, entries); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	got, err := s.Range(ctx, testChain, 0, 100000, 0)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(got) != len(seqs) {
		t.Fatalf("Range returned %d entries, want %d", len(got), len(seqs))
	}
	for i, want := range seqs {
		if got[i].GlobalSeq != want {
			t.Fatalf("position %d has GlobalSeq %d, want %d — sequence numbers are "+
				"not sorting numerically. Encode them as fixed-width big-endian.",
				i, got[i].GlobalSeq, want)
		}
	}

	// A bounded range must respect its endpoints, not just the full scan.
	mid, err := s.Range(ctx, testChain, 10, 101, 0)
	if err != nil {
		t.Fatalf("bounded Range: %v", err)
	}
	if len(mid) != 4 { // 10, 11, 100, 101
		t.Fatalf("Range(10,101) returned %d entries, want 4", len(mid))
	}
	if mid[0].GlobalSeq != 10 || mid[len(mid)-1].GlobalSeq != 101 {
		t.Fatalf("Range(10,101) = [%d..%d], want [10..101]",
			mid[0].GlobalSeq, mid[len(mid)-1].GlobalSeq)
	}

	// limit truncates from the START of the range, keeping ascending order.
	lim, err := s.Range(ctx, testChain, 0, 100000, 3)
	if err != nil {
		t.Fatalf("limited Range: %v", err)
	}
	if len(lim) != 3 || lim[0].GlobalSeq != 1 {
		t.Fatalf("Range with limit 3 = %d entries starting at %d, want 3 starting at 1",
			len(lim), lim[0].GlobalSeq)
	}
}

func testBounds(t *testing.T, s store.Store) {
	ctx := context.Background()

	if err := s.WriteBatch(ctx, []store.Entry{entryAt(7, "")}); err != nil {
		t.Fatalf("WriteBatch single: %v", err)
	}
	min, max, err := s.Bounds(ctx, testChain)
	if err != nil {
		t.Fatalf("Bounds: %v", err)
	}
	if min != 7 || max != 7 {
		t.Errorf("Bounds with one entry = (%d, %d), want (7, 7)", min, max)
	}

	more := chainOf(4)
	if err := s.WriteBatch(ctx, more); err != nil {
		t.Fatalf("WriteBatch many: %v", err)
	}
	min, max, err = s.Bounds(ctx, testChain)
	if err != nil {
		t.Fatalf("Bounds: %v", err)
	}
	if min != 0 || max != 7 {
		t.Errorf("Bounds = (%d, %d), want (0, 7)", min, max)
	}
}

func testByID(t *testing.T, s store.Store) {
	ctx := context.Background()
	entries := chainOf(3)
	if err := s.WriteBatch(ctx, entries); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	got, err := s.ByID(ctx, entries[1].EntryID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.GlobalSeq != entries[1].GlobalSeq || got.ChainHash != entries[1].ChainHash {
		t.Errorf("ByID returned the wrong entry")
	}
	if _, err := s.ByID(ctx, "entry_does_not_exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ByID for a missing entry = %v, want ErrNotFound", err)
	}
}

// testPredecessor covers the head case, where absence is meaningful.
func testPredecessor(t *testing.T, s store.Store) {
	ctx := context.Background()
	entries := chainOf(4)
	if err := s.WriteBatch(ctx, entries); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	got, err := s.Predecessor(ctx, testChain, 2)
	if err != nil {
		t.Fatalf("Predecessor(2): %v", err)
	}
	if got.GlobalSeq != 1 {
		t.Errorf("Predecessor(2) has GlobalSeq %d, want 1", got.GlobalSeq)
	}

	// The first entry has none, and that must be ErrNotFound rather than a nil
	// entry with a nil error — a verifier starting at the head needs to tell
	// "nothing precedes this" from "the lookup silently returned nothing".
	if _, err := s.Predecessor(ctx, testChain, 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Predecessor at the chain head = %v, want ErrNotFound", err)
	}
}

func testState(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Date(2026, 1, 20, 12, 0, 0, 654321000, time.UTC)

	want := &store.State{ChainID: testChain, HeadSeq: 42, HeadHash: "abc", ComputedAt: now}
	if err := s.PutState(ctx, want); err != nil {
		t.Fatalf("PutState: %v", err)
	}
	got, err := s.GetState(ctx, testChain)
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if got.HeadSeq != 42 || got.HeadHash != "abc" {
		t.Errorf("GetState = (%d, %s), want (42, abc)", got.HeadSeq, got.HeadHash)
	}
	if !got.ComputedAt.Equal(now) {
		t.Errorf("ComputedAt round-trip lost precision: got %v, want %v", got.ComputedAt, now)
	}

	// PutState replaces rather than accumulates.
	if err := s.PutState(ctx, &store.State{ChainID: testChain, HeadSeq: 43, HeadHash: "def", ComputedAt: now}); err != nil {
		t.Fatalf("PutState replace: %v", err)
	}
	got, err = s.GetState(ctx, testChain)
	if err != nil {
		t.Fatalf("GetState after replace: %v", err)
	}
	if got.HeadSeq != 43 || got.HeadHash != "def" {
		t.Errorf("PutState did not replace: got (%d, %s)", got.HeadSeq, got.HeadHash)
	}
}

func testLease(t *testing.T, s store.Store) {
	ctx := context.Background()

	token, ok, err := s.Acquire(ctx, testChain)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !ok {
		t.Fatal("first Acquire on a free lease failed")
	}

	// Contention is an expected outcome, not an error.
	if _, ok2, err := s.Acquire(ctx, testChain); err != nil {
		t.Fatalf("second Acquire returned an error; contention must be reported as ok=false: %v", err)
	} else if ok2 {
		t.Fatal("the lease was granted twice — two appenders would link from the same tail")
	}

	if err := s.Release(ctx, testChain, token); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok, err := s.Acquire(ctx, testChain); err != nil || !ok {
		t.Fatalf("Acquire after Release failed: ok=%v err=%v", ok, err)
	}
}

// testTimestampFidelity is the test the port's precision requirement exists for.
//
// The timestamp is hash INPUT. An adapter that persists it with less than
// microsecond precision produces entries whose chain hash cannot be reproduced
// after a round-trip — and the failure surfaces much later, as an unverifiable
// chain rather than as a storage error. So this does not compare timestamps: it
// re-derives the chain hash from the stored entry and compares THAT.
func testTimestampFidelity(t *testing.T, s store.Store) {
	ctx := context.Background()

	e := entryAt(0, "")
	if e.Timestamp.Nanosecond() == 0 {
		t.Fatal("fixture is wrong: the timestamp has no sub-second component to lose")
	}
	if err := s.WriteBatch(ctx, []store.Entry{e}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	got, err := s.ByID(ctx, e.EntryID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}

	rederived := chainformat.ComputeChainHashUnchecked(
		got.PreviousHash, got.RunID, got.SequenceNum, got.Timestamp, got.ContentHash)
	if rederived != e.ChainHash {
		t.Fatalf("chain hash could not be re-derived after a storage round-trip.\n"+
			"  stored:    %s\n  re-derived: %s\n"+
			"The timestamp almost certainly lost precision. Adapters MUST persist it "+
			"losslessly to at least microsecond precision — see the store package docs.",
			e.ChainHash, rederived)
	}
}

// testChainsAreIndependent pins that chains do not bleed into each other.
//
// An adapter that keys entries by sequence number alone — forgetting the chain
// id — passes every single-chain test here and corrupts the moment a second
// chain exists.
func testChainsAreIndependent(t *testing.T, s store.Store) {
	ctx := context.Background()

	chainA := chainOf(3)
	chainB := chainOf(2)
	for i := range chainB {
		chainB[i].ChainID = "comp_01OTHERTENANT00000000000"
		chainB[i].EntryID = "other_" + chainB[i].EntryID
	}

	if err := s.WriteBatch(ctx, chainA); err != nil {
		t.Fatalf("WriteBatch A: %v", err)
	}
	if err := s.WriteBatch(ctx, chainB); err != nil {
		t.Fatalf("WriteBatch B: %v", err)
	}

	gotA, err := s.Range(ctx, testChain, 0, 100, 0)
	if err != nil {
		t.Fatalf("Range A: %v", err)
	}
	if len(gotA) != 3 {
		t.Fatalf("chain A has %d entries, want 3 — entries from another chain leaked in", len(gotA))
	}
	for _, e := range gotA {
		if e.ChainID != testChain {
			t.Fatalf("chain A contains an entry from %s", e.ChainID)
		}
	}

	_, seq, err := s.ReadTail(ctx, "comp_01OTHERTENANT00000000000")
	if err != nil {
		t.Fatalf("ReadTail B: %v", err)
	}
	if seq != 1 {
		t.Errorf("chain B tail is at %d, want 1", seq)
	}
}
