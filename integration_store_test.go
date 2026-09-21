// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/store/memory"
)

// End-to-end across the store boundary, run against EVERY adapter.
//
// # What this adds over lifecycle_test.go
//
// Those tests hold entries in a slice, so they prove the format composes. These
// put entries through real persistence and read them back, which is where a
// different class of bug lives: an adapter that returns entries out of order, or
// loses timestamp precision, produces a chain that was written correctly and
// verifies as broken.
//
// The matrix is adapter × scenario. A scenario that passes on one adapter and
// fails on another is exactly the kind of divergence the conformance suite is
// meant to prevent, so running the same scenarios against both is the check that
// the suite is sufficient.

// adapters is the matrix axis. Adding an adapter here runs every scenario below
// against it — which is the intended cost of adding one.
var adapters = []struct {
	name string
	open func(t *testing.T) store.Store
}{
	{"memory", func(t *testing.T) store.Store { return memory.New() }},
	{"bolt", func(t *testing.T) store.Store {
		s, err := boltstore.Open(filepath.Join(t.TempDir(), "chain.db"))
		if err != nil {
			t.Fatalf("open bolt: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}},
}

const integChain = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"

// appendChain builds n linked entries and writes them through the store.
//
// This is the shape a real linker has: read the tail, link from it, write. Doing
// it through the port rather than in memory is the point — the tail it links
// from is the tail the STORE reports, not one the test remembered.
func appendChain(t *testing.T, s store.Store, n int) []store.Entry {
	t.Helper()
	ctx := context.Background()

	prevHash, nextSeq := "", int64(0)
	if h, seq, err := s.ReadTail(ctx, integChain); err == nil {
		prevHash, nextSeq = h, seq+1
	} else if !errors.Is(err, store.ErrEmptyChain) {
		t.Fatalf("read tail: %v", err)
	}

	base := time.Date(2026, 1, 20, 12, 0, 0, 123456000, time.UTC)
	out := make([]store.Entry, 0, n)
	for i := 0; i < n; i++ {
		seq := nextSeq + int64(i)
		sum := sha512.Sum512([]byte{byte(seq)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(seq) * time.Second)

		chainHash, err := chainformat.ComputeChainHash(
			prevHash, "run_integration", seq, ts, contentHash)
		if err != nil {
			t.Fatalf("link entry %d: %v", seq, err)
		}
		e := store.Entry{
			ChainID: integChain, EntryID: "entry_" + hex.EncodeToString([]byte{byte(seq)}),
			EntryType: "request", GlobalSeq: seq, RunID: "run_integration",
			SequenceNum: seq, Timestamp: ts, ContentHash: contentHash,
			PreviousHash: prevHash, ChainHash: chainHash,
		}
		out = append(out, e)
		prevHash = chainHash
	}
	if err := s.WriteBatch(ctx, out); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	return out
}

// verifyStored walks a chain read back OUT of the store and returns the index of
// the first break, or -1.
//
// Same two rules as lifecycle_test.go's walkChain, but reading through the port:
// this is what a real verifier does, and it is where an ordering or precision
// bug in an adapter shows up.
func verifyStored(t *testing.T, s store.Store) int {
	t.Helper()
	ctx := context.Background()

	entries, err := s.Range(ctx, integChain, 0, 1<<30, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	previousHash := ""
	for i, e := range entries {
		if chainformat.IsTombstone(e.EntryType, e.EntryID) {
			if !chainformat.ValidateTombstoneContentHash(e.ContentHash) {
				return i
			}
			previousHash = e.ChainHash
			continue
		}
		expected := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, e.Timestamp, e.ContentHash)
		if expected != e.ChainHash {
			return i
		}
		previousHash = expected
	}
	return -1
}

// TestStoreE2E_Matrix runs every scenario against every adapter.
func TestStoreE2E_Matrix(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name string
		run  func(t *testing.T, s store.Store)
	}{
		{"WriteThenVerify", scenarioWriteThenVerify},
		{"AppendAcrossBatches", scenarioAppendAcrossBatches},
		{"TamperIsDetected", scenarioTamperIsDetected},
		{"ErasureDoesNotBreakTheChain", scenarioErasure},
		{"HeadStateTracksTheTail", scenarioHeadState},
		{"LeaseSerialisesAppends", scenarioLease},
	}

	for _, a := range adapters {
		a := a
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			for _, sc := range scenarios {
				sc := sc
				t.Run(sc.name, func(t *testing.T) {
					sc.run(t, a.open(t))
				})
			}
		})
	}
}

func scenarioWriteThenVerify(t *testing.T, s store.Store) {
	appendChain(t, s, 5)
	if idx := verifyStored(t, s); idx != -1 {
		t.Fatalf("a freshly written chain reported a break at index %d", idx)
	}
}

// scenarioAppendAcrossBatches links a second batch from the tail the STORE
// reports, not from a value the test remembered.
//
// That distinction matters: a store whose ReadTail disagrees with its Range
// would produce a chain that is internally inconsistent, and only a test that
// links from the store's own answer can catch it.
func scenarioAppendAcrossBatches(t *testing.T, s store.Store) {
	appendChain(t, s, 3)
	appendChain(t, s, 3)
	appendChain(t, s, 2)

	if idx := verifyStored(t, s); idx != -1 {
		t.Fatalf("chain built over three appends broke at index %d", idx)
	}
	_, seq, err := s.ReadTail(context.Background(), integChain)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if seq != 7 {
		t.Errorf("tail is at %d after 8 entries, want 7", seq)
	}
}

func scenarioTamperIsDetected(t *testing.T, s store.Store) {
	entries := appendChain(t, s, 4)

	tampered := entries[2]
	tampered.ContentHash = flipLastHexNibble(tampered.ContentHash)
	if err := s.WriteBatch(context.Background(), []store.Entry{tampered}); err != nil {
		t.Fatalf("overwrite entry: %v", err)
	}

	if idx := verifyStored(t, s); idx != 2 {
		t.Fatalf("tampering with entry 2 reported a break at index %d, want 2", idx)
	}
}

// scenarioErasure is the case that shipped broken in three SDKs.
func scenarioErasure(t *testing.T, s store.Store) {
	entries := appendChain(t, s, 4)
	ctx := context.Background()

	tombstoneHash, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("generate tombstone: %v", err)
	}
	erased := entries[1]
	erased.EntryType = chainformat.TombstoneEntryType
	erased.EntryID = chainformat.TombstoneEntryIDPrefix + "550e8400-e29b-41d4-a716-446655440000"
	erased.ContentHash = tombstoneHash
	// ChainHash deliberately NOT recomputed — see the chainformat package docs.

	if err := s.WriteBatch(ctx, []store.Entry{erased}); err != nil {
		t.Fatalf("write tombstone: %v", err)
	}
	if idx := verifyStored(t, s); idx != -1 {
		t.Fatalf("a lawfully erased entry broke the chain at index %d", idx)
	}
}

func scenarioHeadState(t *testing.T, s store.Store) {
	ctx := context.Background()
	entries := appendChain(t, s, 3)
	last := entries[len(entries)-1]

	if err := s.PutState(ctx, &store.State{
		ChainID: integChain, HeadSeq: last.GlobalSeq,
		HeadHash: last.ChainHash, ComputedAt: last.Timestamp,
	}); err != nil {
		t.Fatalf("put state: %v", err)
	}
	st, err := s.GetState(ctx, integChain)
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	hash, seq, err := s.ReadTail(ctx, integChain)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if st.HeadSeq != seq || st.HeadHash != hash {
		t.Errorf("stored head state (%d, %s) disagrees with the actual tail (%d, %s)",
			st.HeadSeq, st.HeadHash, seq, hash)
	}
}

func scenarioLease(t *testing.T, s store.Store) {
	ctx := context.Background()

	token, ok, err := s.Acquire(ctx, integChain)
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.Acquire(ctx, integChain); err != nil || ok {
		t.Fatalf("a second appender got the lease: ok=%v err=%v", ok, err)
	}
	if err := s.Release(ctx, integChain, token); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Only after release can another appender proceed — which is what stops two
	// writers linking from the same tail.
	if _, ok, err := s.Acquire(ctx, integChain); err != nil || !ok {
		t.Fatalf("acquire after release: ok=%v err=%v", ok, err)
	}
}

// TestStoreE2E_SurvivesRestart is the scenario the matrix cannot express,
// because only a durable adapter has a restart.
//
// # Why this is the test durability actually needs
//
// A store that keeps everything in a write buffer, or serialises timestamps
// lossily on flush, passes every in-process test — the values it returns are the
// ones it was handed. Closing the database and reopening it forces the data to
// survive a round-trip through the file, which is the only way to find out what
// was really persisted.
//
// It re-derives every chain hash after reopening rather than comparing structs:
// the question is not whether the bytes came back, but whether they came back
// faithfully enough to still verify.
func TestStoreE2E_SurvivesRestart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.db")
	ctx := context.Background()

	s, err := boltstore.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	written := appendChain(t, s, 6)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// ---- process restart ----

	reopened, err := boltstore.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	if idx := verifyStored(t, reopened); idx != -1 {
		t.Fatalf("chain broke at index %d after a restart — something was not "+
			"persisted faithfully", idx)
	}

	entries, err := reopened.Range(ctx, integChain, 0, 1<<30, 0)
	if err != nil {
		t.Fatalf("range after reopen: %v", err)
	}
	if len(entries) != len(written) {
		t.Fatalf("read back %d entries, wrote %d", len(entries), len(written))
	}
	for i := range entries {
		if entries[i].ChainHash != written[i].ChainHash {
			t.Fatalf("entry %d changed across the restart", i)
		}
		if !entries[i].Timestamp.Equal(written[i].Timestamp) {
			t.Fatalf("entry %d lost timestamp precision across the restart:\n"+
				"  wrote %v\n  read  %v", i, written[i].Timestamp, entries[i].Timestamp)
		}
	}

	// A chain must be extendable after a restart, linking from the persisted tail.
	appendChain(t, reopened, 2)
	if idx := verifyStored(t, reopened); idx != -1 {
		t.Fatalf("appending after a restart broke the chain at index %d", idx)
	}
}

// TestStoreE2E_AdaptersAgree runs one identical sequence through every adapter
// and asserts they produce the same chain.
//
// The conformance suite checks each adapter against the CONTRACT. This checks
// them against EACH OTHER, which catches a contract that is underspecified —
// two adapters can both satisfy a loose contract and still disagree.
func TestStoreE2E_AdaptersAgree(t *testing.T) {
	t.Parallel()

	results := make(map[string][]store.Entry, len(adapters))
	for _, a := range adapters {
		s := a.open(t)
		appendChain(t, s, 4)
		appendChain(t, s, 3)

		got, err := s.Range(context.Background(), integChain, 0, 1<<30, 0)
		if err != nil {
			t.Fatalf("%s: range: %v", a.name, err)
		}
		results[a.name] = got
	}

	reference := results[adapters[0].name]
	for _, a := range adapters[1:] {
		got := results[a.name]
		if len(got) != len(reference) {
			t.Fatalf("%s returned %d entries, %s returned %d",
				a.name, len(got), adapters[0].name, len(reference))
		}
		for i := range got {
			if got[i].ChainHash != reference[i].ChainHash ||
				got[i].GlobalSeq != reference[i].GlobalSeq {
				t.Fatalf("adapters disagree at index %d: %s has seq=%d hash=%s, %s has seq=%d hash=%s",
					i, a.name, got[i].GlobalSeq, got[i].ChainHash[:16],
					adapters[0].name, reference[i].GlobalSeq, reference[i].ChainHash[:16])
			}
		}
	}
}
