// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/aleutian-ai/proof/store"
)

// runChainsUpdater runs the ChainsUpdater cases when the adapter implements
// the capability, and says so when it does not: an adapter is allowed to lack
// it, but not to half-implement it.
func runChainsUpdater(t *testing.T, newStore Factory) {
	t.Helper()
	probe := newStore(t)
	if _, ok := probe.(store.ChainsUpdater); !ok {
		t.Run("ChainsUpdater", func(t *testing.T) { t.Skip("adapter does not implement store.ChainsUpdater") })
		return
	}
	updater := func(t *testing.T) (store.Store, store.ChainsUpdater) {
		s := newStore(t)
		return s, s.(store.ChainsUpdater)
	}
	t.Run("ChainsUpdater/TailsFollowTheOrderOfChainIDs", func(t *testing.T) { testUpdaterTailOrder(t, updater) })
	t.Run("ChainsUpdater/WritesEveryChain", func(t *testing.T) { testUpdaterWritesAll(t, updater) })
	t.Run("ChainsUpdater/FnErrorWritesNothing", func(t *testing.T) { testUpdaterFnError(t, updater) })
	t.Run("ChainsUpdater/BadOutputWritesNothing", func(t *testing.T) { testUpdaterBadOutput(t, updater) })
	t.Run("ChainsUpdater/LeaseRefuses", func(t *testing.T) { testUpdaterLease(t, updater) })
	t.Run("ChainsUpdater/InputValidation", func(t *testing.T) { testUpdaterInputs(t, updater) })
	t.Run("ChainsUpdater/AppendOnly", func(t *testing.T) { testUpdaterAppendOnly(t, updater) })
	t.Run("ChainsUpdater/PrefixChainIDs", func(t *testing.T) { testUpdaterPrefixIDs(t, updater) })
	t.Run("ChainsUpdater/NULRefused", func(t *testing.T) { testUpdaterNUL(t, updater) })
	t.Run("ChainsUpdater/LeaseKeepsState", func(t *testing.T) { testUpdaterLeaseKeepsState(t, updater) })
}

type updaterFactory func(t *testing.T) (store.Store, store.ChainsUpdater)

// entriesFor builds n linked entries on chainID, starting after tail.
func entriesFor(chainID string, tail store.Tail, n int64) []store.Entry {
	prev, next := "", int64(0)
	if !tail.Empty {
		prev, next = tail.Hash, tail.GlobalSeq+1
	}
	out := make([]store.Entry, 0, n)
	for i := int64(0); i < n; i++ {
		e := entryAt(next+i, prev)
		e.ChainID = chainID
		e.EntryID = chainID + "-" + e.EntryID
		out = append(out, e)
		prev = e.ChainHash
	}
	return out
}

func stateAfter(entries []store.Entry) store.State {
	last := entries[len(entries)-1]
	return store.State{ChainID: last.ChainID, HeadSeq: last.GlobalSeq, HeadHash: last.ChainHash}
}

// seed writes n entries to chainID through the ordinary WriteBatch.
func seed(t *testing.T, s store.Store, chainID string, n int64) {
	t.Helper()
	if n == 0 {
		return
	}
	if err := s.WriteBatch(context.Background(), entriesFor(chainID, store.Tail{Empty: true}, n)); err != nil {
		t.Fatalf("seed %s: %v", chainID, err)
	}
}

func tailOf(t *testing.T, s store.Store, chainID string) (string, int64, bool) {
	t.Helper()
	h, seq, err := s.ReadTail(context.Background(), chainID)
	if errors.Is(err, store.ErrEmptyChain) {
		return "", 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return h, seq, true
}

// The tails fn receives follow chainIDs' order, each describing its own chain:
// a multi-chain API must never pair a tail with the wrong chain.
func testUpdaterTailOrder(t *testing.T, newStore updaterFactory) {
	s, u := newStore(t)
	seed(t, s, "a", 2)
	seed(t, s, "c", 1)
	aHash, aSeq, _ := tailOf(t, s, "a")
	cHash, cSeq, _ := tailOf(t, s, "c")
	ids := []string{"c", "b", "a"}
	var got []store.Tail
	if err := u.UpdateChains(context.Background(), ids, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		got = tails
		return nil, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []store.Tail{
		{ChainID: "c", Hash: cHash, GlobalSeq: cSeq},
		{ChainID: "b", Empty: true},
		{ChainID: "a", Hash: aHash, GlobalSeq: aSeq},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tails, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tail %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Entries and states for several chains land on their own chains, together.
func testUpdaterWritesAll(t *testing.T, newStore updaterFactory) {
	ctx := context.Background()
	s, u := newStore(t)
	seed(t, s, "a", 3)
	var written map[string][]store.Entry
	if err := u.UpdateChains(ctx, []string{"a", "b"}, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		written = map[string][]store.Entry{
			"a": entriesFor("a", tails[0], 2),
			"b": entriesFor("b", tails[1], 1),
		}
		entries := append(append([]store.Entry{}, written["a"]...), written["b"]...)
		return entries, []store.State{stateAfter(written["a"]), stateAfter(written["b"])}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for id, es := range written {
		h, seq, ok := tailOf(t, s, id)
		last := es[len(es)-1]
		if !ok || h != last.ChainHash || seq != last.GlobalSeq {
			t.Fatalf("chain %s tail = %s@%d, want %s@%d", id, h, seq, last.ChainHash, last.GlobalSeq)
		}
		st, err := s.GetState(ctx, id)
		if err != nil || st.HeadHash != last.ChainHash || st.HeadSeq != last.GlobalSeq {
			t.Fatalf("chain %s state = %+v, %v", id, st, err)
		}
	}
	if _, seq, _ := tailOf(t, s, "a"); seq != 4 {
		t.Fatalf("chain a continued at the wrong sequence: tail %d, want 4", seq)
	}
}

// An error from fn is returned unchanged, and nothing is written.
func testUpdaterFnError(t *testing.T, newStore updaterFactory) {
	ctx := context.Background()
	s, u := newStore(t)
	sentinel := errors.New("fn refused")
	err := u.UpdateChains(ctx, []string{"a"}, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		return entriesFor("a", tails[0], 1), nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want fn's error", err)
	}
	if _, _, ok := tailOf(t, s, "a"); ok {
		t.Fatal("entries were written although fn failed")
	}
}

// Output that cannot be written as a whole writes nothing: an entry for a
// chain the call did not name, or an invalid entry, among valid ones.
func testUpdaterBadOutput(t *testing.T, newStore updaterFactory) {
	cases := map[string]func(tails []store.Tail) ([]store.Entry, []store.State, error){
		"entry for an unnamed chain": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			return append(entriesFor("a", tails[0], 1), entriesFor("z", store.Tail{Empty: true}, 1)...), nil, nil
		},
		"state for an unnamed chain": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 1)
			return es, []store.State{stateAfter(es), {ChainID: "z", HeadSeq: 0, HeadHash: "x"}}, nil
		},
		"invalid entry among valid ones": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 2)
			es[1].EntryID = ""
			return es, nil, nil
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, u := newStore(t)
			if err := u.UpdateChains(ctx, []string{"a"}, fn); err == nil {
				t.Fatal("bad output was accepted")
			}
			if _, _, ok := tailOf(t, s, "a"); ok {
				t.Fatal("part of a refused call was written")
			}
			if _, err := s.GetState(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a state was written by a refused call: %v", err)
			}
		})
	}
}

// A leased chain refuses the whole call before fn runs, and nothing is
// written to any chain; once released, the call succeeds.
func testUpdaterLease(t *testing.T, newStore updaterFactory) {
	ctx := context.Background()
	s, u := newStore(t)
	token, ok, err := s.Acquire(ctx, "b")
	if err != nil || !ok {
		t.Fatalf("Acquire: %v %v", ok, err)
	}
	called := false
	fn := func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		called = true
		return append(entriesFor("a", tails[0], 1), entriesFor("b", tails[1], 1)...), nil, nil
	}
	err = u.UpdateChains(ctx, []string{"a", "b"}, fn)
	if !errors.Is(err, store.ErrChainLeased) || called {
		t.Fatalf("err = %v, fn called = %v; want ErrChainLeased before fn", err, called)
	}
	if _, _, ok := tailOf(t, s, "a"); ok {
		t.Fatal("an unleased chain was written by a refused call")
	}
	if err := s.Release(ctx, "b", token); err != nil {
		t.Fatal(err)
	}
	if err := u.UpdateChains(ctx, []string{"a", "b"}, fn); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// Malformed chain lists are refused before fn runs.
func testUpdaterInputs(t *testing.T, newStore updaterFactory) {
	for name, ids := range map[string][]string{
		"no chains": nil,
		"empty id":  {"a", ""},
		"duplicate": {"a", "b", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			_, u := newStore(t)
			called := false
			err := u.UpdateChains(context.Background(), ids, func([]store.Tail) ([]store.Entry, []store.State, error) {
				called = true
				return nil, nil, nil
			})
			if err == nil || called {
				t.Fatalf("err = %v, fn called = %v; want a refusal before fn", err, called)
			}
		})
	}
}

// UpdateChains is an APPEND: each chain's entries must continue its tail
// contiguously, and each state must be that chain's last written entry.
// Anything else (an overwrite of history, a gap, a head no entry produced)
// is refused and nothing is written.
func testUpdaterAppendOnly(t *testing.T, newStore updaterFactory) {
	cases := map[string]func(tails []store.Tail) ([]store.Entry, []store.State, error){
		"overwrites the tail": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 1)
			es[0].GlobalSeq = tails[0].GlobalSeq // the existing last entry
			return es, nil, nil
		},
		"leaves a gap": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 2)
			es[1].GlobalSeq++
			return es, nil, nil
		},
		"state names a sequence not written": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 2)
			st := stateAfter(es)
			st.HeadSeq++
			return es, []store.State{st}, nil
		},
		"state names a hash not written": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 2)
			st := stateAfter(es)
			st.HeadHash = es[0].ChainHash
			return es, []store.State{st}, nil
		},
		"state for a chain with no entries in the call": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			return nil, []store.State{{ChainID: "a", HeadSeq: 9, HeadHash: "x"}}, nil
		},
		"does not link to the entry before": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("a", tails[0], 1)
			es[0].PreviousHash = "not-the-tail"
			return es, nil, nil
		},
		"negative sequence": func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			es := entriesFor("b", tails[1], 1)
			es[0].GlobalSeq = -1
			return es, nil, nil
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, u := newStore(t)
			seed(t, s, "a", 2)
			hash, seq, _ := tailOf(t, s, "a")
			if err := u.UpdateChains(ctx, []string{"a", "b"}, fn); err == nil {
				t.Fatal("a non-append was accepted")
			}
			if h, q, _ := tailOf(t, s, "a"); h != hash || q != seq {
				t.Fatal("chain a changed")
			}
			if _, _, ok := tailOf(t, s, "b"); ok {
				t.Fatal("chain b was written")
			}
		})
	}
}

// A chain id that is a prefix of another ("a" beside "ab") gets its own tail.
func testUpdaterPrefixIDs(t *testing.T, newStore updaterFactory) {
	s, u := newStore(t)
	seed(t, s, "a", 3)
	seed(t, s, "ab", 1)
	aHash, aSeq, _ := tailOf(t, s, "a")
	abHash, abSeq, _ := tailOf(t, s, "ab")
	var got []store.Tail
	if err := u.UpdateChains(context.Background(), []string{"ab", "a"}, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		got = tails
		return nil, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got[0] != (store.Tail{ChainID: "ab", Hash: abHash, GlobalSeq: abSeq}) ||
		got[1] != (store.Tail{ChainID: "a", Hash: aHash, GlobalSeq: aSeq}) {
		t.Fatalf("tails = %+v", got)
	}
}

// A NUL in a chain id is refused by every adapter (bolt keys would collide).
func testUpdaterNUL(t *testing.T, newStore updaterFactory) {
	_, u := newStore(t)
	called := false
	if err := u.UpdateChains(context.Background(), []string{"a\x00b"}, func([]store.Tail) ([]store.Entry, []store.State, error) {
		called = true
		return nil, nil, nil
	}); err == nil || called {
		t.Fatalf("a chain id with NUL was accepted (fn called = %v)", called)
	}
}

// A refused (leased) call leaves the head states untouched too.
func testUpdaterLeaseKeepsState(t *testing.T, newStore updaterFactory) {
	ctx := context.Background()
	s, u := newStore(t)
	seed(t, s, "a", 1)
	before := store.State{ChainID: "a", HeadSeq: 0, HeadHash: "before"}
	if err := s.PutState(ctx, &before); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Acquire(ctx, "a"); err != nil || !ok {
		t.Fatal("acquire")
	}
	_ = u.UpdateChains(ctx, []string{"a"}, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		es := entriesFor("a", tails[0], 1)
		return es, []store.State{stateAfter(es)}, nil
	})
	if st, err := s.GetState(ctx, "a"); err != nil || st.HeadHash != "before" {
		t.Fatalf("state after a refused call = %+v, %v", st, err)
	}
}
