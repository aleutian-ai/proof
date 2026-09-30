// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/verify"
)

// The pinned V3 heads of TestAppendChains_V3Golden.
const (
	goldenV3HeadA = "ec74899ecca32fb06dbcfe9516ab4522c4701cb34e053d4b30d4821de6c653f6dc711fc85395297a811ee8db3e034ea46b92d3633fdb818ffdf93a3095af8a1d"
	goldenV3HeadB = "51f1132db1ad40c5a7cd5897f0eedfe874fb141595a31b6da807862ede41ebf95775e9fdf6f27b2d8282d89d74c8e95362b5ce6785e659a9875e57a1b0fc858d"
)

// inputsFor builds n inputs for a chain, with distinct content and strictly
// increasing arrival times from base.
func inputsFor(chain string, n int, base time.Time) []Input {
	out := make([]Input, n)
	for i := range out {
		ts := base.Add(time.Duration(i) * time.Microsecond)
		out[i] = Input{
			EntryID:     fmt.Sprintf("%s-%d-%d", chain, base.UnixNano(), i),
			EntryType:   "event",
			Timestamp:   ts,
			IngestedAt:  ts,
			ContentHash: fmt.Sprintf("%0128x", len(chain)*100000+int(base.UnixMicro()%100000)+i),
		}
	}
	return out
}

func allEntries(t *testing.T, s store.Store, chain string) []store.Entry {
	t.Helper()
	es, err := s.Range(context.Background(), chain, 0, 1<<62, 0)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// storeFactories are the stores the property test runs on: the invariant must
// hold on every ChainsUpdater, not only the simplest.
func storeFactories(t *testing.T) map[string]func() store.Store {
	return map[string]func() store.Store{
		"memory": func() store.Store { return memory.New() },
		"bolt": func() store.Store {
			s, err := boltstore.Open(filepath.Join(t.TempDir(), "chains.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	}
}

// shuffledWithTies builds n inputs whose arrival times tie in pairs and whose
// order is shuffled: the linker's copy-and-sort (IngestedAt, then EntryID) must
// decide the order, identically on both paths.
func shuffledWithTies(rng *rand.Rand, chain string, n int, base time.Time) []Input {
	in := inputsFor(chain, n, base)
	for i := range in {
		in[i].IngestedAt = base.Add(time.Duration(i/2) * time.Microsecond)
	}
	rng.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
	return in
}

// verifyAll runs the independent verifier over every chain of a store.
func verifyAll(t *testing.T, s store.Store, chains []string) {
	t.Helper()
	for _, c := range chains {
		es := allEntries(t, s, c)
		if len(es) == 0 {
			continue
		}
		ve := make([]verify.Entry, len(es))
		for i, e := range es {
			ve[i] = verify.Entry{EntryID: e.EntryID, EntryType: e.EntryType,
				Timestamp:     e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
				FormatVersion: e.FormatVersion, GlobalSeq: e.GlobalSeq,
				ContentHash: e.ContentHash, ChainHash: e.ChainHash}
		}
		res, err := verify.Chain(ve, verify.Options{})
		if err != nil || len(res.Breaks) != 0 {
			t.Fatalf("chain %s does not verify: %+v, %v", c, res.Breaks, err)
		}
	}
}

// THE invariant (design §4): for FormatV3, AppendChains produces byte-identical
// entries to appending each chain on its own with Append, whatever the chains,
// the batch sizes, the input order (shuffled, with tied arrivals), how the
// rounds are grouped, or whether Append is mixed in on the same store (erasure
// still appends per chain). It holds on every store, and the result verifies
// independently.
func TestAppendChains_V3MatchesAppend(t *testing.T) {
	for name, newStore := range storeFactories(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
			rng := rand.New(rand.NewPCG(7, 74))
			for trial := 0; trial < 25; trial++ {
				seq, batched := newStore(), newStore()
				ls, err := New(seq, WithClock(func() time.Time { return fixed }))
				if err != nil {
					t.Fatal(err)
				}
				lb, err := New(batched, WithClock(func() time.Time { return fixed }))
				if err != nil {
					t.Fatal(err)
				}
				chains := []string{"alpha", "beta", "gamma", "delta"}[:2+rng.IntN(3)]
				rounds := 1 + rng.IntN(4)
				for round := 0; round < rounds; round++ {
					base := fixed.Add(time.Duration(trial*1000+round*100) * time.Second)
					var batches []ChainInputs
					for _, c := range chains {
						if rng.IntN(4) == 0 {
							continue // a chain sits this round out
						}
						batches = append(batches, ChainInputs{ChainID: c, Inputs: shuffledWithTies(rng, c, 1+rng.IntN(5), base)})
					}
					if len(batches) == 0 {
						continue
					}
					rng.Shuffle(len(batches), func(i, j int) { batches[i], batches[j] = batches[j], batches[i] })
					for _, b := range batches {
						if _, err := ls.Append(ctx, b.ChainID, b.Inputs); err != nil {
							t.Fatal(err)
						}
					}
					// Sometimes the batched store appends one chain on its own with
					// Append, and the rest together: both paths on one store.
					together := batches
					if len(batches) > 1 && rng.IntN(3) == 0 {
						if _, err := lb.Append(ctx, batches[0].ChainID, batches[0].Inputs); err != nil {
							t.Fatal(err)
						}
						together = batches[1:]
					}
					res, err := lb.AppendChains(ctx, together)
					if err != nil {
						t.Fatal(err)
					}
					for i, b := range together {
						tail := allEntries(t, batched, b.ChainID)
						if res[i].HeadHash != tail[len(tail)-1].ChainHash || res[i].Appended != len(b.Inputs) {
							t.Fatalf("trial %d: result %d is not chain %s's: %+v", trial, i, b.ChainID, res[i])
						}
					}
				}
				for _, c := range chains {
					a, b := allEntries(t, seq, c), allEntries(t, batched, c)
					if fmt.Sprintf("%+v", a) != fmt.Sprintf("%+v", b) {
						t.Fatalf("trial %d: chain %s differs between Append and AppendChains:\n%+v\n%+v", trial, c, a, b)
					}
					stA, errA := seq.GetState(ctx, c)
					stB, errB := batched.GetState(ctx, c)
					if (errA == nil) != (errB == nil) || (errA == nil && (stA.HeadHash != stB.HeadHash || stA.HeadSeq != stB.HeadSeq)) {
						t.Fatalf("trial %d: chain %s head state differs: %+v %v / %+v %v", trial, c, stA, errA, stB, errB)
					}
				}
				verifyAll(t, batched, chains)
			}
		})
	}
}

// A V3 known answer for a two-chain AppendChains call, computed step by step
// with the chain-format primitive itself (not through link), and pinned: a bug
// in the shared hashing loop, which the property test cannot see (both of its
// paths use link), fails here.
func TestAppendChains_V3Golden(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	s := memory.New()
	l, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	in := func(id string, sec int, fill string) Input {
		ts := base.Add(time.Duration(sec) * time.Second)
		return Input{EntryID: id, EntryType: "event", Timestamp: ts, IngestedAt: ts, ContentHash: strings.Repeat(fill, 64)}
	}
	if _, err := l.AppendChains(ctx, []ChainInputs{
		{ChainID: "gold-a", Inputs: []Input{in("a1", 0, "11"), in("a2", 1, "22")}},
		{ChainID: "gold-b", Inputs: []Input{in("b1", 0, "33")}},
	}); err != nil {
		t.Fatal(err)
	}
	want := func(prev string, seq int64, sec int, fill string) string {
		h, err := chainformat.ComputeChainHashV3(prev, seq, base.Add(time.Duration(sec)*time.Second), strings.Repeat(fill, 64))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a1 := want("", 0, 0, "11")
	a2 := want(a1, 1, 1, "22")
	b1 := want("", 0, 0, "33")
	for chain, hashes := range map[string][]string{"gold-a": {a1, a2}, "gold-b": {b1}} {
		es := allEntries(t, s, chain)
		if len(es) != len(hashes) {
			t.Fatalf("chain %s has %d entries", chain, len(es))
		}
		for i, e := range es {
			if e.ChainHash != hashes[i] || e.GlobalSeq != int64(i) {
				t.Fatalf("chain %s entry %d: %s@%d, want %s@%d", chain, i, e.ChainHash, e.GlobalSeq, hashes[i], i)
			}
		}
	}
	// Pinned, so a change to ComputeChainHashV3 itself is caught here too.
	if a2 != goldenV3HeadA || b1 != goldenV3HeadB {
		t.Fatalf("V3 golden heads changed:\n a %s\n b %s", a2, b1)
	}
}

// FormatV2 binds a run id into the hash: one per chain, distinct.
func TestAppendChains_V2RunIDPerChain(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	l, err := New(s, WithFormatV2())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	res, err := l.AppendChains(ctx, []ChainInputs{
		{ChainID: "a", Inputs: inputsFor("a", 2, base)},
		{ChainID: "b", Inputs: inputsFor("b", 2, base)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].RunID == "" || res[0].RunID == res[1].RunID {
		t.Fatalf("run ids %q %q: want one distinct run id per chain", res[0].RunID, res[1].RunID)
	}
	for i, c := range []string{"a", "b"} {
		for _, e := range allEntries(t, s, c) {
			if e.RunID != res[i].RunID {
				t.Fatalf("chain %s entry has run id %q, want %q", c, e.RunID, res[i].RunID)
			}
		}
	}
}

// Anything that fails writes nothing, to any chain.
func TestAppendChains_Refusals(t *testing.T) {
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	good := func(c string) ChainInputs { return ChainInputs{ChainID: c, Inputs: inputsFor(c, 2, base)} }
	badHash := good("b")
	badHash.Inputs[1].ContentHash = "not-a-hash"
	noArrival := good("b")
	noArrival.Inputs[0].IngestedAt = time.Time{}
	cases := map[string]struct {
		batches []ChainInputs
		want    string
	}{
		"no batches":          {nil, "no chains"},
		"empty chain id":      {[]ChainInputs{good("a"), {ChainID: "", Inputs: inputsFor("x", 1, base)}}, "batch 1"},
		"chain twice":         {[]ChainInputs{good("a"), good("a")}, "appears twice"},
		"empty batch":         {[]ChainInputs{good("a"), {ChainID: "b"}}, "batch 1"},
		"invalid ordering":    {[]ChainInputs{good("a"), noArrival}, "batch 1"},
		"hash error in batch": {[]ChainInputs{good("a"), badHash}, "batch 1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := memory.New()
			l, _ := New(s)
			_, err := l.AppendChains(context.Background(), c.batches)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v; want one mentioning %q", err, c.want)
			}
			for _, chain := range []string{"a", "b", "x"} {
				if es := allEntries(t, s, chain); len(es) != 0 {
					t.Fatalf("chain %s got %d entries from a refused call", chain, len(es))
				}
			}
		})
	}
}

// A chain leased by an Append in progress refuses the whole call.
func TestAppendChains_LeasedChainIsBusy(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	l, _ := New(s)
	if _, ok, err := s.Acquire(ctx, "b"); err != nil || !ok {
		t.Fatal("acquire failed")
	}
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	_, err := l.AppendChains(ctx, []ChainInputs{
		{ChainID: "a", Inputs: inputsFor("a", 1, base)},
		{ChainID: "b", Inputs: inputsFor("b", 1, base)},
	})
	if !errors.Is(err, ErrChainBusy) {
		t.Fatalf("err = %v, want ErrChainBusy", err)
	}
	if es := allEntries(t, s, "a"); len(es) != 0 {
		t.Fatal("the unleased chain was written by a refused call")
	}
}

// onlyStore hides every capability but store.Store.
type onlyStore struct{ store.Store }

func TestAppendChains_StoreWithoutCapability(t *testing.T) {
	l, _ := New(onlyStore{memory.New()})
	_, err := l.AppendChains(context.Background(), []ChainInputs{
		{ChainID: "a", Inputs: inputsFor("a", 1, time.Now())},
	})
	if err == nil || !strings.Contains(err.Error(), "ChainsUpdater") {
		t.Fatalf("err = %v; want a refusal naming the missing capability", err)
	}
}

// swappingStore returns the tails in the wrong order: the linker must notice,
// not link chain a's entries onto chain b's tail.
type swappingStore struct{ *memory.Store }

func (s swappingStore) UpdateChains(ctx context.Context, ids []string,
	fn func([]store.Tail) ([]store.Entry, []store.State, error)) error {
	return s.Store.UpdateChains(ctx, ids, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
		if len(tails) > 1 {
			tails[0], tails[1] = tails[1], tails[0]
		}
		return fn(tails)
	})
}

func TestAppendChains_RefusesMismatchedTails(t *testing.T) {
	s := swappingStore{memory.New()}
	l, _ := New(s)
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	_, err := l.AppendChains(context.Background(), []ChainInputs{
		{ChainID: "a", Inputs: inputsFor("a", 1, base)},
		{ChainID: "b", Inputs: inputsFor("b", 1, base)},
	})
	if err == nil || !strings.Contains(err.Error(), "tail of") {
		t.Fatalf("err = %v; want the mismatched tail refused", err)
	}
}
