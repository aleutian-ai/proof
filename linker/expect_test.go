// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// withExpectations fills each input's ExpectChainHash with the v3 hash it will
// get after (prev, nextSeq), in the order given: what a caller that signs
// against its predictions computes.
func withExpectations(t *testing.T, in []Input, prev string, nextSeq int64) []Input {
	t.Helper()
	out := append([]Input(nil), in...)
	for i := range out {
		h, err := chainformat.ComputeChainHashV3(prev, nextSeq+int64(i), out[i].Timestamp, out[i].ContentHash)
		if err != nil {
			t.Fatal(err)
		}
		out[i].ExpectChainHash = h
		prev = h
	}
	return out
}

// appenders are the two paths through link; the check must hold on both.
func appenders() map[string]func(ctx context.Context, l *Linker, chain string, in []Input) error {
	return map[string]func(ctx context.Context, l *Linker, chain string, in []Input) error{
		"Append": func(ctx context.Context, l *Linker, chain string, in []Input) error {
			_, err := l.Append(ctx, chain, in)
			return err
		},
		"AppendChains": func(ctx context.Context, l *Linker, chain string, in []Input) error {
			_, err := l.AppendChains(ctx, []ChainInputs{{ChainID: chain, Inputs: in}})
			return err
		},
	}
}

// TestExpectChainHash_Matching: correct expectations are written as usual, on
// both stores and both paths, onto an empty chain and onto an existing one.
func TestExpectChainHash_Matching(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for sname, mk := range storeFactories(t) {
		for aname, appendFn := range appenders() {
			t.Run(sname+"/"+aname, func(t *testing.T) {
				s := mk()
				l, err := New(s)
				if err != nil {
					t.Fatal(err)
				}
				if err := appendFn(ctx, l, "c", withExpectations(t, inputsFor("c", 3, base), "", 0)); err != nil {
					t.Fatal(err)
				}
				tailHash, tailSeq, err := s.ReadTail(ctx, "c")
				if err != nil {
					t.Fatal(err)
				}
				more := withExpectations(t, inputsFor("c", 2, base.Add(time.Second)), tailHash, tailSeq+1)
				if err := appendFn(ctx, l, "c", more); err != nil {
					t.Fatal(err)
				}
				es := allEntries(t, s, "c")
				if len(es) != 5 || es[4].ChainHash != more[1].ExpectChainHash {
					t.Fatalf("got %d entries; the head is not the expected hash", len(es))
				}
			})
		}
	}
}

// TestExpectChainHash_MismatchWritesNothing: a wrong expectation at ANY index
// refuses the whole call. Nothing is written: the tail and the entry count are
// unchanged, on both stores and both paths.
func TestExpectChainHash_MismatchWritesNothing(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for sname, mk := range storeFactories(t) {
		for aname, appendFn := range appenders() {
			for bad := 0; bad < 3; bad++ {
				t.Run(sname+"/"+aname+"/index"+string(rune('0'+bad)), func(t *testing.T) {
					s := mk()
					l, err := New(s)
					if err != nil {
						t.Fatal(err)
					}
					if err := appendFn(ctx, l, "c", inputsFor("c", 2, base)); err != nil {
						t.Fatal(err)
					}
					beforeHash, beforeSeq, _ := s.ReadTail(ctx, "c")
					in := withExpectations(t, inputsFor("c", 3, base.Add(time.Second)), beforeHash, beforeSeq+1)
					in[bad].ExpectChainHash = strings.Repeat("0", 128)
					err = appendFn(ctx, l, "c", in)
					if !errors.Is(err, ErrUnexpectedChainHash) {
						t.Fatalf("err = %v; want ErrUnexpectedChainHash", err)
					}
					if strings.Contains(err.Error(), `"c"`) {
						t.Errorf("the error names the chain: %v", err)
					}
					afterHash, afterSeq, _ := s.ReadTail(ctx, "c")
					if afterHash != beforeHash || afterSeq != beforeSeq || len(allEntries(t, s, "c")) != 2 {
						t.Fatal("something was written although the call was refused")
					}
				})
			}
		}
	}
}

// TestExpectChainHash_CatchesWhatItMustCatch: expectations computed against a
// tail that has since moved, in an order the linker will not use, or for a
// format the linker does not write, are all refused.
func TestExpectChainHash_CatchesWhatItMustCatch(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for sname, mk := range storeFactories(t) {
		t.Run(sname, func(t *testing.T) {
			// Tail moved: expectations made against the tail BEFORE another append.
			s := mk()
			l, _ := New(s)
			if _, err := l.Append(ctx, "c", inputsFor("c", 2, base)); err != nil {
				t.Fatal(err)
			}
			h, seq, _ := s.ReadTail(ctx, "c")
			stale := withExpectations(t, inputsFor("c", 2, base.Add(time.Second)), h, seq+1)
			if _, err := l.Append(ctx, "c", inputsFor("c", 1, base.Add(500*time.Millisecond))); err != nil {
				t.Fatal(err)
			}
			if _, err := l.AppendChains(ctx, []ChainInputs{{ChainID: "c", Inputs: stale}}); !errors.Is(err, ErrUnexpectedChainHash) {
				t.Fatalf("tail moved: err = %v", err)
			}

			// Order: expectations chained in reverse of the linker's arrival order.
			s2 := mk()
			l2, _ := New(s2)
			in := inputsFor("c", 3, base)
			rev := []Input{in[2], in[1], in[0]}
			rev = withExpectations(t, rev, "", 0)
			if _, err := l2.AppendChains(ctx, []ChainInputs{{ChainID: "c", Inputs: rev}}); !errors.Is(err, ErrUnexpectedChainHash) {
				t.Fatalf("reordered: err = %v", err)
			}

			// Format: a v2 linker never produces a v3 hash.
			s3 := mk()
			l3, _ := New(s3, WithFormatV2())
			if _, err := l3.Append(ctx, "c", withExpectations(t, inputsFor("c", 1, base), "", 0)); !errors.Is(err, ErrUnexpectedChainHash) {
				t.Fatalf("v2 linker: err = %v", err)
			}
			if _, _, err := s3.ReadTail(ctx, "c"); !errors.Is(err, store.ErrEmptyChain) {
				t.Fatal("the v2 linker wrote despite the refusal")
			}
		})
	}
}

// TestExpectChainHash_OneBadChainRefusesTheCall: in a multi-chain call, one
// chain's wrong expectation refuses every chain (one transaction).
func TestExpectChainHash_OneBadChainRefusesTheCall(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for sname, mk := range storeFactories(t) {
		t.Run(sname, func(t *testing.T) {
			s := mk()
			l, _ := New(s)
			good := withExpectations(t, inputsFor("a", 2, base), "", 0)
			bad := withExpectations(t, inputsFor("b", 2, base), "", 0)
			bad[1].ExpectChainHash = strings.Repeat("f", 128)
			_, err := l.AppendChains(ctx, []ChainInputs{{ChainID: "a", Inputs: good}, {ChainID: "b", Inputs: bad}})
			if !errors.Is(err, ErrUnexpectedChainHash) {
				t.Fatalf("err = %v", err)
			}
			for _, c := range []string{"a", "b"} {
				if _, _, err := s.ReadTail(ctx, c); !errors.Is(err, store.ErrEmptyChain) {
					t.Fatalf("chain %s was written", c)
				}
			}
		})
	}
}
