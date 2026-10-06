// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"testing"

	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// fixture opens a sink's files the way Commit does, for calling commitPairs
// directly with one dependency swapped for a failing one. Two pairs are bound:
// a failure must leave nothing behind for EITHER.
type fixture struct {
	s      *Sink
	chain  string // bound to (testClass, "u-1")
	chain2 string // bound to (testClass, "u-2")
	f      *folder
	st     *boltstore.Store
	sec    *secretsStore
	src    *sourcesStore
	l      *linker.Linker
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return newFixtureOn(t, s)
}

// newFixtureOn opens the fixture on an existing sink, reusing its bindings.
func newFixtureOn(t *testing.T, s *Sink) *fixture {
	t.Helper()
	var err error
	fx := &fixture{s: s}
	if fx.f, err = s.openFolder(true); err != nil {
		t.Fatal(err)
	}
	if fx.st, fx.sec, err = s.openFiles(); err != nil {
		t.Fatal(err)
	}
	if fx.src, err = openSources(s.sourcesPath(), DefaultLockTimeout); err != nil {
		t.Fatal(err)
	}
	if fx.l, err = linker.New(fx.st); err != nil {
		t.Fatal(err)
	}
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	fx.chain, err = s.resolveChain(context.Background(), fx.st, subj, testClass, "u-1")
	if err == nil {
		fx.chain2, err = s.resolveChain(context.Background(), fx.st, subj, testClass, "u-2")
	}
	subj.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fx.close)
	return fx
}

func (fx *fixture) close() {
	if fx.src != nil {
		fx.src.Close()
		fx.src = nil
	}
	if fx.sec != nil {
		fx.sec.Close()
		fx.sec = nil
	}
	if fx.st != nil {
		fx.st.Close()
		fx.st = nil
	}
	if fx.f != nil {
		fx.f.Close()
		fx.f = nil
	}
}

// plans is the two pairs' records: u-1 ×3 and u-2 ×2, all sourced.
func (fx *fixture) plans() []pairPlan {
	return []pairPlan{
		{chain: fx.chain, recs: sourced("u-1", 3, 1)},
		{chain: fx.chain2, recs: sourced("u-2", 2, 10)},
	}
}

// nothingLeft asserts that a failed commitPairs left no content row, no nonce
// and no entry, on EITHER chain.
func (fx *fixture) nothingLeft(t *testing.T) {
	t.Helper()
	for _, chain := range []string{fx.chain, fx.chain2} {
		if ids, _ := fx.sec.contentIDs(chain); len(ids) != 0 {
			t.Fatalf("chain %s: %d content rows left behind", chain, len(ids))
		}
		if rows, _ := fx.st.Range(context.Background(), chain, 0, 1<<62, 0); len(rows) != 0 {
			t.Fatalf("chain %s: %d entries written by a failed commit", chain, len(rows))
		}
	}
	if chains, _ := fx.sec.chainsWithRowsAfter(nil, 1<<30); len(chains) != 0 {
		t.Fatalf("content or nonces left behind for %v", chains)
	}
}

// recordingSecrets is the real secrets store, remembering which chains it was
// asked to write, and optionally failing putAll or deleteRows.
type recordingSecrets struct {
	*secretsStore
	chains     map[string]int
	fail       bool
	failDelete bool
}

func (r *recordingSecrets) putAll(rows map[string]map[string]secret) error {
	if r.chains == nil {
		r.chains = map[string]int{}
	}
	for chain, byEntry := range rows {
		r.chains[chain] += len(byEntry)
	}
	if r.fail {
		return errors.New("injected: secrets store failed")
	}
	return r.secretsStore.putAll(rows)
}

func (r *recordingSecrets) deleteRows(ids map[string][]string) error {
	if r.failDelete {
		return errors.New("injected: secrets delete failed")
	}
	return r.secretsStore.deleteRows(ids)
}

type failingPositions struct{}

func (failingPositions) putAll(map[string]map[string]position) error {
	return errors.New("injected: sources store failed")
}

// failingAppend fails without appending, as a refused transaction does.
type failingAppend struct{ err error }

func (a failingAppend) AppendChains(context.Context, []linker.ChainInputs) ([]linker.Result, error) {
	return nil, a.err
}

func TestCommitPairs_FailuresLeaveNothing(t *testing.T) {
	cases := map[string]func(fx *fixture) (secretsWriter, positionWriter, chainsAppender, *recordingSecrets){
		"secrets store fails": func(fx *fixture) (secretsWriter, positionWriter, chainsAppender, *recordingSecrets) {
			rs := &recordingSecrets{secretsStore: fx.sec, fail: true}
			return rs, fx.src, fx.l, rs
		},
		"sources store fails": func(fx *fixture) (secretsWriter, positionWriter, chainsAppender, *recordingSecrets) {
			rs := &recordingSecrets{secretsStore: fx.sec}
			return rs, failingPositions{}, fx.l, rs
		},
		"append fails": func(fx *fixture) (secretsWriter, positionWriter, chainsAppender, *recordingSecrets) {
			rs := &recordingSecrets{secretsStore: fx.sec}
			return rs, fx.src, failingAppend{errors.New("injected: append failed")}, rs
		},
	}
	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			sec, src, l, rs := deps(fx)
			err := fx.s.commitPairs(context.Background(), l, fx.st, sec, src, nil, fx.plans())
			if err == nil {
				t.Fatal("the injected failure was not reported")
			}
			if rs.chains[fx.chain] == 0 || rs.chains[fx.chain2] == 0 {
				t.Fatal("test setup: both pairs' secrets were not attempted before the failure")
			}
			fx.nothingLeft(t)
		})
	}
}

// Content and nonces for EVERY pair go in one transaction: a failure writing
// them writes nothing for any pair (there is no "earlier pair" to clean up).
func TestCommitPairs_SecretsAreOneTransaction(t *testing.T) {
	fx := newFixture(t)
	rs := &recordingSecrets{secretsStore: fx.sec, fail: true}
	if err := fx.s.commitPairs(context.Background(), fx.l, fx.st, rs, fx.src, nil, fx.plans()); err == nil {
		t.Fatal("the failure was not reported")
	}
	if len(rs.chains) != 2 {
		t.Fatalf("the call made %d secrets writes' worth of chains, want both pairs in one", len(rs.chains))
	}
	fx.nothingLeft(t)
}

// interloper appends one foreign entry to the first chain before the real
// batch, so that chain's tail is not the one the batch was predicted (and, in a
// signing sink, signed) against. That cannot happen while one process holds the
// file; if it ever does, the append must refuse rather than commit entries at
// positions nobody predicted.
type interloper struct{ real *linker.Linker }

func (i interloper) AppendChains(ctx context.Context, batches []linker.ChainInputs) ([]linker.Result, error) {
	first := batches[0]
	now := first.Inputs[0].IngestedAt.Add(-1)
	if _, err := i.real.Append(ctx, first.ChainID, []linker.Input{{EntryID: "sink-" + "0123456789abcdef0123456789abcdef",
		EntryType: EntryTypeEvent, Timestamp: now, IngestedAt: now, ContentHash: first.Inputs[0].ContentHash}}); err != nil {
		return nil, err
	}
	return i.real.AppendChains(ctx, batches)
}

// TestCommitPairs_MovedTailIsRefused (_75c C2): every entry's chain hash is
// pinned, so a batch whose chain moved under it is refused whole, and the call
// leaves nothing of its own behind (the interloper's entry is not ours).
func TestCommitPairs_MovedTailIsRefused(t *testing.T) {
	fx := newFixture(t)
	err := fx.s.commitPairs(context.Background(), interloper{real: fx.l}, fx.st, fx.sec, fx.src, nil, fx.plans())
	if !errors.Is(err, linker.ErrUnexpectedChainHash) {
		t.Fatalf("err = %v; want the append refused", err)
	}
	if rows, _ := fx.st.Range(context.Background(), fx.chain, 0, 1<<62, 0); len(rows) != 1 {
		t.Fatalf("chain holds %d entries; want only the interloper's", len(rows))
	}
	if rows, _ := fx.st.Range(context.Background(), fx.chain2, 0, 1<<62, 0); len(rows) != 0 {
		t.Fatal("the other chain was written although the call was refused")
	}
	if chains, _ := fx.sec.chainsWithRowsAfter(nil, 1<<30); len(chains) != 0 {
		t.Fatalf("content or nonces left behind for %v", chains)
	}
}
