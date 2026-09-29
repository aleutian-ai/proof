// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// fixture opens a sink's files the way Commit does, for calling appendChain
// directly with one dependency swapped for a failing one.
type fixture struct {
	s   *Sink
	f   *folder
	st  *boltstore.Store
	ns  *noncestore.Store
	src *sourcesStore
	l   *linker.Linker
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := &fixture{s: s}
	if fx.f, err = s.openFolder(true); err != nil {
		t.Fatal(err)
	}
	if fx.st, fx.ns, err = s.openFiles(); err != nil {
		t.Fatal(err)
	}
	if fx.src, err = openSources(s.sourcesPath(), DefaultLockTimeout); err != nil {
		t.Fatal(err)
	}
	if fx.l, err = linker.New(fx.st); err != nil {
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
	if fx.ns != nil {
		fx.ns.Close()
		fx.ns = nil
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

// nothingLeft asserts that a failed appendChain left no content file, no nonce
// and no entry.
func (fx *fixture) nothingLeft(t *testing.T, chain string, nonces *recordingNonces) {
	t.Helper()
	files, _ := os.ReadDir(filepath.Join(fx.s.dir, "content", chain))
	if len(files) != 0 {
		t.Fatalf("content left behind: %v", files)
	}
	for _, id := range nonces.ids {
		if _, err := fx.ns.Get(chain, id); !errors.Is(err, noncestore.ErrNotFound) {
			t.Fatalf("nonce for %s left behind: %v", id, err)
		}
	}
	if rows, _ := fx.st.Range(context.Background(), chain, 0, 1<<62, 0); len(rows) != 0 {
		t.Fatalf("%d entries written by a failed append", len(rows))
	}
}

// recordingNonces is the real nonce store, remembering which ids it stored, and
// optionally failing PutBatch.
type recordingNonces struct {
	*noncestore.Store
	ids  []string
	fail bool
}

func (r *recordingNonces) PutBatch(chain string, n map[string][]byte) error {
	for id := range n {
		r.ids = append(r.ids, id)
	}
	if r.fail {
		return errors.New("injected: nonce store failed")
	}
	return r.Store.PutBatch(chain, n)
}

type failingPositions struct{}

func (failingPositions) putBatch(string, map[string]position) error {
	return errors.New("injected: sources store failed")
}

// appendThen runs the real append, then returns the given error: a failure
// before it (committed=false) or after it (committed=true).
type appendThen struct {
	real      *linker.Linker
	committed bool
	err       error
}

func (a appendThen) Append(ctx context.Context, chain string, in []linker.Input) (linker.Result, error) {
	if !a.committed {
		return linker.Result{}, a.err
	}
	res, err := a.real.Append(ctx, chain, in)
	if err != nil {
		return res, err
	}
	return res, a.err
}

func TestAppendChain_FailuresLeaveNothing(t *testing.T) {
	cases := map[string]func(fx *fixture) (nonceWriter, positionWriter, appender, *recordingNonces){
		"nonce store fails": func(fx *fixture) (nonceWriter, positionWriter, appender, *recordingNonces) {
			rn := &recordingNonces{Store: fx.ns, fail: true}
			return rn, fx.src, fx.l, rn
		},
		"sources store fails": func(fx *fixture) (nonceWriter, positionWriter, appender, *recordingNonces) {
			rn := &recordingNonces{Store: fx.ns}
			return rn, failingPositions{}, fx.l, rn
		},
		"append fails": func(fx *fixture) (nonceWriter, positionWriter, appender, *recordingNonces) {
			rn := &recordingNonces{Store: fx.ns}
			return rn, fx.src, appendThen{real: fx.l, err: errors.New("injected: append failed")}, rn
		},
	}
	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			ns, src, l, rn := deps(fx)
			err := fx.s.appendChain(context.Background(), l, fx.st, ns, src, fx.f, "u-1", sourced("u-1", 3, 1))
			if err == nil {
				t.Fatal("the injected failure was not reported")
			}
			if len(rn.ids) == 0 && name != "nonce store fails" {
				t.Fatal("test setup: no nonces were stored before the failure")
			}
			fx.nothingLeft(t, "u-1", rn)
		})
	}
}

// ErrHeadStateStale means the entries ARE on the chain: nothing may be cleaned
// up, or committed entries would lose their content and nonces.
func TestAppendChain_HeadStateStaleKeepsEverything(t *testing.T) {
	fx := newFixture(t)
	rn := &recordingNonces{Store: fx.ns}
	l := appendThen{real: fx.l, committed: true, err: linker.ErrHeadStateStale}
	if err := fx.s.appendChain(context.Background(), l, fx.st, rn, fx.src, fx.f, "u-1", sourced("u-1", 2, 1)); err != nil {
		t.Fatalf("a committed append with a stale head record was reported as a failure: %v", err)
	}
	rows, _ := fx.st.Range(context.Background(), "u-1", 0, 1<<62, 0)
	if len(rows) != 2 {
		t.Fatalf("%d entries, want 2", len(rows))
	}
	for _, r := range rows {
		if _, err := os.Stat(fx.s.contentPath("u-1", r.EntryID)); err != nil {
			t.Fatalf("content of a committed entry was removed: %v", err)
		}
		if _, err := fx.ns.Get("u-1", r.EntryID); err != nil {
			t.Fatalf("nonce of a committed entry was removed: %v", err)
		}
	}
}

// interloper appends one foreign entry before the batch, so the batch lands one
// sequence later than predicted. That cannot happen while one process holds the
// file, which is why the repair was never exercised; it must still be correct.
type interloper struct{ real *linker.Linker }

func (i interloper) Append(ctx context.Context, chain string, in []linker.Input) (linker.Result, error) {
	now := in[0].IngestedAt.Add(-1)
	if _, err := i.real.Append(ctx, chain, []linker.Input{{EntryID: "sink-" + "0123456789abcdef0123456789abcdef",
		EntryType: EntryTypeEvent, Timestamp: now, IngestedAt: now, ContentHash: in[0].ContentHash}}); err != nil {
		return linker.Result{}, err
	}
	return i.real.Append(ctx, chain, in)
}

func TestAppendChain_MispredictedSequenceIsRepaired(t *testing.T) {
	fx := newFixture(t)
	recs := sourced("u-1", 2, 40)
	if err := fx.s.appendChain(context.Background(), interloper{real: fx.l}, fx.st, fx.ns, fx.src, fx.f, "u-1", recs); err != nil {
		t.Fatalf("a committed batch at a mispredicted sequence must not fail: %v", err)
	}
	fx.close()
	// The recorded positions were corrected: a redelivery is recognised, not
	// committed again.
	got, err := fx.s.Commit(context.Background(), recs)
	if err != nil || got[0].Duplicates != 2 || got[0].Entries != 0 {
		t.Fatalf("redelivery after a mispredicted sequence: %+v, %v; want 2 duplicates", got, err)
	}
}
