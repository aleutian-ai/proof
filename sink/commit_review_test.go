// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// _74a review fixes (R1–R3, 1.3–1.5, 2.3, 2.4, 4.3).

// anyChainID matches a chain id anywhere in a string.
var anyChainID = regexp.MustCompile(`[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}`)

// R1: the positions correction fails AFTER the evidence committed. The call
// must report success (the records ARE committed), never "nothing committed".
func TestCommitPairs_RepairFailureStillReportsCommitted(t *testing.T) {
	fx := newFixture(t)
	plans := fx.plans()
	src := &flakyPositions{real: fx.src, failAfter: 1} // the first putAll works, the repair fails
	if err := fx.s.commitPairs(context.Background(), interloper{real: fx.l}, fx.st, fx.sec, src, plans); err != nil {
		t.Fatalf("committed records were reported as failed: %v", err)
	}
	if rows, _ := fx.st.Range(context.Background(), fx.chain2, 0, 1<<62, 0); len(rows) != 2 {
		t.Fatalf("chain2 holds %d entries, want 2", len(rows))
	}
}

type flakyPositions struct {
	real      *sourcesStore
	failAfter int
	calls     int
}

func (p *flakyPositions) putAll(pos map[string]map[string]position) error {
	p.calls++
	if p.calls > p.failAfter {
		return errors.New("injected: sources store failed")
	}
	return p.real.putAll(pos)
}

// R2: one pair's stored state is broken (its reverse index row disagrees).
// Nothing is committed, and the error is a *PairError naming exactly that
// pair's records, so a consumer can set those aside and retry the rest.
func TestCommit_PairErrorNamesTheFailingRecords(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, append(events("u-1", 1), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	bad := cid(t, s, "u-2")
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).Put([]byte(bad), reverseValue(testClass, "u-9"))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	recs := []Record{events("u-1", 1)[0], events("u-2", 1)[0], events("u-3", 1)[0], events("u-2", 1)[0]}
	recs[3].Content = []byte("again")
	out, err := s.Commit(ctx, recs)
	var pe *PairError
	if !errors.As(err, &pe) || len(pe.Records) != 2 || pe.Records[0] != 1 || pe.Records[1] != 3 {
		t.Fatalf("err = %v; want a *PairError naming records [1 3]", err)
	}
	if pattern(out) != "----" {
		t.Fatalf("outcomes %s; want ----", pattern(out))
	}
}

// R3: a returned error leaves nothing new: the new pairs' index rows and
// source positions are removed too, not just content and nonces. Existing
// pairs keep their rows.
func TestCommit_FailedCallRemovesNewPairsRows(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	doomed := testClass + "." + strings.Repeat("d", 32)
	ids := []string{testClass + "." + strings.Repeat("e", 32), doomed} // u-2, then u-3
	s.mintChainID = func(string) (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	failAppends(s)
	recs := []Record{sourced("u-1", 1, 60)[0], sourced("u-2", 1, 70)[0], sourced("u-3", 1, 80)[0]}
	if _, err := s.Commit(ctx, recs); err == nil {
		t.Fatal("the failure was not reported")
	}
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	for _, u := range []string{"u-2", "u-3"} {
		if _, ok, _ := subj.lookup(u, testClass); ok {
			t.Fatalf("a failed call left %s's new index row", u)
		}
	}
	if _, ok, _ := subj.lookup("u-1", testClass); !ok {
		t.Fatal("the existing pair lost its row")
	}
	src, err := openSources(s.sourcesPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, c := range []string{testClass + "." + strings.Repeat("e", 32), doomed} {
		if _, found, _ := src.get(c, recs[1].Source); found {
			t.Fatalf("a failed call left positions for new chain %s", c)
		}
		if _, found, _ := src.get(c, recs[2].Source); found {
			t.Fatalf("a failed call left positions for new chain %s", c)
		}
	}
}

// 1.3: the append reports an error although its transaction committed. The
// entries exist, so their content and nonces must NOT be deleted: the call is
// a success.
type landedThenFailed struct{ real *linker.Linker }

func (a landedThenFailed) AppendChains(ctx context.Context, b []linker.ChainInputs) ([]linker.Result, error) {
	if _, err := a.real.AppendChains(ctx, b); err != nil {
		return nil, err
	}
	return nil, errors.New("injected: error after the commit")
}

func TestCommitPairs_AppendThatLandedKeepsContent(t *testing.T) {
	fx := newFixture(t)
	if err := fx.s.commitPairs(context.Background(), landedThenFailed{real: fx.l}, fx.st, fx.sec, fx.src, fx.plans()); err != nil {
		t.Fatalf("an append that landed was reported as failed: %v", err)
	}
	fx.close()
	_, ring := newSigner(t)
	r, err := fx.s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, fx.chain); c.Opened != 3 || len(c.Problems) != 0 {
		t.Fatalf("the landed entries lost their content or nonces: %+v", c)
	}
}

// 1.5: a chain named twice in the plans is refused before anything is written.
func TestCommitPairs_DuplicateChainRefusedBeforeWriting(t *testing.T) {
	fx := newFixture(t)
	plans := []pairPlan{{chain: fx.chain, recs: sourced("u-1", 1, 1)}, {chain: fx.chain, recs: sourced("u-2", 1, 5)}}
	rs := &recordingSecrets{secretsStore: fx.sec}
	if err := fx.s.commitPairs(context.Background(), fx.l, fx.st, rs, fx.src, plans); err == nil {
		t.Fatal("a duplicated chain was accepted")
	}
	if len(rs.chains) != 0 {
		t.Fatal("content or nonces were written before the refusal")
	}
}

// 2.3: Commit's errors never carry a chain id (next to the caller's records it
// would be a row of the secret index). errors.Is still reaches the cause.
func TestCommit_ErrorsNameNoChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	doomed := testClass + "." + strings.Repeat("d", 32)
	s.mintChainID = func(string) (string, error) { return doomed, nil }
	failAppends(s)
	_, err = s.Commit(ctx, events("u-1", 1))
	if err == nil || anyChainID.MatchString(err.Error()) {
		t.Fatalf("err = %v; want an error that names no chain", err)
	}
	if !errors.Is(err, errInjectedAppend) {
		t.Fatalf("the cause is no longer reachable with errors.Is: %v", err)
	}
}

// 2.4: when the cleanup itself fails, the error says so.
func TestCommitPairs_CleanupFailureIsReported(t *testing.T) {
	fx := newFixture(t)
	rs := &recordingSecrets{secretsStore: fx.sec, failDelete: true}
	err := fx.s.commitPairs(context.Background(), failingAppend{errors.New("injected: append failed")},
		fx.st, rs, fx.src, fx.plans())
	if err == nil || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("err = %v; want the cleanup failure reported", err)
	}
}

// 4.3: a failure on a chain that already has entries removes only this call's
// files and nonces; the earlier entries' content and nonces survive.
func TestCommitPairs_FailureKeepsEarlierContent(t *testing.T) {
	fx := newFixture(t)
	fx.close()
	if _, err := fx.s.Commit(context.Background(), events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	fx2 := newFixtureOn(t, fx.s)
	err := fx2.s.commitPairs(context.Background(), failingAppend{errors.New("injected")},
		fx2.st, fx2.sec, fx2.src, []pairPlan{{chain: fx.chain, recs: sourced("u-1", 2, 30)}})
	if err == nil {
		t.Fatal("the failure was not reported")
	}
	fx2.close()
	_, ring := newSigner(t)
	r, err := fx.s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, fx.chain); c.Entries != 2 || c.Opened != 2 || len(c.Problems) != 0 {
		t.Fatalf("the earlier entries were damaged by a failed call: %+v", c)
	}
}

// R3, directly: forgetFresh removes the new chains' source positions, then
// their index rows. (The Commit-level test fails before positions are written;
// this pins the positions half.)
func TestForgetFreshRemovesPositionsThenRows(t *testing.T) {
	fx := newFixture(t)
	fresh := []binding{{subject: "u-7", class: testClass, chain: testClass + "." + strings.Repeat("7", 32)}}
	subj, err := openSubjects(fx.s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	if err := subj.bindAll(fresh); err != nil {
		t.Fatal(err)
	}
	if err := fx.src.putAll(map[string]map[string]position{fresh[0].chain: {"EVIDENCE:1": {entryID: "sink-x", seq: 0}},
		fx.chain: {"EVIDENCE:2": {entryID: "sink-y", seq: 0}}}); err != nil {
		t.Fatal(err)
	}
	if err := fx.s.forgetFresh(subj, fx.src, fresh); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := fx.src.get(fresh[0].chain, "EVIDENCE:1"); found {
		t.Fatal("the new chain's position survived")
	}
	if _, found, _ := fx.src.get(fx.chain, "EVIDENCE:2"); !found {
		t.Fatal("another chain's position was removed")
	}
	if _, ok, _ := subj.lookup("u-7", testClass); ok {
		t.Fatal("the new row survived")
	}
}

// errInjectedAppend is the cause failAppends reports.
var errInjectedAppend = errors.New("injected: append failed")

// namingFailure fails every append with an error that NAMES a chain, as a
// store error may: what Commit returns must still name none.
type namingFailure struct{}

func (namingFailure) AppendChains(_ context.Context, b []linker.ChainInputs) ([]linker.Result, error) {
	return nil, fmt.Errorf("chain %s: %w", b[0].ChainID, errInjectedAppend)
}

// failAppends makes every Commit of s fail at the append: after the index
// rows, content, nonces and source positions were written.
func failAppends(s *Sink) {
	s.wrapAppender = func(chainsAppender) chainsAppender { return namingFailure{} }
}
