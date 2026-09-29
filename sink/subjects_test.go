// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSubjectNotInShareableArtifacts is the point of opaque chain ids: the
// evidence file and every checkpoint are free of the subject; only the secret
// index (and the content, which is the event itself) holds it.
func TestSubjectNotInShareableArtifacts(t *testing.T) {
	s, signer, _ := setup(t)
	if _, err := s.Checkpoint(context.Background(), signer, nil); err != nil {
		t.Fatal(err)
	}
	shareable := []string{s.DBPath()}
	anchors, _ := filepath.Glob(filepath.Join(s.dir, "anchors", "*", "*.json"))
	if len(anchors) == 0 {
		t.Fatal("control: no checkpoints were written")
	}
	shareable = append(shareable, anchors...)
	for _, subject := range []string{"u-81", "u-82", "u-90"} {
		for _, p := range shareable {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(subject)) {
				t.Errorf("%s names subject %s", filepath.Base(p), subject)
			}
		}
	}
	// Control: the secret index does hold them, so the scan can find a subject.
	raw, err := os.ReadFile(s.subjectsPath())
	if err != nil || !bytes.Contains(raw, []byte("u-81")) {
		t.Fatalf("control: the subject index does not hold u-81 (%v)", err)
	}
}

// TestIndexAccountsForEveryChain: after commits across classes and subjects,
// every chain in the evidence file has a reverse row naming its own pair.
func TestIndexAccountsForEveryChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Class: "payments", Subject: "u-1", Content: []byte("p1")},
		{Class: "auth", Subject: "u-1", Content: []byte("a1")},
		{Class: "payments", Subject: "u-2", Content: []byte("p2")},
		{Class: "payments", Subject: "u-1", Content: []byte("p1b")},
	}
	done, err := s.Commit(ctx, recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 3 {
		t.Fatalf("want 3 chains (2 classes for u-1, 1 for u-2), got %+v", done)
	}
	ids := map[string]bool{}
	for _, d := range done {
		if !strings.HasPrefix(d.Chain, d.Class+".") || ids[d.Chain] {
			t.Fatalf("chain %s: wrong class prefix, or reused", d.Chain)
		}
		ids[d.Chain] = true
	}

	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := st.Chains(ctx)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	for _, chain := range chains {
		class, subject, ok, err := subj.owner(chain)
		if err != nil || !ok {
			t.Fatalf("chain %s is not accounted for by the index: %v", chain, err)
		}
		fwd, ok, err := subj.lookup(subject, class)
		if err != nil || !ok || fwd != chain {
			t.Fatalf("forward and reverse rows disagree for %s: %s, %v", chain, fwd, err)
		}
	}
}

// TestIndexRowWithoutChainIsReused: a crash after Commit's step 1 leaves an
// index row and no chain. The next commit of that pair must use that chain,
// not mint a second one (which would split the subject's history).
func TestIndexRowWithoutChainIsReused(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil { // create the folder and files
		t.Fatal(err)
	}
	bound := bindChain(t, s, "u-1")
	done, err := s.Commit(context.Background(), events("u-1", 2))
	if err != nil || len(done) != 1 || done[0].Chain != bound {
		t.Fatalf("commit after a crash at step 1 = %+v, %v; want chain %s reused", done, err, bound)
	}
}

// TestFailedAppendKeepsTheBinding: a commit that fails after the index row was
// written (content and nonces are cleaned up) leaves the row; the retry uses
// the same chain.
func TestFailedAppendKeepsTheBinding(t *testing.T) {
	fx := newFixture(t)
	rn := &recordingNonces{Store: fx.ns}
	err := fx.s.appendChain(context.Background(), appendThen{real: fx.l, err: errors.New("injected")},
		fx.st, rn, fx.src, fx.f, fx.chain, sourced("u-1", 2, 1))
	if err == nil {
		t.Fatal("the injected failure was not reported")
	}
	fx.close()
	done, err := fx.s.Commit(context.Background(), sourced("u-1", 2, 1))
	if err != nil || done[0].Chain != fx.chain || done[0].Entries != 2 {
		t.Fatalf("retry = %+v, %v; want 2 entries on %s", done, err, fx.chain)
	}
}

// TestBindRefusesOverwrite: a pair has one chain and a chain one pair.
func TestBindRefusesOverwrite(t *testing.T) {
	subj, err := openSubjects(filepath.Join(t.TempDir(), "subjects"), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	a, b := "events."+strings.Repeat("a", 32), "events."+strings.Repeat("b", 32)
	if err := subj.bind("u-1", "events", a); err != nil {
		t.Fatal(err)
	}
	if err := subj.bind("u-1", "events", b); err == nil {
		t.Fatal("a pair was rebound to a second chain")
	}
	if err := subj.bind("u-2", "events", a); err == nil {
		t.Fatal("a chain was bound to a second pair")
	}
	if c, ok, _ := subj.lookup("u-1", "events"); !ok || c != a {
		t.Fatalf("the refused rebind changed the row: %s", c)
	}
}

// TestNewChainIDIsCheckedUnused: a minted id that is already in use (a
// collision, forced by the minter) is never bound to a new pair: taken in the
// store, or taken in the index, it is skipped; if every attempt collides,
// Commit fails rather than merge two subjects' histories.
func TestNewChainIDIsCheckedUnused(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done, err := s.Commit(ctx, events("u-1", 1)) // u-1's chain: in the store AND the index
	if err != nil {
		t.Fatal(err)
	}
	taken := done[0].Chain
	indexOnly := bindChain(t, s, "u-2") // in the index, no entries yet

	fresh := testClass + "." + strings.Repeat("f", 32)
	queue := []string{taken, indexOnly, fresh}
	s.mintChainID = func(string) (string, error) {
		id := queue[0]
		queue = queue[1:]
		return id, nil
	}
	got, err := s.Commit(ctx, events("u-3", 1))
	if err != nil || got[0].Chain != fresh {
		t.Fatalf("u-3 = %+v, %v; want the first unused id %s", got, err, fresh)
	}

	s.mintChainID = func(string) (string, error) { return taken, nil } // always collides
	if _, err := s.Commit(ctx, events("u-4", 1)); err == nil {
		t.Fatal("a pair was bound although every minted id was taken")
	}
	if c := cid(t, s, "u-1"); c != taken {
		t.Fatalf("u-1's binding changed: %s", c)
	}
}
