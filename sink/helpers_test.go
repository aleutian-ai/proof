// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

func newSigner(t *testing.T) (*anchor.MLDSA65Signer, *anchor.KeyRing) {
	t.Helper()
	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	id, pub, err := anchor.KeyIDOf(s)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	if err != nil {
		t.Fatal(err)
	}
	return s, ring
}

func events(key string, n int) []Record {
	out := make([]Record, n)
	for i := range out {
		out[i] = Record{Class: testClass, Subject: key, Content: []byte(fmt.Sprintf(`{"user":%q,"i":%d}`, key, i))}
	}
	return out
}

func chainReport(t *testing.T, r Report, chain string) ChainReport {
	t.Helper()
	for _, c := range r.Chains {
		if c.Chain == chain {
			return c
		}
	}
	t.Fatalf("no report for chain %s in %+v", chain, r)
	return ChainReport{}
}

func mustVerify(t *testing.T, s *Sink, keys anchor.KeySource) Report {
	t.Helper()
	r, err := s.Verify(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() {
		t.Fatalf("verify found problems: %+v", r)
	}
	return r
}

// setup commits u-81 ×3, u-82 ×2 and u-90 ×1, interleaved, and checkpoints them.
func setup(t *testing.T) (*Sink, *anchor.MLDSA65Signer, *anchor.KeyRing) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	a, b, c := events("u-81", 3), events("u-82", 2), events("u-90", 1)
	batch := []Record{a[0], b[0], a[1], c[0], b[1], a[2]}
	got, err := s.Commit(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	// Grouped per subject, in order of first appearance, each on its own
	// opaque chain.
	want := []string{"u-81 3", "u-82 2", "u-90 1"}
	for i, c := range got {
		if i >= len(want) || fmt.Sprintf("%s %d", c.Subject, c.Entries) != want[i] || !ValidChainID(c.Chain) {
			t.Fatalf("Commit = %v, want subjects and counts %v on opaque chains", got, want)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("Commit = %v, want %d chains", got, len(want))
	}
	if _, err := s.Checkpoint(context.Background(), signer, nil); err != nil {
		t.Fatal(err)
	}
	return s, signer, ring
}

func entryIDs(t *testing.T, s *Sink, chain string) []string {
	t.Helper()
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	es, err := readChain(context.Background(), st, chain)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(es))
	for i, e := range es {
		ids[i] = e.EntryID
	}
	return ids
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// appendRaw appends an entry with an arbitrary id, as another writer of the
// evidence file could.
func appendRaw(t *testing.T, s *Sink, chain, entryID string) {
	t.Helper()
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := l.Append(context.Background(), chain, []linker.Input{{EntryID: entryID,
		EntryType: EntryTypeEvent, Timestamp: now, IngestedAt: now,
		ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		t.Fatal(err)
	}
}

func sourced(key string, n int, from int) []Record {
	out := events(key, n)
	for i := range out {
		out[i].Source = fmt.Sprintf("EVIDENCE:%d", from+i)
	}
	return out
}

// problemFor returns the Problem Checkpoint reported for a chain, or "" if it
// was checkpointed or not mentioned.
func problemFor(done []Checkpointed, chain string) string {
	for _, c := range done {
		if c.Chain == chain {
			return c.Problem
		}
	}
	return ""
}

// readChain loads a whole chain: for tests only. The sink itself reads chains
// a page at a time (forEachEntry).
func readChain(ctx context.Context, st *boltstore.Store, chain string) ([]verify.Entry, error) {
	var out []verify.Entry
	err := forEachEntry(ctx, st, chain, func(e store.Entry) { out = append(out, toVerifyEntry(e)) })
	return out, err
}

// testClass is the evidence class the tests commit under.
const testClass = "events"

// cid returns the opaque chain id holding a subject's testClass evidence, as
// the subject index records it. Tests name subjects; the sink names chains.
func cid(t *testing.T, s *Sink, subject string) string {
	t.Helper()
	memo := chainMemoFor(t)
	key := fmt.Sprintf("%p|%s", s, subject)
	if c, ok := memo[key]; ok {
		return c // resolved before an erasure made the index forget it
	}
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	chain, ok, err := subj.lookup(subject, testClass)
	if err != nil || !ok {
		t.Fatalf("no chain for subject %s: %v", subject, err)
	}
	memo[key] = chain
	return chain
}

// chainMemo lets a test keep naming a subject's OLD chain after erasing the
// subject, which makes the index forget it (by design). One memo per test,
// dropped when the test ends, so no test can see another's chains.
var (
	chainMemoMu sync.Mutex
	chainMemo   = map[*testing.T]map[string]string{}
)

func chainMemoFor(t *testing.T) map[string]string {
	chainMemoMu.Lock()
	defer chainMemoMu.Unlock()
	m, ok := chainMemo[t]
	if !ok {
		m = map[string]string{}
		chainMemo[t] = m
		t.Cleanup(func() {
			chainMemoMu.Lock()
			delete(chainMemo, t)
			chainMemoMu.Unlock()
		})
	}
	return m
}

// eraseOne erases a subject (all classes) and returns its one chain's result,
// remembering the chain first so the test can inspect it afterwards.
func eraseOne(t *testing.T, s *Sink, subject string) (EraseResult, error) {
	t.Helper()
	cid(t, s, subject)
	res, err := s.EraseSubject(context.Background(), subject)
	if len(res.Erased) > 0 {
		return res.Erased[0], err
	}
	return EraseResult{}, err
}

// bindChain performs Commit's first step alone for a subject: mint its chain
// and write the index rows, with no entry appended. That is exactly the state a
// crash right after step 1 leaves.
func bindChain(t *testing.T, s *Sink, subject string) string {
	t.Helper()
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	chain, err := s.resolveChain(context.Background(), st, subj, testClass, subject)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}
