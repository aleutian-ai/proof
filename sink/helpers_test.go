// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
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
		out[i] = Record{Key: key, Content: []byte(fmt.Sprintf(`{"user":%q,"i":%d}`, key, i))}
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
	want := []Committed{{Chain: "u-81", Entries: 3}, {Chain: "u-82", Entries: 2}, {Chain: "u-90", Entries: 1}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Commit = %v, want %v (grouped, in order of first appearance)", got, want)
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
