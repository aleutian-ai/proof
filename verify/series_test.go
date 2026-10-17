// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/mldsa"
)

// resign signs a with the all-zero test seed that series uses, so an anchor
// edited by a test still carries a valid signature: the series rules are what
// is under test, not the signature.
func resign(t *testing.T, a anchor.Anchor) anchor.Anchor {
	t.Helper()
	signer, err := anchor.NewMLDSA65Signer(make([]byte, mldsa.MLDSA65.SeedSize()))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	a.SigningKeyID = ""
	signed, err := anchor.SignAnchor(context.Background(), signer, a)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestVerifyAnchorSeries: a well-formed series verifies, and each rule that
// makes several anchors a series is enforced. Every broken case carries valid
// signatures and binds on its own under VerifyAnchor: only the series check
// can object. These rules were enforced by the sink alone; `proof verify
// --anchor` and the MCP tool accepted each case.
func TestVerifyAnchorSeries(t *testing.T) {
	entries, _ := buildChain(t, 8)
	good, ring := series(t, entries, 3, 6, 8)

	res, problems, err := VerifyAnchorSeries(testSubject, entries, good, ring)
	if err != nil || res.Verdict != VerdictIntact || len(problems) != 0 {
		t.Fatalf("a good series: %s, %v, %v", res.Verdict, problems, err)
	}

	rehash := func(a anchor.Anchor, prevHash string, n int) anchor.Anchor {
		t.Helper()
		ch, err := anchor.ChainHash(prevHash, a.Subject, entries[0].EntryID, entries[n-1].EntryID, entries[n-1].ChainHash)
		if err != nil {
			t.Fatal(err)
		}
		a.ChainHash = ch
		return resign(t, a)
	}
	cases := map[string]struct {
		mutate func(s []anchor.Anchor)
		want   string
	}{
		"the first names a predecessor that is not the seed": {func(s []anchor.Anchor) {
			s[0].PreviousAnchorID = "anchor_99999999-0000-0000-0000-000000000000"
			s[0] = resign(t, s[0])
		}, "does not name the seed anchor"},
		"the second claims to be the first": {func(s []anchor.Anchor) {
			s[1].PreviousAnchorID = anchor.SeedAnchorID
			s[1] = resign(t, s[1])
		}, "does not name anchor 1 as its predecessor"},
		"an anchor for another subject": {func(s []anchor.Anchor) {
			s[1].Subject = "someone-else"
			s[1] = rehash(s[1], s[0].ChainHash, 6)
		}, "is for another chain"},
		"a series that does not grow": {func(s []anchor.Anchor) {
			s[1].EntryCount, s[1].VerifiedThrough = 3, 3
			s[1].Range.EndEntryID = entries[2].EntryID
			s[1] = rehash(s[1], s[0].ChainHash, 3)
		}, "a series must grow"},
		"time going backwards": {func(s []anchor.Anchor) {
			s[1].CreatedAtMs = s[0].CreatedAtMs - 1
			s[1] = resign(t, s[1])
		}, "does not go back in time"},
		"an anchor beyond the chain": {func(s []anchor.Anchor) {
			s[2].EntryCount, s[2].VerifiedThrough = 9, 9
			s[2] = resign(t, s[2])
		}, "claims 9 entries; the chain has 8"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := append([]anchor.Anchor(nil), good...)
			tc.mutate(s)
			_, problems, err := VerifyAnchorSeries(testSubject, entries, s, ring)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tc.want) {
				t.Fatalf("problems = %v, want one containing %q", problems, tc.want)
			}
		})
	}

	if _, _, err := VerifyAnchorSeries(testSubject, nil, good, ring); err == nil {
		t.Error("no entries: accepted")
	}
	if _, _, err := VerifyAnchorSeries(testSubject, entries, nil, ring); err == nil {
		t.Error("no anchors: accepted")
	}
}

// TestVerifyAnchor_PredecessorNamedTwiceMustAgree: an anchor names its
// predecessor by id and is hashed onto its predecessor's hash. A first anchor
// naming a real predecessor, and a later anchor naming the seed, each verified.
func TestVerifyAnchor_PredecessorNamedTwiceMustAgree(t *testing.T) {
	entries, _ := buildChain(t, 6)
	good, ring := series(t, entries, 3, 6)

	first := good[0]
	first.PreviousAnchorID = "anchor_99999999-0000-0000-0000-000000000000"
	first = resign(t, first)
	res, err := VerifyAnchor(first, entries[:3], Expect{PreviousAnchorHash: anchor.SeedAnchorHash}, ring)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bound || res.Outcome != BindPredecessorMismatch {
		t.Fatalf("a first anchor naming another predecessor: %+v", res)
	}

	second := good[1]
	second.PreviousAnchorID = anchor.SeedAnchorID
	second = resign(t, second)
	res, err = VerifyAnchor(second, entries, Expect{PreviousAnchorHash: good[0].ChainHash}, ring)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bound || res.Outcome != BindPredecessorMismatch {
		t.Fatalf("a later anchor naming the seed: %+v", res)
	}
}

// TestWalkerVerifyAnchor_RefusesASegment: an anchor is never bound to a walk
// that started from a predecessor hash. Such a walk over entries 3..5 once
// bound an anchor with entry_count 3 as if it covered a three-entry chain.
func TestWalkerVerifyAnchor_RefusesASegment(t *testing.T) {
	entries, _ := buildChain(t, 6)
	good, ring := series(t, entries, 3)

	w := NewWalker(Options{PreviousHash: entries[2].ChainHash})
	for _, e := range entries[3:] {
		w.Add(e)
	}
	if !w.Segment() {
		t.Fatal("Segment() is false for a walk with a previous hash")
	}
	res, err := w.VerifyAnchor(good[0], Expect{PreviousAnchorHash: anchor.SeedAnchorHash}, ring)
	if err == nil || res.Bound {
		t.Fatalf("bound an anchor to a segment: %+v, %v", res, err)
	}
}
