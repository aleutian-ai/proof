// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
)

// relink recomputes every chain hash from the entries' current fields, as an
// attacker with write access to the store would after an edit.
func relink(t *testing.T, entries []Entry) {
	t.Helper()
	prev := ""
	for i := range entries {
		ts, err := time.Parse(time.RFC3339Nano, entries[i].Timestamp)
		if err != nil {
			t.Fatalf("parse timestamp: %v", err)
		}
		entries[i].ChainHash = chainformat.ComputeChainHashV3Unchecked(
			prev, entries[i].GlobalSeq, ts, entries[i].ContentHash)
		prev = entries[i].ChainHash
	}
}

// firstBreak verifies entries and returns the first break, failing the test if
// the chain verified.
func firstBreak(t *testing.T, entries []Entry, opts Options) Break {
	t.Helper()
	res, err := Chain(entries, opts)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if res.Verdict != VerdictBroken || len(res.Breaks) == 0 {
		t.Fatalf("verdict = %s with %d breaks, want BROKEN", res.Verdict, len(res.Breaks))
	}
	return res.Breaks[0]
}

// TestChain_FieldShapesAreChecked: an entry whose fields are not in the shape
// the format requires is a break even when its chain hash is the hash of those
// fields. Each case re-links the chain after the edit, so the hashes agree and
// only the shape check can object.
func TestChain_FieldShapesAreChecked(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(es []Entry)
		relink bool
		want   BreakType
		at     int
	}{
		{"content hash that is not a digest", func(es []Entry) { es[1].ContentHash = "not|a|hash" },
			true, BreakInvalidField, 1},
		{"uppercase content hash", func(es []Entry) { es[1].ContentHash = strings.Repeat("AB", 64) },
			true, BreakInvalidField, 1},
		{"negative global_seq on the first entry", func(es []Entry) {
			for i := range es {
				es[i].GlobalSeq = int64(i) - 7
			}
		}, true, BreakSequenceGap, 0},
		{"a whole chain that does not start at 0", func(es []Entry) {
			for i := range es {
				es[i].GlobalSeq = int64(i) + 1
			}
		}, true, BreakSequenceGap, 0},
		{"chain hash that is not a digest", func(es []Entry) { es[2].ChainHash = "short" },
			false, BreakInvalidField, 2},
		{"a tombstone whose chain hash is not a digest", func(es []Entry) {
			es[2].EntryType, es[2].EntryID = chainformat.TombstoneEntryType, "tomb_x"
			es[2].ContentHash = chainformat.TombstoneContentHashPrefix + strings.Repeat("ab", 32)
			es[2].ChainHash = "a|b"
		}, false, BreakInvalidField, 2},
		{"timestamp in another offset", func(es []Entry) { es[1].Timestamp = "2026-09-24T15:30:01.000000+05:30" },
			false, BreakInvalidTimestamp, 1},
		{"timestamp with no fraction", func(es []Entry) { es[1].Timestamp = "2026-09-24T10:00:01Z" },
			false, BreakInvalidTimestamp, 1},
		{"timestamp with nanoseconds", func(es []Entry) { es[1].Timestamp = "2026-09-24T10:00:01.000000999Z" },
			false, BreakInvalidTimestamp, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, _ := buildChain(t, 4)
			tc.mutate(entries)
			if tc.relink {
				relink(t, entries)
			}
			b := firstBreak(t, entries, Options{})
			if b.Type != tc.want || b.Position != tc.at {
				t.Fatalf("first break = %s at %d (%s), want %s at %d", b.Type, b.Position, b.Detail, tc.want, tc.at)
			}
			if strings.Contains(b.Detail, "not|a|hash") {
				t.Error("the break detail echoes the field's value")
			}
		})
	}
}

// TestChain_TimestampSpellingsHashAlike is the control for the timestamp
// cases above: the three refused spellings name the instant the entry was
// hashed at, so without the stored-form check each would verify.
func TestChain_TimestampSpellingsHashAlike(t *testing.T) {
	want, _ := time.Parse(time.RFC3339Nano, "2026-09-24T10:00:01.000000Z")
	for _, s := range []string{"2026-09-24T15:30:01.000000+05:30", "2026-09-24T10:00:01Z", "2026-09-24T10:00:01.000000999Z"} {
		got, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		a := chainformat.ComputeChainHashV3Unchecked("", 1, want, strings.Repeat("ab", 64))
		b := chainformat.ComputeChainHashV3Unchecked("", 1, got, strings.Repeat("ab", 64))
		if a != b {
			t.Errorf("%s hashes differently; it is not a second spelling of the same instant", s)
		}
	}
}

// TestChain_SegmentStart: a segment links from a well-formed predecessor hash
// and starts after global_seq 0.
func TestChain_SegmentStart(t *testing.T) {
	entries, _ := buildChain(t, 4)
	segment, prev := entries[2:], entries[1].ChainHash

	res, err := Chain(segment, Options{PreviousHash: prev})
	if err != nil || res.Verdict != VerdictIntact {
		t.Fatalf("a good segment: %s, %v", res.Verdict, err)
	}
	if b := firstBreak(t, segment, Options{}); b.Type != BreakSequenceGap || b.Position != 0 {
		t.Fatalf("a segment verified as a whole chain: %s at %d", b.Type, b.Position)
	}
	if b := firstBreak(t, segment, Options{PreviousHash: "abc"}); b.Type != BreakInvalidField {
		t.Fatalf("a malformed previous hash: %s", b.Type)
	}
	if b := firstBreak(t, entries, Options{PreviousHash: prev}); b.Type != BreakSequenceGap {
		t.Fatalf("a whole chain verified as a segment: %s", b.Type)
	}
}

// TestBindAnchor_OneTombstonePredicate: an entry is a tombstone by its type and
// id, for the binder as for Chain. The binder once took any entry whose content
// hash began "TOMBSTONE:" as erased and adopted its stored chain hash, so
// marking only the LAST entry that way let every other entry be replaced under
// a valid signed anchor.
func TestBindAnchor_OneTombstonePredicate(t *testing.T) {
	entries, head := buildChain(t, 5)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)

	forged, _ := buildChain(t, 5)
	for i := range forged {
		forged[i].ContentHash = strings.Repeat("f", 128)
	}
	relink(t, forged)
	forged[4].ChainHash = entries[4].ChainHash
	forged[4].ContentHash = chainformat.TombstoneContentHashPrefix + strings.Repeat("0", 64)

	res, err := BindAnchor(a, forged, anchor.SeedAnchorHash)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if res.Bound || res.Outcome != BindChainBroken {
		t.Fatalf("bound = %v, outcome = %s; want chain_broken", res.Bound, res.Outcome)
	}
	chain, _ := Chain(forged, Options{})
	if chain.Verdict != VerdictBroken {
		t.Fatalf("Chain disagrees with the binder: %s", chain.Verdict)
	}
}

// TestBindAnchor_ReportsWhatATombstoneLeavesUnbound pins the limitation, not a
// defence. A real tombstone's chain hash is taken as stored, so the entries
// before it can be replaced and the anchor still binds. Until the format
// changes, the result says so: how many entries are not bound, and in words.
//
// When a format version closes this, the assertion that the forged chain binds
// fails, and this test and docs/verification-model.md change together.
func TestBindAnchor_ReportsWhatATombstoneLeavesUnbound(t *testing.T) {
	entries, head := buildChain(t, 5)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)

	clean, err := BindAnchor(a, entries, anchor.SeedAnchorHash)
	if err != nil || !clean.Bound {
		t.Fatalf("clean bind: %+v, %v", clean, err)
	}
	if clean.Tombstones != 0 || clean.EntriesNotBound != 0 || strings.Contains(clean.NotProven, "erased") {
		t.Fatalf("a chain with no tombstone reports one: %+v", clean)
	}

	// Rewrite entries 0 and 1, turn entry 2 into a tombstone that keeps its
	// chain hash, and leave 3 and 4 alone.
	forged := append([]Entry(nil), entries...)
	forged[0].ContentHash, forged[1].ContentHash = strings.Repeat("1", 128), strings.Repeat("2", 128)
	relink(t, forged[:2])
	forged[2].EntryType = chainformat.TombstoneEntryType
	forged[2].EntryID = "tomb_00000000-0000-0000-0000-000000000000"
	forged[2].ContentHash = chainformat.TombstoneContentHashPrefix + strings.Repeat("0", 64)

	chain, _ := Chain(forged, Options{})
	if chain.Verdict != VerdictIntact || chain.TombstonesFound != 1 || chain.LastTombstone != 2 {
		t.Fatalf("Chain = %s, %d tombstones, last at %d", chain.Verdict, chain.TombstonesFound, chain.LastTombstone)
	}
	res, err := BindAnchor(a, forged, anchor.SeedAnchorHash)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if !res.Bound {
		t.Fatalf("the forged chain no longer binds (%s): the limitation is closed; update this test and the docs", res.Outcome)
	}
	if res.Tombstones != 1 || res.EntriesNotBound != 3 {
		t.Fatalf("tombstones = %d, entries not bound = %d; want 1 and 3", res.Tombstones, res.EntriesNotBound)
	}
	if !strings.Contains(res.Proven, "entries 3 to 4") || !strings.Contains(res.NotProven, "first 3 entries") {
		t.Fatalf("the claim does not state the unbound range:\n  proven: %s\n  not proven: %s", res.Proven, res.NotProven)
	}
}
