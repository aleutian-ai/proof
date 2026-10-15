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
		{"negative global_seq", func(es []Entry) {
			for i := range es {
				es[i].GlobalSeq = int64(i) - 7
			}
		}, true, BreakInvalidField, 0},
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

// TestChain_SegmentStart: a segment links from a well-formed predecessor hash.
func TestChain_SegmentStart(t *testing.T) {
	entries, _ := buildChain(t, 4)
	segment, prev := entries[2:], entries[1].ChainHash

	res, err := Chain(segment, Options{PreviousHash: prev})
	if err != nil || res.Verdict != VerdictIntact {
		t.Fatalf("a good segment: %s, %v", res.Verdict, err)
	}
	if b := firstBreak(t, segment, Options{PreviousHash: "abc"}); b.Type != BreakInvalidField {
		t.Fatalf("a malformed previous hash: %s", b.Type)
	}
}

// TestChain_FirstSequenceNumberIsNotFixed: the format does not say where a
// chain starts. This module's linker starts at 0 and the hosted platform's at
// 1, and both verify. A rule that a chain starts at 0 was added and withdrawn
// on 2026-10-11: it reported every platform chain as broken.
func TestChain_FirstSequenceNumberIsNotFixed(t *testing.T) {
	for _, start := range []int64{0, 1, 1001} {
		entries, _ := buildChain(t, 4)
		for i := range entries {
			entries[i].GlobalSeq = start + int64(i)
		}
		relink(t, entries)
		res, err := Chain(entries, Options{})
		if err != nil || res.Verdict != VerdictIntact {
			t.Errorf("a chain starting at global_seq %d: %s, %v", start, res.Verdict, err)
		}
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

// TestChain_ATombstoneStillDeclaresAValidFormat: a tombstone's hash is not
// recomputed, but its format version and field use are checked like any
// entry's. The tombstone branch once returned before the format dispatch, so a
// tombstone with format_version 99, or a v3 one carrying run_id, was INTACT.
func TestChain_ATombstoneStillDeclaresAValidFormat(t *testing.T) {
	cases := map[string]struct {
		mutate func(e *Entry)
		want   BreakType
	}{
		"unknown format version": {func(e *Entry) { e.FormatVersion = 99 }, BreakUnknownFormat},
		"v3 carrying run_id":     {func(e *Entry) { e.RunID = "run-1" }, BreakFormatFieldMisuse},
		"v3 carrying sequence":   {func(e *Entry) { e.SequenceNum = 4 }, BreakFormatFieldMisuse},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entries, _ := buildChain(t, 4)
			entries[2].EntryType = chainformat.TombstoneEntryType
			entries[2].EntryID = "tomb_00000000-0000-0000-0000-000000000000"
			entries[2].ContentHash = chainformat.TombstoneContentHashPrefix + strings.Repeat("ab", 32)
			if res, _ := Chain(entries, Options{}); res.Verdict != VerdictIntact {
				t.Fatalf("control failed: a well-formed tombstone is %s", res.Verdict)
			}
			tc.mutate(&entries[2])
			if b := firstBreak(t, entries, Options{}); b.Type != tc.want || b.Position != 2 {
				t.Fatalf("first break = %s at %d, want %s at 2", b.Type, b.Position, tc.want)
			}
		})
	}
}

// TestVerifyAnchor_ASignatureErrorIsNeverBound: with a signature that does not
// verify, the result beside the error says so and is not bound. It once carried
// Bound=true and Outcome "bound" next to the error, for a caller to read after
// dropping the error.
func TestVerifyAnchor_ASignatureErrorIsNeverBound(t *testing.T) {
	entries, _ := buildChain(t, 5)
	series, ring := series(t, entries, 5)
	a := series[0]

	good, err := VerifyAnchor(a, entries, anchor.SeedAnchorHash, ring)
	if err != nil || !good.Bound || !good.SignatureVerified {
		t.Fatalf("control failed: %+v, %v", good, err)
	}

	empty, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{})
	if err != nil {
		t.Skipf("an empty key ring cannot be built: %v", err)
	}
	res, err := VerifyAnchor(a, entries, anchor.SeedAnchorHash, empty)
	if err == nil {
		t.Fatal("an anchor signed by an unknown key verified")
	}
	if res.Bound || res.SignatureVerified || res.Outcome != BindSignatureInvalid {
		t.Fatalf("result beside the error = %+v", res)
	}
	if !strings.Contains(res.Detail, "does match") || !strings.HasPrefix(res.Proven, "nothing") {
		t.Fatalf("detail %q, proven %q", res.Detail, res.Proven)
	}
}

// TestBindAnchor_OnlyABindSaysTheChainIsTheAnchors: a result that is not bound
// says nothing was proven. Every outcome once carried the wording of a
// successful bind ("the chain in front of you is the one this anchor committed
// to"), printed by the CLI directly under "ANCHOR DOES NOT DESCRIBE THIS CHAIN".
func TestBindAnchor_OnlyABindSaysTheChainIsTheAnchors(t *testing.T) {
	entries, head := buildChain(t, 5)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)

	bound, err := BindAnchor(a, entries, anchor.SeedAnchorHash)
	if err != nil || !bound.Bound || !strings.Contains(bound.Proven, "is the one this anchor committed to") {
		t.Fatalf("control failed: %+v, %v", bound, err)
	}

	edited := append([]Entry(nil), entries...)
	edited[2].ContentHash = strings.Repeat("f", 128)
	wrongHead := a
	wrongHead.ChainHash = strings.Repeat("e", 128)
	for name, res := range map[string]BindResult{
		"chain_broken":       mustBind(t, a, edited),
		"range_end_mismatch": mustBind(t, a, entries[:4]),
		"head_mismatch":      mustBind(t, wrongHead, entries),
		"predecessor_mismatch": func() BindResult {
			r, err := BindAnchor(a, entries, strings.Repeat("a", 128))
			if err != nil {
				t.Fatal(err)
			}
			return r
		}(),
	} {
		if res.Bound || string(res.Outcome) != name {
			t.Fatalf("%s: got %+v", name, res)
		}
		if !strings.HasPrefix(res.Proven, "nothing") || strings.Contains(res.Proven, "is the one this anchor committed to") {
			t.Errorf("%s: a result that is not bound says %q", name, res.Proven)
		}
	}
}

func mustBind(t *testing.T, a anchor.Anchor, entries []Entry) BindResult {
	t.Helper()
	res, err := BindAnchor(a, entries, anchor.SeedAnchorHash)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestVerifyAnchor_NoKeySourceIsAnError: a nil key source, or a nil *KeyRing
// passed as one, is an error from both VerifyAnchor functions. A nil key ring
// panicked once the signature came to be checked even when the bind failed.
func TestVerifyAnchor_NoKeySourceIsAnError(t *testing.T) {
	entries, head := buildChain(t, 3)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)
	var nilRing *anchor.KeyRing
	for name, src := range map[string]anchor.KeySource{"nil interface": nil, "nil *KeyRing": nilRing} {
		t.Run(name, func(t *testing.T) {
			if res, err := VerifyAnchor(a, entries, anchor.SeedAnchorHash, src); err == nil || res.Bound {
				t.Fatalf("VerifyAnchor: %+v, %v", res, err)
			}
			w := NewWalker(Options{})
			for _, e := range entries {
				w.Add(e)
			}
			if res, err := w.VerifyAnchor(a, anchor.SeedAnchorHash, src); err == nil || res.Bound {
				t.Fatalf("Walker.VerifyAnchor: %+v, %v", res, err)
			}
		})
	}
}
