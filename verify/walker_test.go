// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/mldsa"
)

// series signs checkpoints over prefixes of entries, chained, and returns them
// with the key ring that verifies them.
func series(t *testing.T, entries []Entry, counts ...int) ([]anchor.Anchor, anchor.KeySource) {
	t.Helper()
	signer, err := anchor.NewMLDSA65Signer(make([]byte, mldsa.MLDSA65.SeedSize()))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	var out []anchor.Anchor
	prevHash, prevID := anchor.SeedAnchorHash, anchor.SeedAnchorID
	for i, n := range counts {
		res, err := Chain(entries[:n], Options{})
		if err != nil || res.FirstBreak >= 0 {
			t.Fatalf("building the series: %v, break %d", err, res.FirstBreak)
		}
		head := entries[n-1].ChainHash
		a := anchorOver(t, entries[:n], head, prevHash)
		a.AnchorID = "anchor_0000000" + string(rune('0'+i)) + "-0000-0000-0000-000000000000"
		a.PreviousAnchorID = prevID
		a.SigningKeyID = ""
		signed, err := anchor.SignAnchor(context.Background(), signer, a)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, signed)
		prevHash, prevID = signed.ChainHash, signed.AnchorID
	}
	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{out[0].SigningKeyID: pub})
	if err != nil {
		t.Fatal(err)
	}
	return out, ring
}

// TestWalker_SameResultAsVerifyAnchor: binding each checkpoint as a single
// walk reaches it gives what VerifyAnchor gives over entries[:EntryCount]:
// intact, with a (well-formed) tombstone, and tampered, with checkpoints that
// end exactly at the tombstone and at the break.
func TestWalker_SameResultAsVerifyAnchor(t *testing.T) {
	cases := map[string]func(es []Entry){
		"intact": func([]Entry) {},
		"tombstone": func(es []Entry) {
			es[2].EntryType = chainformat.TombstoneEntryType
			es[2].ContentHash = chainformat.TombstoneContentHashPrefix + strings.Repeat("ab", 32)
		},
		"tampered": func(es []Entry) { es[4].ContentHash = strings.Repeat("fedcba9876543210", 8) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entries, _ := buildChain(t, 8)
			anchors, ring := series(t, entries, 2, 3, 4, 5, 6, 8)
			mutate(entries)
			if name == "tombstone" {
				// A tombstone replaces the id too; keep ids in step for both paths.
				entries[2].EntryID = chainformat.TombstoneEntryIDPrefix + entries[2].EntryID
			}
			w := NewWalker(Options{})
			prev, next := anchor.SeedAnchorHash, 0
			for _, e := range entries {
				w.Add(e)
				for next < len(anchors) && int64(w.Count()) == anchors[next].EntryCount {
					a := anchors[next]
					want, werr := VerifyAnchor(a, entries[:a.EntryCount], prev, ring)
					got, gerr := w.VerifyAnchor(a, prev, ring)
					if (werr == nil) != (gerr == nil) || want.Bound != got.Bound ||
						want.Outcome != got.Outcome || want.SignatureVerified != got.SignatureVerified {
						t.Fatalf("checkpoint over %d: VerifyAnchor = %+v, %v; Walker = %+v, %v",
							a.EntryCount, want, werr, got, gerr)
					}
					prev = a.ChainHash
					next++
				}
			}
			if next != len(anchors) {
				t.Fatalf("only %d of %d checkpoints were reached", next, len(anchors))
			}
		})
	}
}

// TestWalker_IsChain: Chain is a Walker over a slice; the walker's Result after
// every entry equals Chain over that prefix.
func TestWalker_IsChain(t *testing.T) {
	entries, _ := buildChain(t, 6)
	entries[3].ContentHash = strings.Repeat("fedcba9876543210", 8)
	w := NewWalker(Options{})
	for i, e := range entries {
		w.Add(e)
		want, err := Chain(entries[:i+1], Options{})
		if err != nil || !reflect.DeepEqual(want, w.Result()) {
			t.Fatalf("after %d entries: Chain = %+v, %v; Walker = %+v", i+1, want, err, w.Result())
		}
	}
	if _, err := NewWalker(Options{}).VerifyAnchor(anchor.Anchor{}, anchor.SeedAnchorHash, nil); err != ErrNoEntries {
		t.Fatalf("an empty walker: %v", err)
	}
}

// TestWalker_AnchorMustFitWhatWasWalked: an anchor covering more entries than
// the walker has seen is never bound. Usually the range check says so first;
// the count check is what catches it when a crafted chain repeats the anchor's
// last entry id earlier (ids are not in the v3 chain hash).
func TestWalker_AnchorMustFitWhatWasWalked(t *testing.T) {
	entries, _ := buildChain(t, 8)
	anchors, ring := series(t, entries, 8)

	w := NewWalker(Options{})
	for _, e := range entries[:5] {
		w.Add(e)
	}
	if res, err := w.VerifyAnchor(anchors[0], anchor.SeedAnchorHash, ring); err != nil || res.Bound {
		t.Fatalf("an anchor over 8 entries against a walk of 5 was bound: %+v, %v", res, err)
	}

	// Entry 5 carries entry 8's id: first and last ids now match the anchor.
	crafted := append([]Entry(nil), entries...)
	crafted[4].EntryID = entries[7].EntryID
	w = NewWalker(Options{})
	for _, e := range crafted[:5] {
		w.Add(e)
	}
	res, err := w.VerifyAnchor(anchors[0], anchor.SeedAnchorHash, ring)
	if err != nil || res.Bound || res.Outcome != BindHeightMismatch {
		t.Fatalf("a crafted repeated id: %+v, %v; want height_mismatch", res, err)
	}
}
