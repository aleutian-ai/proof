// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/fixtures"
)

// verdictVectors mirrors fixtures/testdata/verify_verdict_vectors.json.
type verdictVectors struct {
	ChainCases []struct {
		Name         string  `json:"name"`
		PreviousHash string  `json:"previous_hash"`
		Entries      []Entry `json:"entries"`
		Expected     struct {
			Verdict         string `json:"verdict"`
			FirstBreak      int    `json:"first_break"`
			FirstBreakType  string `json:"first_break_type"`
			TombstonesFound int    `json:"tombstones_found"`
			LastTombstone   int    `json:"last_tombstone"`
		} `json:"expected"`
	} `json:"chain_cases"`
	EntriesTextCases []struct {
		Name     string `json:"name"`
		Text     string `json:"text"`
		Expected string `json:"expected"`
	} `json:"entries_text_cases"`
	AnchorTextCases []struct {
		Name     string `json:"name"`
		Text     string `json:"text"`
		Expected string `json:"expected"`
	} `json:"anchor_text_cases"`
	BindCases []struct {
		Name               string          `json:"name"`
		Entries            []Entry         `json:"entries"`
		Anchor             json.RawMessage `json:"anchor"`
		PreviousAnchorHash string          `json:"previous_anchor_hash"`
		Expected           struct {
			Error           bool   `json:"error"`
			Outcome         string `json:"outcome"`
			Bound           bool   `json:"bound"`
			Tombstones      int    `json:"tombstones"`
			EntriesNotBound int64  `json:"entries_not_bound"`
		} `json:"expected"`
	} `json:"bind_cases"`
}

// TestVerdictVectors holds this verifier to the verdict vectors: the cases the
// Python and JavaScript verifiers are held to. The expected results were
// declared in Python from the spec; a case failing here is a bug in this
// verifier or a disagreement with the spec, and is never fixed by changing the
// vector to match.
func TestVerdictVectors(t *testing.T) {
	var v verdictVectors
	if err := json.Unmarshal(fixtures.VerifyVerdictVectors(), &v); err != nil {
		t.Fatalf("decode the verdict vectors: %v", err)
	}
	if len(v.ChainCases) == 0 || len(v.EntriesTextCases) == 0 || len(v.AnchorTextCases) == 0 || len(v.BindCases) == 0 {
		t.Fatal("a section of the verdict vectors is empty")
	}

	for _, c := range v.ChainCases {
		t.Run("chain/"+c.Name, func(t *testing.T) {
			res, err := Chain(c.Entries, Options{PreviousHash: c.PreviousHash})
			if err != nil {
				t.Fatal(err)
			}
			firstType := ""
			if len(res.Breaks) > 0 {
				firstType = string(res.Breaks[0].Type)
			}
			if string(res.Verdict) != c.Expected.Verdict || res.FirstBreak != c.Expected.FirstBreak ||
				firstType != c.Expected.FirstBreakType || res.TombstonesFound != c.Expected.TombstonesFound ||
				res.LastTombstone != c.Expected.LastTombstone {
				t.Fatalf("got %s, first break %d (%s), %d tombstones, last at %d\nwant %+v",
					res.Verdict, res.FirstBreak, firstType, res.TombstonesFound, res.LastTombstone, c.Expected)
			}
		})
	}

	for _, c := range v.EntriesTextCases {
		t.Run("entries_text/"+c.Name, func(t *testing.T) {
			_, err := DecodeEntries([]byte(c.Text))
			if got := map[bool]string{true: "entries", false: "not_entries"}[err == nil]; got != c.Expected {
				t.Fatalf("got %s (%v), want %s", got, err, c.Expected)
			}
		})
	}

	for _, c := range v.AnchorTextCases {
		t.Run("anchor_text/"+c.Name, func(t *testing.T) {
			var a anchor.Anchor
			err := json.Unmarshal([]byte(c.Text), &a)
			if got := map[bool]string{true: "parses", false: "refused"}[err == nil]; got != c.Expected {
				t.Fatalf("got %s (%v), want %s", got, err, c.Expected)
			}
		})
	}

	for _, c := range v.BindCases {
		t.Run("bind/"+c.Name, func(t *testing.T) {
			var a anchor.Anchor
			if err := json.Unmarshal(c.Anchor, &a); err != nil {
				t.Fatalf("the case's anchor does not parse: %v", err)
			}
			res, err := BindAnchor(a, c.Entries, c.PreviousAnchorHash)
			if c.Expected.Error {
				if err == nil {
					t.Fatalf("accepted a malformed anchor: %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(res.Outcome) != c.Expected.Outcome || res.Bound != c.Expected.Bound ||
				res.Tombstones != c.Expected.Tombstones || res.EntriesNotBound != c.Expected.EntriesNotBound {
				t.Fatalf("got %s, bound %v, %d tombstones, %d not bound\nwant %+v",
					res.Outcome, res.Bound, res.Tombstones, res.EntriesNotBound, c.Expected)
			}
		})
	}
}
