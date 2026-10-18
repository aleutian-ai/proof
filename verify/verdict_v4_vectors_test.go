// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/fixtures"
)

// verdictV4Vectors mirrors fixtures/testdata/verify_verdict_v4_vectors.json.
// Entries stay raw so that they are read by DecodeEntries, as a file is: some
// cases turn on a member being present with an empty value.
type verdictV4Vectors struct {
	ChainCases []struct {
		Name         string          `json:"name"`
		PreviousHash string          `json:"previous_hash"`
		Entries      json.RawMessage `json:"entries"`
		Expected     struct {
			Verdict         string `json:"verdict"`
			FirstBreak      int    `json:"first_break"`
			FirstBreakType  string `json:"first_break_type"`
			TombstonesFound int    `json:"tombstones_found"`
			LastTombstone   int    `json:"last_tombstone"`
			ErasedFound     int    `json:"erased_found"`
			Breaks          int    `json:"breaks"`
		} `json:"expected"`
	} `json:"chain_cases"`
	EntriesTextCases []struct {
		Name       string `json:"name"`
		Text       string `json:"text"`
		TextBase64 string `json:"text_base64"`
		Expected   string `json:"expected"`
	} `json:"entries_text_cases"`
	BindCases []struct {
		Name         string          `json:"name"`
		Entries      json.RawMessage `json:"entries"`
		Anchor       json.RawMessage `json:"anchor"`
		PreviousHash string          `json:"previous_hash"`
		Expect       struct {
			Subject            string `json:"subject"`
			PreviousAnchorHash string `json:"previous_anchor_hash"`
		} `json:"expect"`
		Expected struct {
			Error           bool   `json:"error"`
			Outcome         string `json:"outcome"`
			Bound           bool   `json:"bound"`
			Tombstones      int    `json:"tombstones"`
			EntriesNotBound int64  `json:"entries_not_bound"`
			SubjectChecked  bool   `json:"subject_checked"`
		} `json:"expected"`
	} `json:"bind_cases"`
}

func loadVerdictV4(t *testing.T) verdictV4Vectors {
	t.Helper()
	var v verdictV4Vectors
	if err := json.Unmarshal(fixtures.VerifyVerdictV4Vectors(), &v); err != nil {
		t.Fatalf("decode the v4 verdict vectors: %v", err)
	}
	if len(v.ChainCases) < 30 || len(v.BindCases) < 15 {
		t.Fatalf("%d chain cases, %d bind cases: the file was truncated", len(v.ChainCases), len(v.BindCases))
	}
	return v
}

// TestVerdictV4Vectors_Chains holds the walk to the v4 chain cases, declared
// in Python from the spec. A failing case is a bug here or a disagreement with
// the spec, never fixed by changing the vector.
func TestVerdictV4Vectors_Chains(t *testing.T) {
	for _, c := range loadVerdictV4(t).ChainCases {
		t.Run(c.Name, func(t *testing.T) {
			entries, err := DecodeEntries(c.Entries)
			if err != nil {
				t.Fatalf("the case's entries do not decode: %v", err)
			}
			res, err := Chain(entries, Options{PreviousHash: c.PreviousHash})
			if err != nil {
				t.Fatal(err)
			}
			firstType := ""
			if len(res.Breaks) > 0 {
				firstType = string(res.Breaks[0].Type)
			}
			if string(res.Verdict) != c.Expected.Verdict || res.FirstBreak != c.Expected.FirstBreak ||
				firstType != c.Expected.FirstBreakType || res.TombstonesFound != c.Expected.TombstonesFound ||
				res.LastTombstone != c.Expected.LastTombstone || res.ErasedFound != c.Expected.ErasedFound ||
				len(res.Breaks) != c.Expected.Breaks {
				t.Fatalf("got %s, first break %d (%s), %d tombstones, last at %d, %d erased, %d breaks\nwant %+v\nbreaks %+v",
					res.Verdict, res.FirstBreak, firstType, res.TombstonesFound, res.LastTombstone,
					res.ErasedFound, len(res.Breaks), c.Expected, res.Breaks)
			}
		})
	}
}

// TestVerdictV4Vectors_EntriesText holds both readers to what a v4 entries
// file must be before any check: one spelling of every member and every
// string, and text that is not repaired.
func TestVerdictV4Vectors_EntriesText(t *testing.T) {
	cases := loadVerdictV4(t).EntriesTextCases
	if len(cases) < 15 {
		t.Fatalf("%d entries text cases: the file was truncated", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			raw := []byte(c.Text)
			if c.TextBase64 != "" {
				var err error
				if raw, err = base64.StdEncoding.DecodeString(c.TextBase64); err != nil {
					t.Fatal(err)
				}
			}
			_, err := DecodeEntries(raw)
			r := NewEntryReader(bytes.NewReader(raw))
			var rerr error
			for rerr == nil {
				_, rerr = r.Next()
			}
			if rerr == io.EOF {
				rerr = nil
			}
			want := c.Expected == "entries"
			if (err == nil) != want || (rerr == nil) != want {
				t.Fatalf("DecodeEntries: %v; EntryReader: %v; want %s", err, rerr, c.Expected)
			}
		})
	}
}

// TestEntryMarshalJSON_V4RoundTrips: every entry of every intact chain in the
// vectors, decoded and written again, decodes to the same entry, and an erased
// entry is written without the members it must not carry. (A malformed entry
// cannot round-trip: its shape is what is wrong with it.)
func TestEntryMarshalJSON_V4RoundTrips(t *testing.T) {
	for _, c := range loadVerdictV4(t).ChainCases {
		if c.Expected.Verdict != "INTACT" {
			continue
		}
		entries, err := DecodeEntries(c.Entries)
		if err != nil {
			t.Fatal(err)
		}
		for i, e := range entries {
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeEntries(append(append([]byte("["), raw...), ']'))
			if err != nil {
				t.Fatalf("%s[%d]: %s does not decode: %v", c.Name, i, raw, err)
			}
			if again[0] != e {
				t.Errorf("%s[%d]: round trip changed the entry:\n%+v\n%+v", c.Name, i, e, again[0])
			}
		}
	}
	erased := Entry{FormatVersion: 4, Erased: true, GlobalSeq: 3, Timestamp: "t", LeafHash: "l", ChainHash: "c"}
	raw, _ := json.Marshal(erased)
	if want := `{"timestamp":"t","format_version":4,"global_seq":3,"erased":true,"leaf_hash":"l","chain_hash":"c"}`; string(raw) != want {
		t.Errorf("erased entry written as %s\nwant %s", raw, want)
	}
	v3 := Entry{FormatVersion: 3, EntryID: "e", EntryType: "t", Timestamp: "ts", ContentHash: "h", ChainHash: "c"}
	raw, _ = json.Marshal(v3)
	if want := `{"entry_id":"e","entry_type":"t","timestamp":"ts","format_version":3,"run_id":"","sequence_num":0,"global_seq":0,"content_hash":"h","chain_hash":"c"}`; string(raw) != want {
		t.Errorf("v3 entry written as %s\nwant %s (v3 exports must not change)", raw, want)
	}
}

// TestVerdictV4Vectors_Binds holds BindAnchor to the v7 bind cases: binds by
// sequence, erasure that changes nothing an anchor binds, the order of the
// checks, and what the caller expects. Both the slice path and the walker
// path are held to them.
func TestVerdictV4Vectors_Binds(t *testing.T) {
	for _, c := range loadVerdictV4(t).BindCases {
		t.Run(c.Name, func(t *testing.T) {
			entries, err := DecodeEntries(c.Entries)
			if err != nil {
				t.Fatalf("the case's entries do not decode: %v", err)
			}
			var a anchor.Anchor
			if err := json.Unmarshal(c.Anchor, &a); err != nil {
				t.Fatalf("the case's anchor does not parse: %v", err)
			}
			expect := Expect{Subject: c.Expect.Subject, PreviousAnchorHash: c.Expect.PreviousAnchorHash}
			var res BindResult
			if c.PreviousHash == "" {
				res, err = BindAnchor(a, entries, expect)
			} else {
				w := NewWalker(Options{PreviousHash: c.PreviousHash})
				for _, e := range entries {
					w.Add(e)
				}
				res, err = w.BindAnchor(a, expect)
			}
			if c.Expected.Error {
				if err == nil {
					t.Fatalf("accepted: %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(res.Outcome) != c.Expected.Outcome || res.Bound != c.Expected.Bound ||
				res.Tombstones != c.Expected.Tombstones || res.EntriesNotBound != c.Expected.EntriesNotBound ||
				res.SubjectChecked != c.Expected.SubjectChecked {
				t.Fatalf("got %s (%s), bound %v, %d tombstones, %d not bound, subject checked %v\nwant %+v",
					res.Outcome, res.Detail, res.Bound, res.Tombstones, res.EntriesNotBound, res.SubjectChecked, c.Expected)
			}
			if res.Bound && !res.SubjectChecked && !strings.Contains(res.NotProven, "subject was not checked") {
				t.Errorf("not_proven does not say the subject was not checked: %q", res.NotProven)
			}

			// The walker binds what it has seen: given the entries through the
			// anchor's end, it must agree with the slice path.
			if c.PreviousHash == "" && res.Outcome != BindChainBroken {
				end := len(entries)
				for i, e := range entries {
					if e.GlobalSeq == a.Range.EndSeq {
						end = i + 1
					}
				}
				w := NewWalker(Options{MaxBreaks: 1})
				for _, e := range entries[:end] {
					w.Add(e)
				}
				wr, werr := w.BindAnchor(a, expect)
				if werr != nil || wr.Outcome != res.Outcome || wr.EntriesNotBound != res.EntriesNotBound {
					t.Errorf("the walker path gave %s, %d not bound, %v; the slice path %s, %d",
						wr.Outcome, wr.EntriesNotBound, werr, res.Outcome, res.EntriesNotBound)
				}
			}
			// Given every entry, a walker told the tip in advance agrees with
			// the slice path too: a chain that has grown since still binds
			// (§9.7). Without WatchTip it once reported height_mismatch.
			if c.PreviousHash == "" {
				w := NewWalker(Options{MaxBreaks: 1})
				w.WatchTip(a.Range.EndSeq)
				for _, e := range entries {
					w.Add(e)
				}
				wr, werr := w.BindAnchor(a, expect)
				if werr != nil || wr.Outcome != res.Outcome || wr.Tombstones != res.Tombstones ||
					wr.EntriesNotBound != res.EntriesNotBound {
					t.Errorf("the watching walker gave %s, %d tombstones, %d not bound, %v; the slice path %s, %d, %d",
						wr.Outcome, wr.Tombstones, wr.EntriesNotBound, werr, res.Outcome, res.Tombstones, res.EntriesNotBound)
				}
			}
		})
	}
}
