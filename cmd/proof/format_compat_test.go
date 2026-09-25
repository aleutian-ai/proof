// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/verify"
)

// TestExport_V2BytesAreUnchanged is a compatibility promise, not a style test.
//
// The published verification SDKs read these field names. A v2 export must
// carry exactly the fields it carried before v3 existed — including
// "sequence_num": 0, which an `omitempty` tag would silently drop from the
// first entry of every chain — and must NOT carry a format_version field,
// since entries written before the field existed do not have one.
func TestExport_V2BytesAreUnchanged(t *testing.T) {
	row := store.Entry{
		EntryID:       "e00",
		EntryType:     "capture.request.v3",
		FormatVersion: chainformat.FormatV2,
		GlobalSeq:     0,
		RunID:         "0123456789abcdef0123456789abcdef",
		SequenceNum:   0,
		ContentHash:   strings.Repeat("ab", 64),
		ChainHash:     strings.Repeat("cd", 64),
	}

	raw, err := json.Marshal(toExported(row))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)

	for _, want := range []string{`"run_id":"0123456789abcdef0123456789abcdef"`, `"sequence_num":0`} {
		if !strings.Contains(got, want) {
			t.Errorf("a v2 export lost %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "format_version") {
		t.Errorf("a v2 export gained a format_version field:\n%s", got)
	}
}

// TestExport_LegacyRowWithNoFormatVersionIsV2 covers a database written before
// v3 existed: the field decodes as zero, and zero must mean v2. Getting this
// wrong makes every chain ever written unverifiable.
func TestExport_LegacyRowWithNoFormatVersionIsV2(t *testing.T) {
	legacy := store.Entry{
		EntryID:     "e00",
		EntryType:   "capture.request.v3",
		RunID:       "0123456789abcdef0123456789abcdef",
		SequenceNum: 3,
		ContentHash: strings.Repeat("ab", 64),
		ChainHash:   strings.Repeat("cd", 64),
	} // FormatVersion deliberately left at its zero value

	e := toExported(legacy)
	if e.RunID == "" || e.SequenceNum != 3 {
		t.Error("a legacy row lost its v2 hash inputs")
	}
	if e.FormatVersion != 0 {
		t.Errorf("a legacy row gained format_version %d", e.FormatVersion)
	}
}

// TestExport_V3CarriesItsFormatAndNoV2Fields: a v3 entry must say it is v3 —
// the formats are indistinguishable from the digest alone — and must not carry
// fields its hash does not bind.
func TestExport_V3CarriesItsFormatAndNoV2Fields(t *testing.T) {
	row := store.Entry{
		EntryID:       "e00",
		EntryType:     "capture.request.v3",
		FormatVersion: chainformat.FormatV3,
		GlobalSeq:     7,
		ContentHash:   strings.Repeat("ab", 64),
		ChainHash:     strings.Repeat("cd", 64),
	}

	e := toExported(row)
	if e.FormatVersion != chainformat.FormatV3 {
		t.Errorf("format_version = %d, want %d", e.FormatVersion, chainformat.FormatV3)
	}
	if e.RunID != "" || e.SequenceNum != 0 {
		t.Errorf("a v3 export carries v2 fields: run_id=%q sequence_num=%d", e.RunID, e.SequenceNum)
	}

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"format_version":3`) {
		t.Errorf("the v3 export does not name its format:\n%s", raw)
	}
}

// TestExport_StrippingTheFormatVersionBreaksVerification is the reason the
// field must travel with the entry: without it a v3 entry is read as v2 and
// reported as a break on an intact chain.
func TestExport_StrippingTheFormatVersionBreaksVerification(t *testing.T) {
	ts := "2026-09-23T14:30:45.123456Z"
	content := strings.Repeat("ab", 64)
	hash := chainformat.ComputeChainHashV3Unchecked("", 0, mustParse(t, ts), content)

	good := []verify.Entry{{
		EntryID: "e00", EntryType: "capture.request.v3", Timestamp: ts,
		FormatVersion: chainformat.FormatV3, GlobalSeq: 0,
		ContentHash: content, ChainHash: hash,
	}}
	res, err := verify.Chain(good, verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != verify.VerdictIntact {
		t.Fatalf("an intact v3 chain did not verify: %q %+v", res.Verdict, res.Breaks)
	}

	stripped := append([]verify.Entry(nil), good...)
	stripped[0].FormatVersion = 0 // as if the field had been dropped in transit
	res, err = verify.Chain(stripped, verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != verify.VerdictBroken {
		t.Error("a v3 entry read as v2 verified anyway; the formats are not distinguishable")
	}
}

// mustParse parses an exported timestamp or fails the test.
func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}
