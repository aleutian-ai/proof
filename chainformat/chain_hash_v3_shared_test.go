// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/fixtures"
)

type v3Vector struct {
	Name           string `json:"name"`
	PreviousHash   string `json:"previous_hash"`
	GlobalSeq      string `json:"global_seq"`
	TimestampInput string `json:"timestamp_input"`
	Timestamp      string `json:"timestamp"`
	ContentHash    string `json:"content_hash"`
	ExpectedHash   string `json:"expected_hash"`
}

// TestChainHashV3_SharedVectors holds Go to the shared vectors, whose expected
// values were computed in Python from the spec — not by this package.
func TestChainHashV3_SharedVectors(t *testing.T) {
	var file struct {
		Domain  string     `json:"domain"`
		Vectors []v3Vector `json:"vectors"`
		Reject  []v3Vector `json:"reject"`
	}
	if err := json.Unmarshal(fixtures.ChainV3Vectors(), &file); err != nil {
		t.Fatal(err)
	}
	if file.Domain != ChainHashPrefixV3 {
		t.Fatalf("vectors are for %q, this package uses %q", file.Domain, ChainHashPrefixV3)
	}
	if len(file.Vectors) < 6 || len(file.Reject) < 4 {
		t.Fatalf("%d vectors / %d reject cases: the file was truncated", len(file.Vectors), len(file.Reject))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			seq, err := strconv.ParseInt(v.GlobalSeq, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			in := v.Timestamp
			if v.TimestampInput != "" {
				in = v.TimestampInput
			}
			ts, err := time.Parse(time.RFC3339Nano, in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ComputeChainHashV3(v.PreviousHash, seq, ts, v.ContentHash)
			if err != nil {
				t.Fatal(err)
			}
			if got != v.ExpectedHash {
				t.Errorf("hash = %s\n want %s", got, v.ExpectedHash)
			}
		})
	}
	for _, v := range file.Reject {
		t.Run("reject: "+v.Name, func(t *testing.T) {
			seq, err := strconv.ParseInt(v.GlobalSeq, 10, 64)
			if err != nil {
				return // unparseable is refused
			}
			ts, err := time.Parse(time.RFC3339Nano, v.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ComputeChainHashV3(v.PreviousHash, seq, ts, v.ContentHash); err == nil {
				t.Error("accepted a case every implementation must refuse")
			}
		})
	}
}
