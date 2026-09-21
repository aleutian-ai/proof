// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store/memory"
)

// TestGoldenVector pins the linker's output to exact hashes.
//
// # Why this exists
//
// Aleutian's hosted platform carries its own linking loop, and these two
// implementations must agree forever: entries linked by one and verified by the
// other are the whole point of publishing this module. A shared hash function is
// not sufficient evidence — the ASSIGNMENT is what can drift. An off-by-one in
// the sequence number, global sequence used where batch-local was meant, or a
// previous-hash advanced at the wrong point all produce a chain that passes its
// own verifier and disagrees with the other implementation.
//
// These values were produced on 2026-09-14 by BOTH implementations
// independently, from identical inputs, and matched byte for byte:
//
//	proof/linker.Append                       (this package)
//	the platform's chain hash, seq 0,1,2      (driven independently)
//
// If this test fails, one side has changed the format. That is a decision to be
// made deliberately with every published SDK in view, never a test to update.
func TestGoldenVector(t *testing.T) {
	const goldenRunID = "0123456789abcdef0123456789abcdef"
	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)

	s := memory.New()
	l, err := linker.New(s, linker.WithRunIDFunc(func() (string, error) { return goldenRunID, nil }))
	if err != nil {
		t.Fatalf("new linker: %v", err)
	}
	inputs := []linker.Input{
		{EntryID: "e-alpha", EntryType: "capture.request.v3", Timestamp: base,
			ContentHash: strings.Repeat("11", 64), IngestedAt: base},
		{EntryID: "e-bravo", EntryType: "capture.request.v3", Timestamp: base.Add(time.Second),
			ContentHash: strings.Repeat("22", 64), IngestedAt: base.Add(time.Second)},
		{EntryID: "e-charlie", EntryType: "capture.request.v3", Timestamp: base.Add(2 * time.Second),
			ContentHash: strings.Repeat("33", 64), IngestedAt: base.Add(2 * time.Second)},
	}
	if _, err := l.Append(context.Background(), "golden-chain", inputs); err != nil {
		t.Fatalf("append: %v", err)
	}

	want := []struct {
		entryID     string
		globalSeq   int64
		sequenceNum int64
		chainHash   string
	}{
		{"e-alpha", 0, 0, "d9844ba412840bc0df8b4f722bd677da0f3abf965389756505b66401f87253d11fed441c2cb7dab5f496e3751064ff9b2f5c0bebd1e69c438f9d2ea26fde016a"},
		{"e-bravo", 1, 1, "160ff5a7e314957717d4c7d57d4da37caaa95dbd9925c8a6f7af99782f8a0a341b94592617d8f65242d7c9b78335f911d9390026080e21bb4bb7f126a35a7039"},
		{"e-charlie", 2, 2, "60079e411dad90df05fa72d06bc7e5cb27fc081a08b0457047c8f8562fd0c05c8bf2601aebd12d57ba227d72b2132b896075441a6d4f0629f64c819a4bf5b3ae"},
	}

	rows, err := s.Range(context.Background(), "golden-chain", 0, 1<<40, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(rows) != len(want) {
		t.Fatalf("stored %d rows, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if rows[i].EntryID != w.entryID {
			t.Errorf("row %d: EntryID = %q, want %q", i, rows[i].EntryID, w.entryID)
		}
		if rows[i].GlobalSeq != w.globalSeq {
			t.Errorf("row %d: GlobalSeq = %d, want %d", i, rows[i].GlobalSeq, w.globalSeq)
		}
		if rows[i].SequenceNum != w.sequenceNum {
			t.Errorf("row %d: SequenceNum = %d, want %d", i, rows[i].SequenceNum, w.sequenceNum)
		}
		if rows[i].ChainHash != w.chainHash {
			t.Errorf("row %d (%s): chain hash drift\n got  %s\n want %s",
				i, w.entryID, rows[i].ChainHash, w.chainHash)
		}
		if rows[i].RunID != goldenRunID {
			t.Errorf("row %d: RunID = %q, want %q", i, rows[i].RunID, goldenRunID)
		}
	}
}
