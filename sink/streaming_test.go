// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// TestStreaming_AcrossPages: a chain longer than two pages, with checkpoints on
// both sides of the page boundaries, verifies in the paged walk; then one
// tampered entry in the middle page leaves the checkpoints before it verified
// and the ones after it not.
func TestStreaming_AcrossPages(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	for _, n := range []int{entryPage - 1, 2, entryPage, 502} { // checkpoints at 999, 1001, 2001, 2503
		if _, err := s.Commit(ctx, events("u-1", n)); err != nil {
			t.Fatal(err)
		}
		if done, err := s.Checkpoint(ctx, signer, nil); err != nil || len(done) != 1 || done[0].Problem != "" {
			t.Fatalf("checkpoint: %+v, %v", done, err)
		}
	}
	c := chainReport(t, mustVerify(t, s, ring), "u-1")
	if c.Entries != 2503 || c.Opened != 2503 || c.Checkpoints != 4 || c.Unanchored != 0 {
		t.Fatalf("across pages: %+v", c)
	}

	// Tamper entry 1500 (in the second page) through the store, as a writer can.
	st, err := boltstore.Open(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.Range(ctx, "u-1", 1500, 1500, 1)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	rows[0].ContentHash = strings.Repeat("ab", 64)
	if err := st.WriteBatch(ctx, rows); err != nil {
		t.Fatal(err)
	}
	st.Close()
	r, err := s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	c = chainReport(t, r, "u-1")
	p := strings.Join(c.Problems, "; ")
	if c.Checkpoints != 2 || !strings.Contains(p, "links BROKEN at entry 1500") ||
		!strings.Contains(p, "checkpoint 0003") {
		t.Fatalf("after tampering entry 1500: %d checkpoints verified, problems %q", c.Checkpoints, p)
	}
}

// TestStreaming_CheckpointBeyondTheChain: a checkpoint claiming more entries
// than the chain holds is never reached by the walk; it is reported at the end.
func TestStreaming_CheckpointBeyondTheChain(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	f, err := s.openFolder(false)
	if err != nil {
		t.Fatal(err)
	}
	series, _, err := f.readAnchors("u-81")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := readChain(ctx, st, "u-81")
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	next, err := build.Anchor(ctx, build.Input{Subject: "u-81", Entries: entries, Previous: &series[0]})
	if err != nil {
		t.Fatal(err)
	}
	next.EntryCount = int64(len(entries)) + 5
	next.VerifiedThrough = next.EntryCount
	signed, err := anchor.SignAnchor(ctx, signer, next)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(signed, "", "  ")
	if err := os.WriteFile(filepath.Join(s.anchorDir("u-81"), "0002.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if p := problems(t, s, ring, "u-81"); !strings.Contains(p, "checkpoint 0002 claims 8 entries; the chain has 3") {
		t.Fatalf("problems: %q", p)
	}
}
