// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/verify"
)

// writeV4Chain writes a linked v4 chain of n entries to dir/name; with erase,
// entry 1 is in the erased shape (format-spec §2.0, §5.0).
func writeV4Chain(t *testing.T, dir, name string, n int, erase bool) string {
	t.Helper()
	base := time.Date(2026, 1, 20, 12, 0, 0, 123456000, time.UTC)
	entries := make([]verify.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)
		salt, err := chainformat.NewSaltV4()
		if err != nil {
			t.Fatal(err)
		}
		id, typ := "entry_"+hex.EncodeToString([]byte{byte(i)}), "request"
		leaf, err := chainformat.ComputeLeafHashV4(id, typ, contentHash, salt)
		if err != nil {
			t.Fatal(err)
		}
		h, err := chainformat.ComputeChainHashV4(prev, int64(i), ts, leaf)
		if err != nil {
			t.Fatal(err)
		}
		e := verify.Entry{
			EntryID: id, EntryType: typ, FormatVersion: chainformat.FormatV4,
			Timestamp: ts.Format(verify.TimestampLayout), GlobalSeq: int64(i),
			ContentHash: contentHash, Salt: salt, LeafHash: leaf, ChainHash: h,
		}
		if erase && i == 1 {
			e.EntryID, e.EntryType, e.ContentHash, e.Salt, e.Erased = "", "", "", "", true
		}
		entries = append(entries, e)
		prev = h
	}
	path := filepath.Join(dir, name)
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestVerifyChain_V4ErasureIsReported: an erased v4 entry is counted, and the
// result says the erasure itself is not authenticated, as `proof verify` does.
// It once returned the same result as a chain with no erasure.
func TestVerifyChain_V4ErasureIsReported(t *testing.T) {
	dir := t.TempDir()
	cs := connectWith(t, serverConfig{root: testRoot(t, dir)})

	var live, erased verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": writeV4Chain(t, dir, "live.json", 3, false)}, &live)
	call(t, cs, "verify_chain", map[string]any{"path": writeV4Chain(t, dir, "erased.json", 3, true)}, &erased)

	if live.ErasedFound != 0 || strings.Contains(live.NotProven, "who erased") {
		t.Errorf("a chain with no erasure reports one: %+v", live)
	}
	if erased.Verdict != string(verify.VerdictIntact) {
		t.Fatalf("verdict = %q, want INTACT", erased.Verdict)
	}
	if erased.ErasedFound != 1 || erased.TombstonesFound != 0 {
		t.Errorf("erased_found = %d, tombstones_found = %d; want 1 and 0", erased.ErasedFound, erased.TombstonesFound)
	}
	for _, want := range []string{"who erased the 1 erased entries", "not authenticated", "withholds"} {
		if !strings.Contains(erased.NotProven, want) {
			t.Errorf("not_proven is missing %q: %q", want, erased.NotProven)
		}
	}
}
