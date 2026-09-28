// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// TestChains lists every chain exactly once, including chains whose ids are
// prefixes of one another — the case a seek-based walk gets wrong first.
func TestChains(t *testing.T) {
	ctx := context.Background()
	s, err := boltstore.Open(filepath.Join(t.TempDir(), "chain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := s.Chains(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty file: got %v, %v; want no chains", got, err)
	}

	// "a" has several entries; "a.b", "a-" and "ab" all start with "a".
	counts := map[string]int{"a": 3, "a.b": 1, "a-": 2, "ab": 1, "z": 1}
	for chain, n := range counts {
		batch := make([]store.Entry, n)
		for i := range batch {
			batch[i] = store.Entry{
				ChainID: chain, EntryID: "e", GlobalSeq: int64(i + 1),
				Timestamp: time.Unix(0, 0).UTC(), ContentHash: "h", ChainHash: "c",
			}
		}
		if err := s.WriteBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}

	got, err = s.Chains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "a-", "a.b", "ab", "z"} // byte order
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Chains() = %v, want %v", got, want)
	}
}

func TestChains_HonoursContext(t *testing.T) {
	s, err := boltstore.Open(filepath.Join(t.TempDir(), "chain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Chains(ctx); err == nil {
		t.Fatal("a cancelled context must stop Chains")
	}
}
