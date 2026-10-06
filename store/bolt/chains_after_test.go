// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/store"
)

func TestChainsAfter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	names := []string{"a", "b", "b2", "c", "d"}
	for _, n := range names {
		if err := s.WriteBatch(ctx, []store.Entry{{ChainID: n, EntryID: n + "-0", EntryType: "x",
			GlobalSeq: 0, ContentHash: "00"}, {ChainID: n, EntryID: n + "-1", EntryType: "x", GlobalSeq: 1,
			ContentHash: "00"}}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	var after *string
	for {
		page, err := s.ChainsAfter(ctx, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 2 {
			t.Fatalf("page of %d, limit 2", len(page))
		}
		got = append(got, page...)
		last := page[len(page)-1]
		after = &last
	}
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("paged %v, want %v", got, names)
	}
	all, _ := s.Chains(ctx)
	if !reflect.DeepEqual(all, names) {
		t.Fatalf("Chains %v", all)
	}
	if p, _ := s.ChainsAfter(ctx, ptr("d"), 10); len(p) != 0 {
		t.Fatalf("after the last chain: %v", p)
	}
	// "b" must not be skipped into "b2" (a prefix of a longer id).
	if p, _ := s.ChainsAfter(ctx, ptr("a"), 1); !reflect.DeepEqual(p, []string{"b"}) {
		t.Fatalf("after a: %v", p)
	}
	if p, _ := s.ChainsAfter(ctx, ptr("b"), 1); !reflect.DeepEqual(p, []string{"b2"}) {
		t.Fatalf("after b: %v", p)
	}
}

func ptr(s string) *string { return &s }

// A chain id of "" (a crafted file: a key starting with NUL) is a chain like
// any other: listed once, and the walk moves past it.
func TestChainsAfter_EmptyChainID(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.WriteBatch(ctx, []store.Entry{{ChainID: "a", EntryID: "a-0", EntryType: "x",
		GlobalSeq: 0, ContentHash: "00"}}); err != nil {
		t.Fatal(err)
	}
	// The store refuses an empty chain id; a crafted file is not the store.
	raw, _ := json.Marshal(store.Entry{EntryID: "x-0", EntryType: "x", ContentHash: "00"})
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketEntries).Put(entryKey("", 0), raw)
	}); err != nil {
		t.Fatal(err)
	}
	var got []string
	var after *string
	for i := 0; i < 5; i++ {
		page, err := s.ChainsAfter(ctx, after, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		got = append(got, page...)
		last := page[0]
		after = &last
	}
	if !reflect.DeepEqual(got, []string{"", "a"}) {
		t.Fatalf("paged %q, want [\"\" \"a\"]", got)
	}
}
