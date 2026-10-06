// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The paged scans resume exactly once: no row skipped, none repeated.

func sp(s string) *string { return &s }

func TestChainsAfterIn_TwoBucketsAndTruncation(t *testing.T) {
	st, _ := openTestSignatures(t)
	db := st.db
	a, b := []byte("a"), []byte("b")
	if err := db.Update(func(tx *bolt.Tx) error {
		ba, _ := tx.CreateBucket(a)
		bb, _ := tx.CreateBucket(b)
		for _, c := range []string{"c1", "c3", "c5"} {
			_ = ba.Put(rowKey(c, "x"), []byte{1})
		}
		for _, c := range []string{"c2", "c3", "c4"} {
			_ = bb.Put(rowKey(c, "x"), []byte{1})
		}
		_ = bb.Put([]byte("no-nul-1"), []byte{1}) // malformed: skipped, bounded
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var got []string
	var after *string
	for i := 0; i < 20; i++ {
		var page []string
		_ = db.View(func(tx *bolt.Tx) error {
			page = chainsAfterIn(tx, [][]byte{a, b}, after, 2)
			return nil
		})
		if len(page) == 0 {
			break
		}
		got = append(got, page...)
		after = sp(page[len(page)-1])
	}
	if want := []string{"c1", "c2", "c3", "c4", "c5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paged %v, want %v", got, want)
	}
}

func TestMalformedAfter_AcrossBuckets(t *testing.T) {
	st, _ := openTestSignatures(t)
	db := st.db
	a, b := []byte("a"), []byte("b")
	good := rowKey("events."+strings.Repeat("1", 32), "sink-"+strings.Repeat("2", 32))
	if err := db.Update(func(tx *bolt.Tx) error {
		ba, _ := tx.CreateBucket(a)
		bb, _ := tx.CreateBucket(b)
		_ = ba.Put([]byte("bad-1"), []byte{1})
		_ = ba.Put(good, []byte{1})
		_ = ba.Put([]byte("bad-2"), []byte{1})
		_ = bb.Put([]byte("bad-3"), []byte{1})
		_ = bb.Put(good, []byte{1})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	total := 0
	cur := keyCursor{}
	for i := 0; i < 20; i++ {
		var n int
		var done bool
		_ = db.View(func(tx *bolt.Tx) error {
			n, cur, done = malformedAfter(tx, [][]byte{a, b}, cur, 1)
			return nil
		})
		total += n
		if done {
			break
		}
	}
	if total != 3 {
		t.Fatalf("counted %d malformed keys across pages, want 3", total)
	}
}

func TestReverseAndForwardAfter(t *testing.T) {
	s, _, _ := setup(t)
	idx, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	ix, err := idx.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer ix.close()
	var keys []string
	after := ""
	for i := 0; i < 10; i++ {
		rows := ix.reverseAfter(after, 1)
		if len(rows) == 0 {
			break
		}
		keys = append(keys, rows[0].key)
		after = rows[0].key
	}
	if len(keys) != 3 {
		t.Fatalf("reverse rows paged: %v, want 3", keys)
	}
	examined := 0
	var cur []byte
	for i := 0; i < 10; i++ {
		bad, next, done := ix.badForwardAfter(cur, 1)
		if len(bad) != 0 {
			t.Fatalf("a consistent index reported bad rows: %v", bad)
		}
		if next != nil {
			examined++
			cur = next
		}
		if done {
			break
		}
	}
	if examined != 3 {
		t.Fatalf("forward rows examined %d, want 3", examined)
	}
}
