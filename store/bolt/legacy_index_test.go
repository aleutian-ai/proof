// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestOpen_RemovesTheLegacyIDIndex: files written by v0.3.0 and earlier carry a
// file-wide "by_id" bucket. It collided across chains and nothing used it; Open
// deletes it. It is derived data, so nothing is lost.
func TestOpen_RemovesTheLegacyIDIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("by_id"))
		if err != nil {
			return err
		}
		return b.Put([]byte("e-a"), []byte("a\x00seq"))
	}); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("a file with the legacy index must still open: %v", err)
	}
	var present bool
	s.db.View(func(tx *bolt.Tx) error { present = tx.Bucket([]byte("by_id")) != nil; return nil })
	s.Close()
	if present {
		t.Fatal("the legacy by_id bucket is still in the file")
	}

	// Opening again (no legacy bucket now) must also succeed.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopening after removal: %v", err)
	}
	s2.Close()
}
