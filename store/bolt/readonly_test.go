// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	bbolt "go.etcd.io/bbolt"
)

// TestReadOnly_ChangesNothing: a verifier must not modify the evidence it
// checks. Opening read-only leaves the file byte-identical, allows concurrent
// readers, and refuses writes.
func TestReadOnly_ChangesNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "chain.db")
	w, err := boltstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := store.Entry{ChainID: "c", EntryID: "e", GlobalSeq: 0, Timestamp: time.Unix(0, 0).UTC(),
		ContentHash: "h", ChainHash: "x"}
	if err := w.WriteBatch(ctx, []store.Entry{e}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	before, _ := os.ReadFile(path)

	r1, err := boltstore.Open(path, boltstore.WithReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := boltstore.Open(path, boltstore.WithReadOnly(), boltstore.WithLockTimeout(time.Second))
	if err != nil {
		t.Fatalf("a second reader must be able to open alongside the first: %v", err)
	}
	if rows, err := r1.Range(ctx, "c", 0, 10, 0); err != nil || len(rows) != 1 {
		t.Fatalf("read-only Range: %v, %v", rows, err)
	}
	if err := r1.WriteBatch(ctx, []store.Entry{e}); err == nil {
		t.Fatal("a read-only store accepted a write")
	}
	r1.Close()
	r2.Close()
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("opening read-only changed the file")
	}
}

func TestReadOnly_Refusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := boltstore.Open(filepath.Join(dir, "absent.db"), boltstore.WithReadOnly()); err == nil {
		t.Fatal("read-only open created or accepted a missing file")
	}
	if _, err := os.Stat(filepath.Join(dir, "absent.db")); !os.IsNotExist(err) {
		t.Fatal("read-only open created a file")
	}
	// A bbolt file that is not a chain database: refused, not read.
	foreign := filepath.Join(dir, "foreign.db")
	db, err := bbolt.Open(foreign, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := boltstore.Open(foreign, boltstore.WithReadOnly()); err == nil {
		t.Fatal("a file without chain buckets was accepted")
	}
}
