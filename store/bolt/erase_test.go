// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/internal/safebolt"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/store/bolt"
)

// TestErase_V4EntryStaysVerifiableAndItsFieldsLeaveTheFile: an erased v4
// entry keeps the chain intact, every link recomputed; after CompactFile the
// erased id, content hash and salt are nowhere in the database file.
func TestErase_V4EntryStaysVerifiableAndItsFieldsLeaveTheFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "chain.db")
	st, err := bolt.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := linker.New(st)
	ts := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var in []linker.Input
	for i, id := range []string{"keep-0", "erase-me-1", "keep-2"} {
		at := ts.Add(time.Duration(i) * time.Second)
		in = append(in, linker.Input{EntryID: id, EntryType: "event", Timestamp: at, IngestedAt: at,
			ContentHash: strings.Repeat(string(rune('a'+i)), 128)})
	}
	if _, err := l.Append(ctx, "c", in); err != nil {
		t.Fatal(err)
	}
	was, err := st.Erase(ctx, "c", 1)
	if err != nil {
		t.Fatal(err)
	}
	if was.EntryID != "erase-me-1" || was.Salt == "" {
		t.Fatalf("Erase returned %+v, want the entry as it was", was)
	}
	again, err := st.Erase(ctx, "c", 1)
	if err != nil || again.EntryID != "" || !again.Erased {
		t.Fatalf("a second erase: %+v, %v; want the erased entry, unchanged", again, err)
	}
	if _, err := st.Erase(ctx, "c", 9); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("erase of a missing entry: %v", err)
	}
	rows, err := st.Range(ctx, "c", 0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	// What a verifier recomputes the link from is kept; what erasure removes is
	// gone. (cmd/proof's erase test verifies the chain; verify is not a
	// dependency this package's tests may take.)
	e := rows[1]
	if !e.Erased || e.EntryID != "" || e.EntryType != "" || e.ContentHash != "" || e.Salt != "" ||
		e.LeafHash != was.LeafHash || e.ChainHash != was.ChainHash || e.GlobalSeq != 1 || !e.Timestamp.Equal(was.Timestamp) {
		t.Fatalf("erased entry %+v", e)
	}
	if rows[0].Erased || rows[2].Erased {
		t.Fatal("erasure touched another entry")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bolt.CompactFile(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"erase-me-1", was.Salt, was.ContentHash} {
		if bytes.Contains(raw, []byte(gone)) {
			t.Errorf("the compacted file still holds %.20s…", gone)
		}
	}
	if !bytes.Contains(raw, []byte("keep-2")) {
		t.Error("the compacted file lost an entry it should keep")
	}
}

// TestErase_RefusesAV3Entry: v2 and v3 are frozen, and their erasure is a
// tombstone, which this store does not write.
func TestErase_RefusesAV3Entry(t *testing.T) {
	ctx := context.Background()
	st, err := bolt.Open(filepath.Join(t.TempDir(), "chain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, _ := linker.New(st, linker.WithFormatV3())
	ts := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if _, err := l.Append(ctx, "c", []linker.Input{{EntryID: "e", EntryType: "event", Timestamp: ts,
		IngestedAt: ts, ContentHash: strings.Repeat("a", 128)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Erase(ctx, "c", 0); !errors.Is(err, bolt.ErrNotV4) {
		t.Fatalf("erase of a v3 entry: %v, want ErrNotV4", err)
	}
}

// TestCompactFile_ExcludesWritersAcrossTheRename: CompactFile renames a fresh
// copy over the database, so a writer must not hold the old file meanwhile, or
// what it writes is lost with it. The lock file is what keeps them apart, both
// ways; a reader is not kept out, and needs no lock file.
func TestCompactFile_ExcludesWritersAcrossTheRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.db")
	st, err := bolt.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bolt.CompactFile(path, bolt.WithLockTimeout(50*time.Millisecond)); !errors.Is(err, bolt.ErrLocked) {
		t.Fatalf("compaction while a writer is open: %v, want ErrLocked", err)
	}
	st.Close()

	// Compaction's hold on the lock file, as it is held from before the copy
	// until after the rename.
	lock, err := safebolt.LockFile(path, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bolt.Open(path, bolt.WithLockTimeout(50*time.Millisecond)); !errors.Is(err, bolt.ErrLocked) {
		t.Fatalf("a writer opened while compaction held the lock: %v", err)
	}
	r, err := bolt.Open(path, bolt.WithReadOnly())
	if err != nil {
		t.Fatalf("a reader was kept out: %v", err)
	}
	r.Close()
	safebolt.UnlockFile(lock)
	if err := bolt.CompactFile(path); err != nil {
		t.Fatal(err)
	}
}
