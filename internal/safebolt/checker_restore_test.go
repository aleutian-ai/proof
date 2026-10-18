// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package safebolt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func goodFile(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("b"))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), []byte("v"))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func ino(t *testing.T, path string) uint64 {
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestChecker_RestoredOverAFreedInodeIsReadAgain: a damaged file fails and is
// remembered. The operator deletes it and restores a good copy at the same
// path, which on ext4 and tmpfs often gets the freed inode back. The good file
// must be read again, not refused as the damaged one.
func TestChecker_RestoredOverAFreedInodeIsReadAgain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	goodFile(t, path)
	// Damage: truncate to half a page inside the data.
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	var c Checker
	opts := &bolt.Options{Timeout: time.Second}
	err := c.Once(path, opts)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
	bad := ino(t, path)

	// Operator: remove the damaged file, restore from backup.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	goodFile(t, path)
	good := ino(t, path)
	t.Logf("damaged inode %d, restored inode %d", bad, good)
	if bad != good {
		t.Skip("the file system did not reuse the inode")
	}
	if err := c.Once(path, opts); err != nil {
		t.Errorf("the restored, well-formed file is refused: %v", err)
	}
}

// TestChecker_RepairedInPlaceIsReadAgain: `cp backup x.db` keeps the inode and
// changes the size and times; the file is read again. Left alone, a failed
// file stays refused without being read.
func TestChecker_RepairedInPlaceIsReadAgain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	goodFile(t, path)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	var c Checker
	opts := &bolt.Options{Timeout: time.Second}
	if err := c.Once(path, opts); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
	if err := c.Once(path, opts); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "already failed") {
		t.Fatalf("the unchanged damaged file was not refused from memory: %v", err)
	}
	before := ino(t, path)
	// cp backup x.db: truncates and rewrites the same inode.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if ino(t, path) != before {
		t.Fatal("inode changed")
	}
	if err := Check(path, opts); err != nil {
		t.Fatalf("the repaired file does not pass Check on its own: %v", err)
	}
	if err := c.Once(path, opts); err != nil {
		t.Errorf("repaired in place, refused: %v", err)
	}
}
