// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package osfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenNoFollow_RefusesASymlink: a symlink is never followed.
func TestOpenNoFollow_RefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenNoFollow(link, os.O_RDONLY, 0); err == nil {
		f.Close()
		t.Fatal("opened a symlink")
	}
	f, err := OpenNoFollow(target, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// TestTryLock_ExclusiveExcludes: a second exclusive lock on the same file,
// through another open file, is refused without waiting; after Unlock it is
// taken.
func TestTryLock_ExclusiveExcludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	a, _ := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	b, _ := os.OpenFile(path, os.O_RDWR, 0)
	defer a.Close()
	defer b.Close()
	if ok, err := TryLock(a, true); !ok || err != nil {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	if ok, err := TryLock(b, false); ok || err != nil {
		t.Fatalf("a shared lock beside an exclusive one: %v %v", ok, err)
	}
	Unlock(a)
	if ok, err := TryLock(b, true); !ok || err != nil {
		t.Fatalf("after Unlock: %v %v", ok, err)
	}
	if _, _, ok := Identity(mustStat(t, path)); !ok {
		t.Error("no identity for a regular file")
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
