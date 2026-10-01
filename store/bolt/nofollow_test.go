// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWithNoFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(link, WithNoFollow()); err == nil {
		s.Close()
		t.Fatal("opened a database through a symlink")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("the symlink's target was created")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(fifo, WithNoFollow(), WithReadOnly()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("a FIFO: %v; want it refused as not a regular file", err)
	}
	s, err := Open(filepath.Join(dir, "real.db"), WithNoFollow())
	if err != nil {
		t.Fatalf("a regular file: %v", err)
	}
	s.Close()
}
