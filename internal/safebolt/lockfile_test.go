// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package safebolt

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLockFile_RefusesAFIFO: a FIFO planted at the lock file's name would
// block a read-only open on some systems; it is opened without blocking and
// refused as not a regular file.
func TestLockFile_RefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	if err := syscall.Mkfifo(path+LockSuffix, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	for _, exclusive := range []bool{true, false} {
		done := make(chan error, 1)
		go func() {
			f, err := LockFile(path, exclusive, time.Second)
			UnlockFile(f)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("exclusive=%v: locked a FIFO", exclusive)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("exclusive=%v: the open blocked on a FIFO", exclusive)
		}
	}
}

// TestLockFile_SharedNeedsNoWriteAccess: a reader takes its shared lock on a
// lock file it cannot write, as on read-only media; it creates the file only
// when there is none.
func TestLockFile_SharedNeedsNoWriteAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	path := filepath.Join(t.TempDir(), "x.db")
	f, err := LockFile(path, false, time.Second)
	if err != nil {
		t.Fatalf("shared lock with no lock file: %v", err)
	}
	UnlockFile(f)
	if err := os.Chmod(path+LockSuffix, 0o400); err != nil {
		t.Fatal(err)
	}
	f, err = LockFile(path, false, time.Second)
	if err != nil {
		t.Fatalf("shared lock on a read-only lock file: %v", err)
	}
	UnlockFile(f)
	if f, err := LockFile(path, true, time.Second); err == nil {
		UnlockFile(f)
		t.Error("an exclusive lock opened a lock file it cannot write")
	}
}
