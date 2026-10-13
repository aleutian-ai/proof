// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFileRootRead_NamedPipeDoesNotHang: the file is opened before it is
// checked, and opening a named pipe for reading waits for a writer unless the
// open is non-blocking. One tool call must not park a handler for good.
func TestFileRootRead_NamedPipeDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("cannot create a named pipe here: %v", err)
	}
	root := testRoot(t, dir)

	done := make(chan error, 1)
	go func() {
		_, err := root.read(pipe, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) || !strings.Contains(err.Error(), "named pipe") {
			t.Errorf("a named pipe must be reported as one: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a named pipe did not return")
	}
}
