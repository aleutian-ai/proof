// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package exportbundle

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO named as a key or bundle file is refused, and at once: opening it
// must not wait for a writer that never comes.
func TestReadRegular_RefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 2)
	go func() {
		_, err := ReadPublicKeyFile(fifo)
		done <- err
		_, err = ReadBundleFile(fifo, 100)
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Fatalf("a FIFO: %v", err)
			}
		case <-time.After(5 * time.Second):
			// Release the reader, so the test can end.
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatal("reading a FIFO blocked")
		}
	}
}
