// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package noncestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// filledNonces is a nonce file with enough rows to have several pages.
func filledNonces(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.db.nonces")
	s, err := Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]byte{}
	for i := 0; i < 3000; i++ {
		rows[fmt.Sprintf("entry-%05d", i)] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	if err := s.PutBatch("chain", rows); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// damagedCopy copies the file under a new name (the check before a first write
// runs once per file) and overwrites its pages from fromPage on.
func damagedCopy(t *testing.T, path string, fromPage int) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := fromPage * os.Getpagesize()
	if len(raw) <= start {
		t.Fatalf("%s is %d bytes: no page %d", path, len(raw), fromPage)
	}
	copy(raw[start:], bytes.Repeat([]byte{0xA5}, len(raw)-start))
	out := filepath.Join(t.TempDir(), "evidence.db.nonces")
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCorrupt_NothingCrashesOrHangs: every function and method returns on a
// nonce file whose pages were overwritten, and reports ErrCorrupt. They once
// panicked inside bbolt.
func TestCorrupt_NothingCrashesOrHangs(t *testing.T) {
	healthy := filledNonces(t)
	calls := map[string]func(path string) error{
		"Open": func(path string) error {
			s, err := Open(path, time.Second)
			if err == nil {
				s.Close()
			}
			return err
		},
		"OpenReadOnly then Get": func(path string) error {
			s, err := OpenReadOnly(path, time.Second)
			if err != nil {
				return err
			}
			defer s.Close()
			_, err = s.Get("chain", "entry-02999")
			return err
		},
		"Forget":  func(path string) error { return Forget(path, "chain", "entry-00001", time.Second) },
		"Compact": func(path string) error { return Compact(path, time.Second) },
	}
	for name, call := range calls {
		for _, fromPage := range []int{2, 5} {
			t.Run(fmt.Sprintf("%s/from page %d", name, fromPage), func(t *testing.T) {
				path := damagedCopy(t, healthy, fromPage)
				done := make(chan error, 1)
				go func() { done <- call(path) }()
				select {
				case err := <-done:
					if !errors.Is(err, ErrCorrupt) {
						t.Fatalf("err = %v; want ErrCorrupt", err)
					}
				case <-time.After(30 * time.Second):
					t.Fatal("it did not return")
				}
				// No temporary copy of the nonce file is left beside it. The
				// lock file is not a copy: it is there for good (see lockFile).
				ents, _ := os.ReadDir(filepath.Dir(path))
				for _, e := range ents {
					if n := e.Name(); n != filepath.Base(path) && n != filepath.Base(path)+lockSuffix {
						t.Fatalf("%s was left beside the nonce file", n)
					}
				}
			})
		}
	}
}
