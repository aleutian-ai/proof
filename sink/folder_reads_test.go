// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
)

// How the sink reads its folder: nothing through a symlink, no hang on a FIFO,
// and a verb that only reads changes nothing and creates nothing.

func problems(t *testing.T, s *Sink, ring anchor.KeySource, chain string) string {
	t.Helper()
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(chainReport(t, r, chain).Problems, "; ")
}

// Nothing outside the folder is opened: a secrets file that is a symlink is
// refused.
func TestSymlinkedBoltFileIsRefused(t *testing.T) {
	s, _, _ := setup(t)
	target := filepath.Join(t.TempDir(), "elsewhere.db")
	np := s.secretsPath()
	if err := os.Rename(np, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, np); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-81", 1)); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Commit opened a symlinked nonce file: %v", err)
	}
}

// A FIFO in place of a file would hang a plain open; /dev/zero would never end.
func TestFIFOsDoNotHang(t *testing.T) {
	s, _, ring := setup(t)
	// (Content is not a file; checkpoints are.)
	anchorFile := filepath.Join(s.anchorDir(cid(t, s, "u-90")), "0001.json")
	for _, p := range []string{anchorFile} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
	}
	done := make(chan string, 1)
	go func() {
		done <- problems(t, s, ring, cid(t, s, "u-90"))
	}()
	select {
	case p := <-done:
		if strings.Count(p, "not a regular file") != 1 {
			t.Fatalf("FIFOs not reported as such: %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Verify hung on a FIFO")
	}
}

// A verifier changes nothing.
func TestVerify_IsReadOnly(t *testing.T) {
	s, _, ring := setup(t)
	files := []string{s.DBPath(), s.secretsPath()}
	var before [][]byte
	for _, f := range files {
		b, _ := os.ReadFile(f)
		before = append(before, b)
	}
	if _, err := s.Verify(context.Background(), ring); err != nil {
		t.Fatal(err)
	}
	for i, f := range files {
		if b, _ := os.ReadFile(f); !bytes.Equal(b, before[i]) {
			t.Fatalf("Verify modified %s", filepath.Base(f))
		}
	}
}

// A verb on a folder that does not exist fails without creating it, and Verify
// does not create a missing secrets file.
func TestReadVerbsCreateNothing(t *testing.T) {
	typo := filepath.Join(t.TempDir(), "sink-dta")
	s, err := Open(typo)
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	if _, err := s.Verify(context.Background(), ring); err == nil {
		t.Fatal("Verify of a folder that does not exist succeeded")
	}
	if _, err := s.Checkpoint(context.Background(), signer, nil); err == nil {
		t.Fatal("Checkpoint of a folder that does not exist succeeded")
	}
	if _, err := s.EraseSubject(context.Background(), "u-1"); err == nil {
		t.Fatal("Erase of a folder that does not exist succeeded")
	}
	if _, err := os.Stat(typo); !os.IsNotExist(err) {
		t.Fatal("a read verb created the folder")
	}

	// A sink with no secrets file: Verify reports its events' content as gone
	// (MISSING) and does not create the file.
	s2, _, ring2 := setup(t)
	np := s2.secretsPath()
	if err := os.Remove(np); err != nil {
		t.Fatal(err)
	}
	if p := problems(t, s2, ring2, cid(t, s2, "u-82")); !strings.Contains(p, "MISSING") {
		t.Fatalf("missing secrets file not reported: %q", p)
	}
	if _, err := os.Stat(np); !os.IsNotExist(err) {
		t.Fatal("Verify created a nonce file")
	}
}

// TestReadSmall_SwapAfterCheck: the file passes the Lstat check, then is
// swapped for a FIFO before the open. The check on the open handle catches it.
func TestReadSmall_SwapAfterCheck(t *testing.T) {
	s, _, ring := setup(t)
	target := filepath.Join("anchors", cid(t, s, "u-82"), "0001.json") // checkpoints are still files
	afterLstat = func(name string) {
		if name != target {
			return
		}
		p := filepath.Join(s.dir, name)
		_ = os.Remove(p)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Errorf("mkfifo: %v", err)
		}
	}
	defer func() { afterLstat = nil }()
	done := make(chan string, 1)
	go func() { done <- problems(t, s, ring, cid(t, s, "u-82")) }()
	select {
	case p := <-done:
		if !strings.Contains(p, "not a regular file") {
			t.Fatalf("the swapped-in FIFO was not caught: %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hung on a FIFO swapped in after the check")
	}
}
