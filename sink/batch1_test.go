// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/internal/noncestore"
)

func problems(t *testing.T, s *Sink, ring anchor.KeySource, chain string) string {
	t.Helper()
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(chainReport(t, r, chain).Problems, "; ")
}

// ---- 1.4: nothing outside the folder, and no chain's files through another's

func TestSymlinkedContentDir_OutsideTheSink(t *testing.T) {
	s, _, ring := setup(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "precious.txt")
	if err := os.WriteFile(victim, []byte("not the sink's"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.dir, "content", "u-81")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Erase(context.Background(), "u-81"); err == nil {
		t.Fatal("Erase went ahead through a symlinked content folder")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("Erase deleted a file outside the sink: %v", err)
	}
	if n := len(entryIDs(t, s, "u-81")); n != 3 {
		t.Fatalf("a refused Erase still appended an erasure entry (%d entries)", n)
	}
	if p := problems(t, s, ring, "u-81"); !strings.Contains(p, "not a real directory") {
		t.Fatalf("Verify did not report the symlinked folder: %q", p)
	}
	if _, err := s.Commit(context.Background(), events("u-81", 1)); err == nil {
		t.Fatal("Commit wrote content through a symlinked folder")
	}
}

func TestSymlinkedContentDir_InsideTheSink(t *testing.T) {
	s, _, _ := setup(t)
	before, _ := os.ReadDir(filepath.Join(s.dir, "content", "u-82"))
	dir := filepath.Join(s.dir, "content", "u-81")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(s.dir, "content", "u-82"), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Erase(context.Background(), "u-81"); err == nil {
		t.Fatal("erasing u-81 went ahead through a link to u-82's folder")
	}
	after, _ := os.ReadDir(filepath.Join(s.dir, "content", "u-82"))
	if len(after) != len(before) {
		t.Fatal("erasing u-81 deleted u-82's content")
	}
}

func TestSymlinkedBoltFileIsRefused(t *testing.T) {
	s, _, _ := setup(t)
	target := filepath.Join(t.TempDir(), "elsewhere.db")
	np := noncestore.PathFor(s.DBPath())
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

// ---- 1.5 / 1.6: bounded, typed reads; a well-formed checkpoint series

func TestAnchors_StrayFileAndGap(t *testing.T) {
	for name, tamper := range map[string]func(dir string) error{
		"stray file": func(dir string) error { return os.WriteFile(filepath.Join(dir, "notes.json"), []byte("{}"), 0o644) },
		"gap": func(dir string) error {
			return os.Rename(filepath.Join(dir, "0001.json"), filepath.Join(dir, "0002.json"))
		},
		"oversized": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "0001.json"), make([]byte, maxAnchorBytes+1), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, signer, ring := setup(t)
			if err := tamper(s.anchorDir("u-81")); err != nil {
				t.Fatal(err)
			}
			if p := problems(t, s, ring, "u-81"); p == "" {
				t.Fatal("Verify accepted the malformed series")
			}
			if _, err := s.Commit(context.Background(), events("u-81", 1)); err != nil {
				t.Fatal(err)
			}
			done, err := s.Checkpoint(context.Background(), signer, nil)
			if err != nil {
				t.Fatal(err)
			}
			if problemFor(done, "u-81") == "" {
				t.Fatalf("Checkpoint added to a malformed series: %+v", done)
			}
		})
	}
}

// A FIFO in place of a file would hang a plain open; /dev/zero would never end.
func TestFIFOsDoNotHang(t *testing.T) {
	s, _, ring := setup(t)
	content := s.contentPath("u-82", entryIDs(t, s, "u-82")[0])
	anchorFile := filepath.Join(s.anchorDir("u-90"), "0001.json")
	for _, p := range []string{content, anchorFile} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
	}
	done := make(chan string, 1)
	go func() { done <- problems(t, s, ring, "u-82") + " | " + problems(t, s, ring, "u-90") }()
	select {
	case p := <-done:
		if strings.Count(p, "not a regular file") != 2 {
			t.Fatalf("FIFOs not reported as such: %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Verify hung on a FIFO")
	}
}

// ---- 1.7: a verifier changes nothing and creates nothing

func TestVerify_IsReadOnly(t *testing.T) {
	s, _, ring := setup(t)
	files := []string{s.DBPath(), noncestore.PathFor(s.DBPath())}
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
	if _, err := s.Erase(context.Background(), "u-1"); err == nil {
		t.Fatal("Erase of a folder that does not exist succeeded")
	}
	if _, err := os.Stat(typo); !os.IsNotExist(err) {
		t.Fatal("a read verb created the folder")
	}

	// A sink with no nonce file: Verify reports events as unopenable and does
	// not create the nonce file.
	s2, _, ring2 := setup(t)
	np := noncestore.PathFor(s2.DBPath())
	if err := os.Remove(np); err != nil {
		t.Fatal(err)
	}
	if p := problems(t, s2, ring2, "u-82"); !strings.Contains(p, "nonce is gone") {
		t.Fatalf("missing nonce file not reported: %q", p)
	}
	if _, err := os.Stat(np); !os.IsNotExist(err) {
		t.Fatal("Verify created a nonce file")
	}
}

// ---- 1.8: a series must grow, and each checkpoint names its predecessor

func TestCheckpointSeriesMustGrowAndLink(t *testing.T) {
	// Each case breaks exactly one rule; the other checks all pass.
	cases := map[string]struct {
		grow   bool // commit a new entry first, so the successor covers more
		mutate func(next *anchor.Anchor)
	}{
		"does not grow": {grow: false, mutate: func(*anchor.Anchor) {}},
		"wrong predecessor id": {grow: true, mutate: func(next *anchor.Anchor) {
			next.PreviousAnchorID = "anchor_11111111-1111-1111-1111-111111111111"
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, signer, ring := setup(t)
			if c.grow {
				if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
					t.Fatal(err)
				}
			}
			f, err := s.openFolder(false)
			if err != nil {
				t.Fatal(err)
			}
			series, _, err := f.readAnchors("u-81")
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			st, err := s.openStore(true)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := readChain(ctx, st, "u-81")
			st.Close()
			if err != nil {
				t.Fatal(err)
			}
			prev := series[0]
			// A valid, signed successor over the SAME entries: the chain and
			// signature checks pass; only the series rules can object.
			next, err := build.Anchor(ctx, build.Input{Subject: "u-81", Entries: entries, Previous: &prev})
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(&next)
			signed, err := anchor.SignAnchor(ctx, signer, next)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.MarshalIndent(signed, "", "  ")
			if err := os.WriteFile(filepath.Join(s.anchorDir("u-81"), "0002.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if p := problems(t, s, ring, "u-81"); !strings.Contains(p, "checkpoint 0002") {
				t.Fatalf("Verify accepted it: %q", p)
			}
		})
	}
}

// TestReadSmall_SwapAfterCheck: the file passes the Lstat check, then is
// swapped for a FIFO before the open. The check on the open handle catches it.
func TestReadSmall_SwapAfterCheck(t *testing.T) {
	s, _, ring := setup(t)
	target := contentName("u-82", entryIDs(t, s, "u-82")[0])
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
	go func() { done <- problems(t, s, ring, "u-82") }()
	select {
	case p := <-done:
		if !strings.Contains(p, "not a regular file") {
			t.Fatalf("the swapped-in FIFO was not caught: %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hung on a FIFO swapped in after the check")
	}
}

// TestErase_PreflightRefusesBeforeRecording: an entry in the content folder
// that cannot be removed (a subdirectory) is refused BEFORE the erasure entry
// is appended, so retries do not pile up erasure entries.
func TestErase_PreflightRefusesBeforeRecording(t *testing.T) {
	s, _, _ := setup(t)
	if err := os.Mkdir(filepath.Join(s.dir, "content", "u-81", "stuck"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Erase(context.Background(), "u-81"); err == nil ||
			!strings.Contains(err.Error(), "Nothing was erased") {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if n := len(entryIDs(t, s, "u-81")); n != 3 {
		t.Fatalf("refused erasures appended entries: %d, want 3", n)
	}
}
