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
)

// swapToSymlinkAfterCheck makes the next regularOrAbsent(path) end by
// replacing path with a symlink to a place outside the sink: a COPY of the file
// (a valid bbolt database, so bbolt would happily use it), or, when there is no
// file yet, a path that does not exist (bbolt would create it). That is the
// swap an attacker with write access would race in between the check and the
// open. It returns the outside path and its bytes (nil: must not come to exist).
func swapToSymlinkAfterCheck(t *testing.T, path string) (string, []byte) {
	t.Helper()
	outside := filepath.Join(t.TempDir(), "outside")
	orig, err := os.ReadFile(path)
	if err == nil {
		if err := os.WriteFile(outside, orig, 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		orig = nil
	}
	afterRegularCheck = func(p string) {
		if p != path {
			return
		}
		_ = os.Remove(p)
		if err := os.Symlink(outside, p); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterRegularCheck = nil })
	return outside, orig
}

// untouched fails the test if the outside file changed (or came to exist).
func untouched(t *testing.T, outside string, orig []byte) {
	t.Helper()
	got, err := os.ReadFile(outside)
	if orig == nil {
		if err == nil {
			t.Fatal("a file was created behind the symlink")
		}
		return
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("the file behind the symlink was changed")
	}
}

// TestBoltOpens_SymlinkSwappedInAfterTheCheck: every bbolt file of the sink is
// opened without following a symlink, checked on the handle, so a swap after
// regularOrAbsent is refused and nothing is written where the link points.
func TestBoltOpens_SymlinkSwappedInAfterTheCheck(t *testing.T) {
	ctx := context.Background()
	for _, suffix := range []string{"", ".secrets", ".sources", ".subjects"} {
		t.Run("commit"+suffix, func(t *testing.T) {
			s, _, _ := setup(t)
			outside, orig := swapToSymlinkAfterCheck(t, s.DBPath()+suffix)
			recs := events("u-9", 1)
			recs[0].Source = "S@1:1" // so the sources file is opened too
			if _, err := s.Commit(ctx, recs); err == nil {
				t.Fatal("committed through a symlink swapped in after the check")
			}
			untouched(t, outside, orig)
		})
	}
	t.Run("verify.evidence", func(t *testing.T) {
		s, _, ring := setup(t)
		swapToSymlinkAfterCheck(t, s.DBPath())
		if _, err := s.Verify(ctx, ring); err == nil {
			t.Fatal("read an evidence file through a symlink swapped in after the check")
		}
	})
	t.Run("verify.secrets", func(t *testing.T) {
		s, _, ring := setup(t)
		swapToSymlinkAfterCheck(t, s.secretsPath())
		if _, err := s.Verify(ctx, ring); err == nil {
			t.Fatal("read a secrets file through a symlink swapped in after the check")
		}
	})
	t.Run("signatures", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evidence.db.signatures")
		outside, orig := swapToSymlinkAfterCheck(t, path)
		if _, err := openSignatures(path, DefaultLockTimeout); err == nil {
			t.Fatal("opened a signatures file through a symlink swapped in after the check")
		}
		untouched(t, outside, orig)
	})
}

func TestOpenRegularNoFollow(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": fifo, "symlink": link, "folder": dir} {
		for _, flag := range []int{os.O_RDONLY, os.O_RDWR | os.O_CREATE} {
			f, err := openRegularNoFollow(path, flag, 0o600)
			if err == nil {
				f.Close()
				t.Fatalf("%s (flag %#x) was opened", name, flag)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "target")); err == nil {
		t.Fatal("opening the symlink created its target")
	}
	f, err := openRegularNoFollow(filepath.Join(dir, "new.db"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("a new regular file: %v", err)
	}
	f.Close()
	if _, err := openRegularNoFollow(link, os.O_RDONLY, 0); err == nil || !strings.Contains(err.Error(), "never followed") {
		t.Fatalf("err = %v; want the symlink named", err)
	}
}
