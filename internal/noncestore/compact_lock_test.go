// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package noncestore

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

// TestCompact_AWriterInTheRenameWindowIsNotLost: a writer that tries to open
// the nonce file after the rewrite has copied it, but before the copy is
// renamed over the original, waits for the rename and writes into the new
// file. The rewrite once held only bbolt's own lock, on the original's inode,
// and released it before the rename: such a writer got the lock, wrote its
// nonce into the inode the rename then discarded, and the entry it belonged to
// could never be disclosed.
func TestCompact_AWriterInTheRenameWindowIsNotLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db.nonces")
	ns, err := Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.PutBatch("c", map[string][]byte{"before": bytes.Repeat([]byte{1}, 32)}); err != nil {
		t.Fatal(err)
	}
	ns.Close()

	written := make(chan error, 1)
	afterCopy = func() {
		// A writer arrives in the window. It must not get in until the
		// rename is done; give it every chance to.
		go func() {
			w, err := Open(path, 5*time.Second)
			if err != nil {
				written <- err
				return
			}
			defer w.Close()
			written <- w.PutBatch("c", map[string][]byte{"during": bytes.Repeat([]byte{2}, 32)})
		}()
		select {
		case err := <-written:
			t.Errorf("a writer opened the nonce file between the copy and the rename (err %v)", err)
			written <- err
		case <-time.After(300 * time.Millisecond):
		}
	}
	defer func() { afterCopy = nil }()

	if err := Compact(path, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatalf("the writer failed: %v", err)
	}
	afterCopy = nil

	ro, err := OpenReadOnly(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	for _, id := range []string{"before", "during"} {
		if _, err := ro.Get("c", id); err != nil {
			t.Errorf("nonce %q is not in the file after the rewrite: %v", id, err)
		}
	}
}
