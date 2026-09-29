// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/internal/noncestore"
	bolt "go.etcd.io/bbolt"
)

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)

	// One chain per key, each checkpointed and verified on its own.
	r := mustVerify(t, s, ring)
	if len(r.Chains) != 3 {
		t.Fatalf("want 3 chains, got %+v", r.Chains)
	}
	for chain, n := range map[string]int{"u-81": 3, "u-82": 2, "u-90": 1} {
		c := chainReport(t, r, cid(t, s, chain))
		if c.Entries != n || c.Opened != n || c.Checkpoints != 1 || c.Unanchored != 0 {
			t.Errorf("%s: %+v, want %d entries all opened, 1 checkpoint", chain, c, n)
		}
	}

	// Nothing new: no checkpoint written.
	if cp, err := s.Checkpoint(ctx, signer, nil); err != nil || len(cp) != 0 {
		t.Fatalf("second checkpoint with nothing new: %v, %v", cp, err)
	}

	// New entries on one chain: only that chain gets a checkpoint, linked to its first.
	if _, err := s.Commit(ctx, events("u-82", 2)); err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, mustVerify(t, s, ring), cid(t, s, "u-82")); c.Unanchored != 2 {
		t.Fatalf("u-82 before its checkpoint: %+v, want 2 unanchored", c)
	}
	cp, err := s.Checkpoint(ctx, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp) != 1 || cp[0].Chain != cid(t, s, "u-82") || cp[0].Entries != 4 ||
		cp[0].File != filepath.Join("anchors", cid(t, s, "u-82"), "0002.json") {
		t.Fatalf("checkpoint = %+v, want only u-82's 0002 over 4 entries", cp)
	}
	mustVerify(t, s, ring)
}

// TestCommit_ValidatesBeforeWriting: one bad record refuses the whole call, and
// no file is created.
func TestCommit_ValidatesBeforeWriting(t *testing.T) {
	good := Record{Class: testClass, Subject: "u-1", Content: []byte("{}")}
	cases := map[string][]Record{
		"no records":      nil,
		"over the cap":    make([]Record, MaxBatch+1),
		"invalid key":     {good, {Class: testClass, Subject: "jo@example.com", Content: []byte("{}")}},
		"empty content":   {good, {Class: testClass, Subject: "u-2"}},
		"content too big": {good, {Class: testClass, Subject: "u-2", Content: make([]byte, MaxContentBytes+1)}},
	}
	for name, recs := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Commit(context.Background(), recs); err == nil {
				t.Fatal("Commit accepted it")
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatalf("a refused call left files behind: %v", left)
			}
		})
	}
}

func TestCommit_AtTheCap(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-1", MaxBatch)); err != nil {
		t.Fatalf("exactly MaxBatch records must be accepted: %v", err)
	}
}

// TestCommit_CancelledContextWritesNothing: a context cancelled before Commit
// runs stops it before any file is written. (Cleanup after a failure PART-WAY,
// once content and nonces exist, is cleanup_test.go's.)
func TestCommit_CancelledContextWritesNothing(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Commit(ctx, events("u-1", 3)); err == nil {
		t.Fatal("a cancelled context must fail the append")
	}
	// The context was cancelled before any chain was bound, so nothing exists:
	// no content folder at all, no chain in the evidence file.
	if left, err := os.ReadDir(filepath.Join(s.dir, "content")); err == nil && len(left) != 0 {
		t.Fatalf("content left behind by a cancelled commit: %v", left)
	}
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := st.Chains(context.Background())
	st.Close()
	if err != nil || len(chains) != 0 {
		t.Fatalf("chains written by a cancelled commit: %v, %v", chains, err)
	}
	// Nonce file: the only keys were for this batch, so nothing for u-1 can remain.
	raw, err := bolt.Open(noncestore.PathFor(s.DBPath()), 0o600, &bolt.Options{Timeout: DefaultLockTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	n := 0
	_ = raw.View(func(tx *bolt.Tx) error { n = tx.Bucket([]byte("nonces")).Stats().KeyN; return nil })
	if n != 0 {
		t.Fatalf("%d nonces left behind by a failed append", n)
	}
}

// TestConcurrentCommits: the Sink serialises its own callers, so parallel
// commits all land instead of failing on the file lock.
//
// The file lock is shortened to a microsecond, so a caller that reached the
// file without queueing on the Sink would fail rather than wait it out.
func TestConcurrentCommits(t *testing.T) {
	s, err := Open(t.TempDir(), WithLockTimeout(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	_, ring := newSigner(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Commit(context.Background(), events(fmt.Sprintf("u-%d", i%3), 5))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for _, c := range mustVerify(t, s, ring).Chains {
		total += c.Opened
	}
	if total != 40 {
		t.Fatalf("opened %d events, want 40", total)
	}
}
