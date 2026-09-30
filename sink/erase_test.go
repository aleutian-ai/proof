// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/internal/noncestore"
)

// TestErase is the ticket's erasure criterion: the erased chain still verifies,
// its events cannot be opened, and the other chains are unaffected.
func TestErase(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	before := entryIDs(t, s, cid(t, s, "u-81"))

	res, err := eraseOne(t, s, "u-81")
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 3 || res.ErasureEntryID == "" {
		t.Fatalf("Erase = %+v", res)
	}

	// Erased items cannot be opened: no nonce and no content, for any of them.
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range before {
		if _, err := ns.Get(cid(t, s, "u-81"), id); !errors.Is(err, noncestore.ErrNotFound) {
			t.Errorf("nonce for erased %s still stored: %v", id, err)
		}
		if _, err := os.Stat(s.contentPath(cid(t, s, "u-81"), id)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("content for erased %s still on disk: %v", id, err)
		}
	}
	ns.Close()

	// Every chain still verifies, the erased one included, and its old
	// checkpoint still binds.
	r := mustVerify(t, s, ring)
	if c := chainReport(t, r, cid(t, s, "u-81")); c.Erased != 3 || c.Opened != 0 || c.Checkpoints != 1 || c.Unanchored != 1 {
		t.Fatalf("u-81 after erase: %+v, want 3 erased, 1 checkpoint, the erasure entry unanchored", c)
	}
	for chain, n := range map[string]int{"u-82": 2, "u-90": 1} {
		if c := chainReport(t, r, cid(t, s, chain)); c.Opened != n || c.Erased != 0 {
			t.Errorf("%s was affected by erasing u-81: %+v", chain, c)
		}
	}

	// The erasure is checkpointed like any other entry. The user can come back,
	// but the sink has forgotten them: the new event starts a NEW chain, and
	// never rejoins the erased history.
	old := cid(t, s, "u-81")
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	fresh := cidIn(t, s, testClass, "u-81")
	if fresh == old {
		t.Fatal("a returning subject was committed to its erased chain")
	}
	if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
		t.Fatal(err)
	}
	r = mustVerify(t, s, ring)
	if c := chainReport(t, r, old); c.Erased != 3 || c.Opened != 0 || c.Checkpoints != 2 || c.Unanchored != 0 {
		t.Fatalf("the erased chain after the user returned: %+v", c)
	}
	if c := chainReport(t, r, fresh); c.Entries != 1 || c.Opened != 1 {
		t.Fatalf("the returning user's new chain: %+v", c)
	}

	// Erasing again erases only the new chain.
	res2, err := s.EraseSubject(ctx, "u-81")
	if err != nil || len(res2.Erased) != 1 || res2.Erased[0].Chain != fresh || res2.Erased[0].Events != 1 {
		t.Fatalf("second erase = %+v, %v", res2, err)
	}
	if c := chainReport(t, mustVerify(t, s, ring), fresh); c.Erased != 1 || c.Opened != 0 {
		t.Fatalf("the new chain after a second erase: %+v", c)
	}
}

func TestErase_Refusals(t *testing.T) {
	s, _, _ := setup(t)
	if _, err := s.EraseSubject(context.Background(), "jo@example.com"); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("an invalid subject: %v", err)
	}
	if _, err := s.EraseSubjectClass(context.Background(), "u-81", "Pay.ments"); !errors.Is(err, ErrInvalidClass) {
		t.Fatalf("an invalid class: %v", err)
	}
	// A subject the sink holds nothing for: no error, nothing erased, no entry.
	res, err := s.EraseSubject(context.Background(), "u-unknown")
	if err != nil || len(res.Erased) != 0 || len(res.Resumed) != 0 {
		t.Fatalf("an unknown subject: %+v, %v; want nothing erased", res, err)
	}
}

// ---------------------------------------------------------------------------
// What Verify catches
// ---------------------------------------------------------------------------

// TestErase_RemovesLeftovers: content and a nonce left by a commit that stopped
// before its append are erased too.
func TestErase_RemovesLeftovers(t *testing.T) {
	s, _, ring := setup(t)
	strayID := "sink-" + strings.Repeat("e", 32)
	if err := os.WriteFile(s.contentPath(cid(t, s, "u-81"), strayID), []byte(`{"user":"u-81"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.PutBatch(cid(t, s, "u-81"), map[string][]byte{strayID: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	ns.Close()

	if _, err := eraseOne(t, s, "u-81"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.contentPath(cid(t, s, "u-81"), strayID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover content survived erasure: %v", err)
	}
	ns, err = noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if _, err := ns.Get(cid(t, s, "u-81"), strayID); !errors.Is(err, noncestore.ErrNotFound) {
		t.Fatalf("leftover nonce survived erasure: %v", err)
	}
	ns.Close()
	mustVerify(t, s, ring)
}

// TestErase_LeftoversOfAnInterruptedFirstCommit (review 2.2): a first commit
// that stopped before its append leaves content, a nonce and a source position,
// but no entries. Erase removes all three, writes no erasure entry, and Verify
// no longer reports a removed chain.
func TestErase_LeftoversOfAnInterruptedFirstCommit(t *testing.T) {
	s, _, ring := setup(t)
	// Commit step 1 happened (the index row for u-99 is written first), then
	// content, nonce and source position, then the crash: no append.
	bindChain(t, s, "u-99")
	id := "sink-" + strings.Repeat("c", 32)
	if err := os.MkdirAll(filepath.Join(s.dir, "content", cid(t, s, "u-99")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.contentPath(cid(t, s, "u-99"), id), []byte(`{"user":"u-99"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	if err := ns.PutBatch(cid(t, s, "u-99"), map[string][]byte{id: nonce}); err != nil {
		t.Fatal(err)
	}
	ns.Close()
	src, err := openSources(s.sourcesPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.putBatch(cid(t, s, "u-99"), map[string]position{"EVIDENCE@1:77": {entryID: id, seq: 0}}); err != nil {
		t.Fatal(err)
	}
	src.Close()

	if p := problems(t, s, ring, cid(t, s, "u-99")); !strings.Contains(p, "first commit stopped") {
		t.Fatalf("leftovers not reported: %q", p)
	}
	res, err := eraseOne(t, s, "u-99")
	if err != nil || res.Leftovers != 3 || res.ErasureEntryID != "" {
		t.Fatalf("Erase of leftovers = %+v, %v; want 3 removed and no erasure entry", res, err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "content", cid(t, s, "u-99"))); !os.IsNotExist(err) {
		t.Fatal("the leftover content folder is still there")
	}
	raw, _ := os.ReadFile(noncestore.PathFor(s.DBPath()))
	if bytes.Contains(raw, nonce) {
		t.Fatal("the leftover nonce is still in the nonce file's bytes")
	}
	if raw, _ := os.ReadFile(s.sourcesPath()); bytes.Contains(raw, []byte("EVIDENCE@1:77")) {
		t.Fatal("the leftover source position is still in the sources file's bytes")
	}
	if n := len(entryIDs(t, s, cid(t, s, "u-99"))); n != 0 {
		t.Fatalf("an erasure entry was written for a chain with no entries (%d entries)", n)
	}
	mustVerify(t, s, ring)

	// Nothing left, and the subject is forgotten: a second call erases nothing.
	if res, err := s.EraseSubject(context.Background(), "u-99"); err != nil || len(res.Erased) != 0 {
		t.Fatalf("a second erasure of u-99: %+v, %v; want nothing", res, err)
	}
}

// TestErase_ReadsInPages: a chain longer than one page is counted in full.
func TestErase_ReadsInPages(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Commit(ctx, events("u-1", entryPage)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 5)); err != nil {
		t.Fatal(err)
	}
	res, err := eraseOne(t, s, "u-1")
	if err != nil || res.Events != entryPage+5 {
		t.Fatalf("Erase over %d entries = %+v, %v", entryPage+5, res, err)
	}
}
