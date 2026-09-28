// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package noncestore

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPutGetDelete(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db.nonces"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	n1, n2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := s.PutBatch("a", map[string][]byte{"e1": n1, "e2": n2}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("a", "e1"); err != nil || !bytes.Equal(got, n1) {
		t.Fatalf("get e1: %x %v", got, err)
	}
	// The same entry id in another chain is a different key.
	if _, err := s.Get("b", "e1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("chain b must not see chain a's nonce: %v", err)
	}
	if err := s.Delete("a", "e1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a", "e1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted nonce still readable: %v", err)
	}
	if got, err := s.Get("a", "e2"); err != nil || !bytes.Equal(got, n2) {
		t.Fatal("deleting e1 affected e2")
	}
	if err := s.Delete("a", "e1"); err != nil {
		t.Fatalf("deleting an absent nonce must not be an error: %v", err)
	}
}

// TestGetReturnsACopy: bbolt memory is only valid inside the transaction.
func TestGetReturnsACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db.nonces")
	s, err := Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutBatch("a", map[string][]byte{"e": bytes.Repeat([]byte{7}, 32)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("a", "e")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if !bytes.Equal(got, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("the returned nonce was invalidated by closing the store")
	}
}

// TestDeleteBatch removes only the named entries, only in the named chain.
func TestDeleteBatch(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db.nonces"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	n := bytes.Repeat([]byte{3}, 32)
	for _, chain := range []string{"a", "b"} {
		if err := s.PutBatch(chain, map[string][]byte{"e1": n, "e2": n, "e3": n}); err != nil {
			t.Fatal(err)
		}
	}
	// "absent" is not stored: deleting it must not fail the batch.
	if err := s.DeleteBatch("a", []string{"e1", "e2", "absent"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"e1", "e2"} {
		if _, err := s.Get("a", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a/%s survived DeleteBatch: %v", id, err)
		}
	}
	if _, err := s.Get("a", "e3"); err != nil {
		t.Fatalf("a/e3 was not named but was deleted: %v", err)
	}
	for _, id := range []string{"e1", "e2", "e3"} {
		if _, err := s.Get("b", id); err != nil {
			t.Fatalf("chain b lost %s when chain a was erased: %v", id, err)
		}
	}
}

// TestDeleteChain removes every nonce of one chain, and only that chain —
// including a chain whose id is a prefix of another's.
func TestDeleteChain(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db.nonces"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n := bytes.Repeat([]byte{4}, 32)
	for _, chain := range []string{"a", "ab", "a.b"} {
		if err := s.PutBatch(chain, map[string][]byte{"e1": n, "e2": n}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.DeleteChain("a")
	if err != nil || got != 2 {
		t.Fatalf("DeleteChain(a) = %d, %v; want 2", got, err)
	}
	if _, err := s.Get("a", "e1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a/e1 survived: %v", err)
	}
	for _, chain := range []string{"ab", "a.b"} {
		if _, err := s.Get(chain, "e1"); err != nil {
			t.Fatalf("%s lost a nonce when a was erased: %v", chain, err)
		}
	}
	if got, err := s.DeleteChain("a"); err != nil || got != 0 {
		t.Fatalf("second DeleteChain = %d, %v", got, err)
	}
}
