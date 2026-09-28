// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"context"
	"path/filepath"
	"testing"
)

// TestOpen_ClearsLeaseLeftByACrashedWriter: a process that dies between Acquire
// and Release must not lock its chain forever. Simulated by acquiring and then
// closing without releasing — exactly what a killed process leaves behind.
func TestOpen_ClearsLeaseLeftByACrashedWriter(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Acquire(ctx, "chain"); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	// Within the same open store the lease is genuinely held.
	if _, ok, _ := s.Acquire(ctx, "chain"); ok {
		t.Fatal("a held lease was granted twice")
	}
	s.Close() // no Release: the writer "crashed"

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, ok, err := s2.Acquire(ctx, "chain"); err != nil || !ok {
		t.Fatalf("after reopen the chain is still locked by a dead writer: ok=%v err=%v", ok, err)
	}
}
