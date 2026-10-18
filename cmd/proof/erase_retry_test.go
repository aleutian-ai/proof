// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/internal/noncestore"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// assertErased checks that the entry at seq 0 of chain c is erased, that its
// nonce is gone, and that none of its removed bytes are left in the database.
func assertErased(t *testing.T, db string, salt, contentHash string) {
	t.Helper()
	after, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if !after[0].Erased {
		t.Fatalf("the entry is not erased: %+v", after[0])
	}
	ns, err := noncestore.OpenReadOnly(noncestore.PathFor(db), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, gerr := ns.Get("c", "salted")
	ns.Close()
	if gerr == nil {
		t.Error("the entry's nonce is still stored")
	}
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{salt, contentHash} {
		if bytes.Contains(raw, []byte(b)) {
			t.Errorf("the database still holds %.16s…", b)
		}
	}
}

// TestErase_RetryAfterACrashBeforeTheErase: the nonce was forgotten and the
// process died before the entry was erased. The same command finishes it.
// (The entry is erased only after its nonce is forgotten, so the reverse, an
// erased entry whose nonce nothing can name any more, cannot happen.)
func TestErase_RetryAfterACrashBeforeTheErase(t *testing.T) {
	db, _ := saltedFixture(t)
	before, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := noncestore.Forget(noncestore.PathFor(db), "c", "salted", time.Second); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "0"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	assertErased(t, db, before[0].Salt, before[0].ContentHash)
}

// TestErase_RetryAfterACrashBeforeTheRewrite: the entry was erased and the
// process died before the database was rewritten, so its bytes are in free
// pages. The same command rewrites it, on the "erased already" path too.
func TestErase_RetryAfterACrashBeforeTheRewrite(t *testing.T) {
	db, _ := saltedFixture(t)
	before, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := noncestore.Forget(noncestore.PathFor(db), "c", "salted", time.Second); err != nil {
		t.Fatal(err)
	}
	st, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Erase(context.Background(), "c", 0); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// A leftover of an interrupted rewrite, as a crash inside one leaves.
	leftover := db + ".compact-123"
	if err := os.WriteFile(leftover, []byte("a copy of the old file"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, stderr := runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "0")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !bytes.Contains([]byte(out), []byte("erased already")) {
		t.Errorf("output does not say the entry was erased already: %s", out)
	}
	assertErased(t, db, before[0].Salt, before[0].ContentHash)
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Errorf("the interrupted rewrite's leftover is still there: %v", err)
	}
}

// TestErase_RefusesASymlinkedDB: the nonce file and the rewrite are found by
// --db's own name, so through a link they would miss the real files.
func TestErase_RefusesASymlinkedDB(t *testing.T) {
	db, _ := saltedFixture(t)
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(db, link); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runWithStdin(t, "", cmdErase, "--db", link, "--chain", "c", "--seq", "0"); code == exitOK {
		t.Fatal("erased through a symlink")
	}
	after, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Erased {
		t.Error("the entry was erased through the link")
	}
}
