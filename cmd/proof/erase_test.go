// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// TestErase_V4EntryIsGoneAndTheChainStillVerifies: proof erase removes the
// entry's id, type, content hash and salt and its nonce, leaves none of their
// bytes in either file, and the export still verifies, the erased entry
// recomputed from its leaf hash.
func TestErase_V4EntryIsGoneAndTheChainStillVerifies(t *testing.T) {
	db, content := saltedFixture(t)
	before, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	gone := before[0]
	if gone.EntryID != "salted" || gone.FormatVersion != 4 {
		t.Fatalf("fixture: %+v", gone)
	}

	code, out, stderr := runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "0")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "its nonce was forgotten") || !strings.Contains(out, "Not reached by this") {
		t.Errorf("output does not say what was and was not reached:\n%s", out)
	}

	after, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if !after[0].Erased || after[0].EntryID != "" || after[0].LeafHash != gone.LeafHash || after[0].ChainHash != gone.ChainHash {
		t.Fatalf("erased entry: %+v", after[0])
	}
	res, err := verify.Chain(after, verify.Options{})
	if err != nil || res.Verdict != verify.VerdictIntact || res.ErasedFound != 1 {
		t.Fatalf("after erase: %+v, %v", res, err)
	}

	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{gone.Salt, gone.ContentHash, "mcp.salted"} {
		if bytes.Contains(raw, []byte(b)) {
			t.Errorf("the database still holds %.24s…", b)
		}
	}
	code, _, stderr = runWithStdin(t, "", cmdDisclose, "--db", db, "--chain", "c", "--entry", "salted", "--content", content)
	if code == exitOK {
		t.Fatalf("the erased entry can still be disclosed: %s", stderr)
	}

	code, out, _ = runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "0")
	if code != exitOK || !strings.Contains(out, "erased already") {
		t.Errorf("a second erase: exit %d, %s", code, out)
	}
	if code, _, _ := runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "9"); code != exitUsage {
		t.Errorf("erase of a missing entry: exit %d", code)
	}
}

// TestErase_RefusesAV3Entry: v3 is frozen; its entries are not erased in place.
func TestErase_RefusesAV3Entry(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	st, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := linker.New(st, linker.WithFormatV3())
	now := time.Now().UTC()
	if _, err := l.Append(context.Background(), "c", []linker.Input{{EntryID: "e", EntryType: "t",
		Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	code, _, stderr := runWithStdin(t, "", cmdErase, "--db", db, "--chain", "c", "--seq", "0")
	if code != exitUsage || !strings.Contains(stderr, "not v4") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

// TestErase_AnAnchorStillBindsAfterTheRangesEndsAreErased: ticket's done-when.
// Commit, anchor, erase the first and the last entry of the anchored range,
// export, and the v7 anchor still binds and its signature still verifies.
func TestErase_AnAnchorStillBindsAfterTheRangesEndsAreErased(t *testing.T) {
	f := newVerifyFixture(t, 4)
	for _, seq := range []string{"0", "3"} {
		if code, _, stderr := runWithStdin(t, "", cmdErase, "--db", f.db, "--chain", f.chainID, "--seq", seq); code != exitOK {
			t.Fatalf("erase %s: exit %d: %s", seq, code, stderr)
		}
	}
	exported := filepath.Join(t.TempDir(), "after.jsonl")
	if code, _, stderr := capture(t, "export", "--db", f.db, "--chain", f.chainID, "--out", exported); code != exitOK {
		t.Fatalf("export: %s", stderr)
	}
	code, out, _ := runVerify(t, exported, "--anchor", f.anchorPath, "--key", f.pubPath, "--key-trust", "self")
	if code != exitOK || !strings.Contains(out, "ANCHOR BOUND") || !strings.Contains(out, "2 erased") ||
		!strings.Contains(out, "signature verified") {
		t.Fatalf("after erasing both ends: exit %d\n%s", code, out)
	}
}
