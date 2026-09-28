// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// saltedFixture commits one salted entry and one plain-digest entry, storing the
// salted entry's nonce exactly as proof-mcp's commit tool does.
func saltedFixture(t *testing.T) (db, contentPath string) {
	t.Helper()
	dir := t.TempDir()
	db = filepath.Join(dir, "evidence.db")
	content := []byte("agent refunded order 4411")
	contentPath = filepath.Join(dir, "content.txt")
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	c, nonce, err := commitment.Salted(content)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(db), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.PutBatch("c", map[string][]byte{"salted": nonce}); err != nil {
		t.Fatal(err)
	}
	ns.Close()

	st, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, _ := linker.New(st)
	now := time.Now().UTC()
	if _, err := l.Append(context.Background(), "c", []linker.Input{
		{EntryID: "salted", EntryType: "mcp.salted", Timestamp: now, IngestedAt: now, ContentHash: c},
		{EntryID: "digest", EntryType: "mcp.digest", Timestamp: now.Add(time.Microsecond),
			IngestedAt: now.Add(time.Microsecond), ContentHash: strings.Repeat("ab", 64)},
	}); err != nil {
		t.Fatal(err)
	}
	return db, contentPath
}

func TestDisclose_ProducesAProofAThirdPartyCanCheck(t *testing.T) {
	db, content := saltedFixture(t)
	code, out, stderr := runWithStdin(t, "", cmdDisclose,
		"--db", db, "--chain", "c", "--entry", "salted", "--content", content)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var d disclosure
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("output is not a disclosure: %v\n%s", err, out)
	}
	nonce, err := hex.DecodeString(d.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(content)
	// What a third party runs: no secret, only the disclosure and the content.
	if !commitment.Verify(d.Commitment, nonce, raw) {
		t.Fatal("the disclosure does not verify for a third party")
	}
}

func TestDisclose_Refusals(t *testing.T) {
	db, content := saltedFixture(t)
	wrong := filepath.Join(t.TempDir(), "wrong.txt")
	os.WriteFile(wrong, []byte("agent refunded order 9999"), 0o600)

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"wrong content", []string{"--db", db, "--chain", "c", "--entry", "salted", "--content", wrong}, exitBroken, "not the content that was committed"},
		{"unknown entry", []string{"--db", db, "--chain", "c", "--entry", "nope", "--content", content}, exitIOError, "no entry"},
		{"plain digest entry", []string{"--db", db, "--chain", "c", "--entry", "digest", "--content", content}, exitIOError, "no nonce stored"},
		{"missing flags", []string{"--db", db}, exitUsage, "required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := runWithStdin(t, "", cmdDisclose, tc.args...)
			if code != tc.wantCode || !strings.Contains(stderr, tc.wantErr) {
				t.Fatalf("exit %d stderr %q, want %d containing %q", code, stderr, tc.wantCode, tc.wantErr)
			}
			if out != "" {
				t.Errorf("a refused disclosure still printed: %s", out)
			}
		})
	}
}

// TestForget_ErasesTheOnlyWayToOpenTheEntry, while the chain still verifies.
func TestForget_ErasesTheOnlyWayToOpenTheEntry(t *testing.T) {
	db, content := saltedFixture(t)
	code, out, stderr := runWithStdin(t, "", cmdForget, "--db", db, "--chain", "c", "--entry", "salted")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "Not reached by this") {
		t.Error("forget must say which copies it cannot reach")
	}
	code, _, stderr = runWithStdin(t, "", cmdDisclose,
		"--db", db, "--chain", "c", "--entry", "salted", "--content", content)
	if code == exitOK || !strings.Contains(stderr, "no nonce stored") {
		t.Fatalf("the forgotten entry can still be disclosed: exit %d %s", code, stderr)
	}
	entries, err := readChain(db, "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("forget changed the chain: %d entries", len(entries))
	}
}
