// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// TestForget_LeavesNoNonceBytesInTheFile: after forget, the nonce's bytes are
// not in the nonce file. Deleting the key alone left them in a bbolt free page,
// while the README said forget makes the entry unopenable from this machine.
//
// Many nonces are stored first so the deleted one sits on a page of its own
// neighbours, the case where the review found it left behind.
func TestForget_LeavesNoNonceBytesInTheFile(t *testing.T) {
	db, _ := saltedFixture(t)
	path := noncestore.PathFor(db)
	ns, err := noncestore.Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ns.Get("c", "salted")
	if err != nil {
		t.Fatal(err)
	}
	others := map[string][]byte{}
	for i := 0; i < 500; i++ {
		others[fmt.Sprintf("other-%03d", i)] = bytes.Repeat([]byte{byte(i), byte(i >> 8), 0x5c}, 11)[:32]
	}
	if err := ns.PutBatch("c", others); err != nil {
		t.Fatal(err)
	}
	ns.Close()
	if raw, _ := os.ReadFile(path); !bytes.Contains(raw, secret) {
		t.Fatal("control failed: the nonce is not in the file before forget")
	}

	if code, _, stderr := runWithStdin(t, "", cmdForget, "--db", db, "--chain", "c", "--entry", "salted"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("the forgotten nonce's bytes are still in the nonce file")
	}
	// The other nonces survived the rewrite, and no copy of the file is left.
	ns, err = noncestore.OpenReadOnly(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if got, err := ns.Get("c", "other-499"); err != nil || !bytes.Equal(got, others["other-499"]) {
		t.Fatalf("another entry's nonce did not survive the rewrite: %v", err)
	}
	left, _ := filepath.Glob(path + ".compact-*")
	if len(left) != 0 {
		t.Fatalf("a temporary copy of the nonce file was left behind: %v", left)
	}
}

// TestForget_RefusesWhatDoesNotExist: forget reports success only for an entry
// that is on the chain. A missing entry or chain is an error, and a mistyped
// --db is an error that creates nothing; each once printed "forgot the nonce"
// and exited 0, the last after creating an empty database and nonce file.
func TestForget_RefusesWhatDoesNotExist(t *testing.T) {
	db, _ := saltedFixture(t)
	typo := filepath.Join(filepath.Dir(db), "typo.db")
	for name, args := range map[string][]string{
		"no such entry":    {"--db", db, "--chain", "c", "--entry", "nope"},
		"no such chain":    {"--db", db, "--chain", "nope", "--entry", "salted"},
		"no such database": {"--db", typo, "--chain", "c", "--entry", "salted"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, _ := runWithStdin(t, "", cmdForget, args...)
			if code == exitOK || code == exitUsage {
				t.Fatalf("exit %d, want an error that is not a usage error", code)
			}
			if strings.Contains(out, "forgot the nonce") {
				t.Fatalf("reported success:\n%s", out)
			}
		})
	}
	for _, p := range []string{typo, noncestore.PathFor(typo)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("forget created %s", p)
		}
	}
	// The nonce it was not asked about is untouched.
	ns, err := noncestore.OpenReadOnly(noncestore.PathFor(db), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if _, err := ns.Get("c", "salted"); err != nil {
		t.Fatalf("a refused forget removed a nonce: %v", err)
	}
}

// TestForget_AnEntryWithNoNonce: an entry that is on the chain and has no nonce
// (forgotten already, or a plain digest) is not an error, and is not reported
// as a nonce forgotten.
func TestForget_AnEntryWithNoNonce(t *testing.T) {
	db, _ := saltedFixture(t)
	code, out, stderr := runWithStdin(t, "", cmdForget, "--db", db, "--chain", "c", "--entry", "digest")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(out, "forgot the nonce") || !strings.Contains(out, "no nonce is stored") {
		t.Fatalf("output:\n%s", out)
	}
}

// TestDisclose_CreatesNothing: disclose against a mistyped --db fails without
// creating a database or a nonce file.
func TestDisclose_CreatesNothing(t *testing.T) {
	db, content := saltedFixture(t)
	typo := filepath.Join(filepath.Dir(db), "typo.db")
	code, _, _ := runWithStdin(t, "", cmdDisclose, "--db", typo, "--chain", "c", "--entry", "salted", "--content", content)
	if code == exitOK {
		t.Fatal("disclosed from a database that does not exist")
	}
	for _, p := range []string{typo, noncestore.PathFor(typo)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("disclose created %s", p)
		}
	}
}
