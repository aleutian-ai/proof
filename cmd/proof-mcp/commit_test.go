// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// newCommitDB creates an initialised, empty evidence database, as --db would.
func newCommitDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.db")
	cfg, err := parseFlags([]string{"--db", path, "--chains", "*"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.db
}

// commitCall invokes commit and returns the decoded result, or the error text.
func commitCall(t *testing.T, cs *mcp.ClientSession, args map[string]any) (commitOut, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "commit", Arguments: args})
	if err != nil {
		return commitOut{}, err.Error()
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tx, ok := c.(*mcp.TextContent); ok {
				msg.WriteString(tx.Text)
			}
		}
		return commitOut{}, msg.String()
	}
	var out commitOut
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out, ""
}

// readChain returns a chain's entries straight from the database file.
func readChain(t *testing.T, db, chain string) []verify.Entry {
	t.Helper()
	st, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.Range(context.Background(), chain, 0, 1<<40, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]verify.Entry, len(rows))
	for i, r := range rows {
		out[i] = verify.Entry{
			EntryID: r.EntryID, EntryType: r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion, GlobalSeq: r.GlobalSeq,
			ContentHash: r.ContentHash, ChainHash: r.ChainHash,
		}
	}
	return out
}

func contents(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = map[string]any{"content": fmt.Sprintf("agent action %d", i)}
	}
	return out
}

// ---------------------------------------------------------------------------
// Registration: commit exists only when the human asked for it
// ---------------------------------------------------------------------------

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}

func TestCommit_NotRegisteredWithoutDB(t *testing.T) {
	if _, ok := toolNames(t, connect(t))["commit"]; ok {
		t.Fatal("commit is registered on a server started without --db; it must stay read-only")
	}
}

// TestExactlyOneToolWrites: with --db, commit is the only tool not marked
// read-only, and no import tool exists. Importing trusts hashes from the input,
// which over MCP means trusting a prompt.
func TestExactlyOneToolWrites(t *testing.T) {
	tools := toolNames(t, connectWith(t, commitConfig{db: newCommitDB(t)}))
	var writers []string
	for name, tool := range tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			writers = append(writers, name)
		}
		if strings.Contains(name, "import") {
			t.Errorf("tool %q: there must be no import over MCP", name)
		}
	}
	if len(writers) != 1 || writers[0] != "commit" {
		t.Fatalf("tools not marked read-only: %v, want exactly [commit]", writers)
	}
	if d := tools["commit"].Description; !strings.Contains(d, "WRITES") {
		t.Errorf("commit's description must say plainly that it writes: %q", d)
	}
}

// ---------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------

func TestCommit_ContentRoundTrip(t *testing.T) {
	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})

	before := time.Now().UTC().Add(-time.Second)
	out, errText := commitCall(t, cs, map[string]any{"chain": "agent-7", "entries": contents(3)})
	after := time.Now().UTC().Add(time.Second)
	if errText != "" {
		t.Fatal(errText)
	}
	if out.Committed != 3 || len(out.Entries) != 3 {
		t.Fatalf("committed %d, returned %d entries; want 3/3", out.Committed, len(out.Entries))
	}

	stored := readChain(t, db, "agent-7")
	if res, err := verify.Chain(stored, verify.Options{}); err != nil || len(res.Breaks) > 0 {
		t.Fatalf("the committed chain does not verify: %v %+v", err, res.Breaks)
	}
	if out.HeadHash != stored[len(stored)-1].ChainHash {
		t.Error("head_hash does not match the stored chain head")
	}

	var prev time.Time
	for i, e := range out.Entries {
		// Order is the caller's order, and each entry opens with ITS content.
		if e.GlobalSeq != fmt.Sprint(i) {
			t.Errorf("entry %d: global_seq %s", i, e.GlobalSeq)
		}
		// The nonce is NOT in the result (it would land in the transcript); it is
		// in the local nonce file, and it opens this entry with its content.
		if !e.NonceStored {
			t.Errorf("entry %d: nonce_stored is false", i)
		}
		nonce := storedNonce(t, db, "agent-7", e.EntryID)
		if !commitment.Verify(stored[i].ContentHash, nonce, []byte(fmt.Sprintf("agent action %d", i))) {
			t.Errorf("entry %d does not open with its own content and stored nonce", i)
		}
		if e.EntryType != entryTypeSalted || stored[i].EntryType != entryTypeSalted {
			t.Errorf("entry %d: type %q/%q, want %q", i, e.EntryType, stored[i].EntryType, entryTypeSalted)
		}
		// Server-stamped, inside the call window, strictly increasing.
		ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		if ts.Before(before) || ts.After(after) {
			t.Errorf("entry %d timestamp %v is outside the call window", i, ts)
		}
		if i > 0 && !ts.After(prev) {
			t.Errorf("entry %d timestamp is not after entry %d's", i, i-1)
		}
		prev = ts
		if !strings.HasPrefix(e.EntryID, "mcp-") || len(e.EntryID) != 36 {
			t.Errorf("entry %d: id %q is not server-assigned", i, e.EntryID)
		}
	}
}

func TestCommit_ContentHashIsStoredAsGiven(t *testing.T) {
	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})
	h := strings.Repeat("ab", 64)
	out, errText := commitCall(t, cs, map[string]any{
		"chain": "artifacts", "entries": []any{map[string]any{"content_hash": h}},
	})
	if errText != "" {
		t.Fatal(errText)
	}
	stored := readChain(t, db, "artifacts")[0]
	if out.Entries[0].NonceStored || stored.ContentHash != h {
		t.Error("a supplied content_hash must be committed unchanged, with no nonce")
	}
	if stored.EntryType != entryTypeDigest {
		t.Errorf("type %q, want %q: a verifier must be able to tell it is a plain digest", stored.EntryType, entryTypeDigest)
	}
}

// TestCommit_ChainsAreIndependent: topics and users are separate chains.
func TestCommit_ChainsAreIndependent(t *testing.T) {
	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})
	for _, c := range []string{"payments", "auth", "payments"} {
		if _, e := commitCall(t, cs, map[string]any{"chain": c, "entries": contents(1)}); e != "" {
			t.Fatal(e)
		}
	}
	if n := len(readChain(t, db, "payments")); n != 2 {
		t.Errorf("payments has %d entries, want 2", n)
	}
	if n := len(readChain(t, db, "auth")); n != 1 {
		t.Errorf("auth has %d entries, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// Refusals: each leaves the database byte-identical
// ---------------------------------------------------------------------------

func TestCommit_Refusals(t *testing.T) {
	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db, chains: map[string]bool{"allowed": true, "other": true}})
	// Give the file real content, so "unchanged" is a meaningful assertion.
	if _, e := commitCall(t, cs, map[string]any{"chain": "allowed", "entries": contents(2)}); e != "" {
		t.Fatal(e)
	}
	snapshot, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}

	entry := func(kv ...any) []any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return []any{m}
	}
	big := strings.Repeat("x", maxCommitContentBytes+1)

	tests := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{"uppercase chain", map[string]any{"chain": "Allowed", "entries": contents(1)}, "lowercase"},
		{"email as chain", map[string]any{"chain": "jo@example.com", "entries": contents(1)}, "never an email"},
		{"empty chain", map[string]any{"chain": "", "entries": contents(1)}, "lowercase"},
		{"65-char chain", map[string]any{"chain": strings.Repeat("a", 65), "entries": contents(1)}, "more than 64"},
		{"chain outside --chains", map[string]any{"chain": "elsewhere", "entries": contents(1)}, "--chains"},
		{"no entries", map[string]any{"chain": "allowed", "entries": []any{}}, "minItems"},
		{"101 entries", map[string]any{"chain": "allowed", "entries": contents(101)}, "maxItems"},
		{"content and hash", map[string]any{"chain": "allowed", "entries": entry("content", "x", "content_hash", strings.Repeat("a", 128))}, "not both"},
		{"neither", map[string]any{"chain": "allowed", "entries": entry("label", "note")}, "send content or content_hash"},
		{"empty content", map[string]any{"chain": "allowed", "entries": entry("content", "")}, "content is empty"},
		{"uppercase hash", map[string]any{"chain": "allowed", "entries": entry("content_hash", strings.Repeat("A", 128))}, "128 lowercase hex"},
		{"short hash", map[string]any{"chain": "allowed", "entries": entry("content_hash", strings.Repeat("a", 127))}, "128 lowercase hex"},
		{"content over the cap (characters)", map[string]any{"chain": "allowed", "entries": entry("content", big)}, "maxLength"},
		// Under 64K characters but over 64 KiB in bytes: passes the schema, and the
		// handler's byte cap has to catch it.
		{"content over the cap (bytes)", map[string]any{"chain": "allowed", "entries": entry("content", strings.Repeat("é", maxCommitContentBytes/2+1))}, "byte limit"},
		{"bad label", map[string]any{"chain": "allowed", "entries": entry("content", "x", "label", "Not OK")}, "label"},
		{"caller entry_type", map[string]any{"chain": "allowed", "entries": entry("content", "x", "entry_type", "tombstone")}, "additional properties"},
		// Hash-bound fields cannot be supplied at all: the schema has no room.
		{"caller entry_id", map[string]any{"chain": "allowed", "entries": entry("content", "x", "entry_id", "mine")}, "additional properties"},
		{"caller timestamp", map[string]any{"chain": "allowed", "entries": entry("content", "x", "timestamp", "2020-01-01T00:00:00Z")}, "additional properties"},
		{"caller global_seq", map[string]any{"chain": "allowed", "entries": entry("content", "x", "global_seq", "0")}, "additional properties"},
		{"caller chain_hash", map[string]any{"chain": "allowed", "entries": entry("content", "x", "chain_hash", strings.Repeat("a", 128))}, "additional properties"},
		{"caller previous_hash", map[string]any{"chain": "allowed", "entries": contents(1), "previous_hash": ""}, "additional properties"},
		{"caller db path", map[string]any{"chain": "allowed", "entries": contents(1), "db": "/tmp/x.db"}, "additional properties"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, errText := commitCall(t, cs, tc.args)
			if errText == "" {
				t.Fatalf("accepted; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(errText, tc.wantErr) {
				t.Errorf("error %q does not contain %q", errText, tc.wantErr)
			}
			now, err := os.ReadFile(db)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(now, snapshot) {
				t.Fatal("a refused call changed the database")
			}
		})
	}
}

// TestCommit_Boundaries: exactly at each cap is accepted.
func TestCommit_Boundaries(t *testing.T) {
	cs := connectWith(t, commitConfig{db: newCommitDB(t)})
	if _, e := commitCall(t, cs, map[string]any{"chain": "c", "entries": contents(maxCommitEntries)}); e != "" {
		t.Errorf("exactly %d entries refused: %s", maxCommitEntries, e)
	}
	atCap := []any{map[string]any{"content": strings.Repeat("x", maxCommitContentBytes)}}
	if _, e := commitCall(t, cs, map[string]any{"chain": "c", "entries": atCap}); e != "" {
		t.Errorf("content of exactly %d bytes refused: %s", maxCommitContentBytes, e)
	}
	if _, e := commitCall(t, cs, map[string]any{"chain": strings.Repeat("a", 64), "entries": contents(1)}); e != "" {
		t.Errorf("64-char chain refused: %s", e)
	}
}

// TestCommit_BusyDatabaseCommitsNothing: another process holding the file gets a
// clear, retryable error, and nothing is written.
func TestCommit_BusyDatabaseCommitsNothing(t *testing.T) {
	old := dbLockTimeout
	dbLockTimeout = 100 * time.Millisecond
	t.Cleanup(func() { dbLockTimeout = old })

	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})
	holder, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	_, errText := commitCall(t, cs, map[string]any{"chain": "c", "entries": contents(1)})
	holder.Close()
	if !strings.Contains(errText, "held by another process") || !strings.Contains(errText, "nothing was committed") {
		t.Fatalf("want an error saying another process holds it and nothing was committed, got %q", errText)
	}
	if n := len(readChain(t, db, "c")); n != 0 {
		t.Fatalf("%d entries committed while the database was busy", n)
	}
}

// ---------------------------------------------------------------------------
// Launch flags
// ---------------------------------------------------------------------------

func TestParseFlags(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no flags: read-only", nil, ""},
		{"db without chains", []string{"--db", filepath.Join(dir, "a.db")}, "--db requires --chains"},
		{"db with any chain", []string{"--db", filepath.Join(dir, "a2.db"), "--chains", "*"}, ""},
		{"db and chains", []string{"--db", filepath.Join(dir, "b.db"), "--chains", "payments, auth"}, ""},
		{"chains without db", []string{"--chains", "x"}, "only applies with --db"},
		{"bad chain id", []string{"--db", filepath.Join(dir, "c.db"), "--chains", "ok,Not-Ok"}, "not a valid chain id"},
		{"unopenable db", []string{"--db", filepath.Join(dir, "missing", "d.db"), "--chains", "*"}, "--db"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseFlags(tc.args)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if tc.name == "db and chains" && (!cfg.chains["payments"] || !cfg.chains["auth"]) {
					t.Errorf("chains not parsed with spaces trimmed: %v", cfg.chains)
				}
				if tc.name == "db with any chain" && cfg.chains != nil {
					t.Errorf("'*' must mean any chain, got allowlist %v", cfg.chains)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestToolsAreTheExpectedSet_WithDB: --db adds commit and nothing else.
func TestToolsAreTheExpectedSet_WithDB(t *testing.T) {
	got := toolNames(t, connectWith(t, commitConfig{db: newCommitDB(t)}))
	want := []string{"verify_chain", "compute_chain_hash", "canonicalize_leaf", "verify_inclusion",
		"verify_anchor", "verify_bundle", "explain_trust_model", "commit"}
	if len(got) != len(want) {
		t.Fatalf("%d tools registered, want %d: %v", len(got), len(want), got)
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Errorf("tool %q missing", n)
		}
	}
}

func storedNonce(t *testing.T, db, chain, entryID string) []byte {
	t.Helper()
	ns, err := noncestore.Open(noncestore.PathFor(db), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	n, err := ns.Get(chain, entryID)
	if err != nil {
		t.Fatalf("no nonce stored for %s: %v", entryID, err)
	}
	return n
}

// TestCommit_LabelIsNamespaced: the caller can label an entry but never choose
// its type, so it cannot mimic another writer's types.
func TestCommit_LabelIsNamespaced(t *testing.T) {
	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})
	out, e := commitCall(t, cs, map[string]any{"chain": "c", "entries": []any{
		map[string]any{"content": "x", "label": "agent-action"},
	}})
	if e != "" {
		t.Fatal(e)
	}
	if want := entryTypeSalted + ".agent-action"; out.Entries[0].EntryType != want || readChain(t, db, "c")[0].EntryType != want {
		t.Errorf("type %q, want %q", out.Entries[0].EntryType, want)
	}
}

// TestCommit_ParallelCallsBothSucceed: models issue parallel tool calls; within
// one server they must queue, not fail as "busy".
func TestCommit_ParallelCallsBothSucceed(t *testing.T) {
	// A lock wait far shorter than one commit: without the in-process mutex,
	// parallel calls collide on the file lock and fail. With it, they queue.
	old := dbLockTimeout
	dbLockTimeout = time.Microsecond
	t.Cleanup(func() { dbLockTimeout = old })

	db := newCommitDB(t)
	cs := connectWith(t, commitConfig{db: db})
	errs := make(chan string, 4)
	for i := 0; i < 4; i++ {
		go func() {
			_, e := commitCall(t, cs, map[string]any{"chain": "c", "entries": contents(3)})
			errs <- e
		}()
	}
	for i := 0; i < 4; i++ {
		if e := <-errs; e != "" {
			t.Errorf("a parallel commit failed: %s", e)
		}
	}
	entries := readChain(t, db, "c")
	if len(entries) != 12 {
		t.Fatalf("%d entries, want 12", len(entries))
	}
	if res, err := verify.Chain(entries, verify.Options{}); err != nil || len(res.Breaks) > 0 {
		t.Fatalf("parallel commits broke the chain: %v %+v", err, res.Breaks)
	}
}

// TestCommit_SurvivesALeaseLeftByACrash: an MCP server killed mid-append must
// not lock its chain forever.
func TestCommit_SurvivesALeaseLeftByACrash(t *testing.T) {
	db := newCommitDB(t)
	st, err := boltstore.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.Acquire(context.Background(), "c"); err != nil || !ok {
		t.Fatal("could not take the lease")
	}
	st.Close() // no Release: the writer "crashed"

	cs := connectWith(t, commitConfig{db: db})
	if _, e := commitCall(t, cs, map[string]any{"chain": "c", "entries": contents(1)}); e != "" {
		t.Fatalf("the chain is still locked by a dead writer: %s", e)
	}
}

// TestNoncesAreForgottenWhenTheAppendFails exercises the cleanup directly: an
// orphaned nonce is harmless, but it should not be left behind needlessly.
func TestNoncesAreForgottenWhenTheAppendFails(t *testing.T) {
	db := newCommitDB(t)
	n := map[string][]byte{"e1": bytes.Repeat([]byte{1}, 32)}
	if err := storeNonces(db, "c", n); err != nil {
		t.Fatal(err)
	}
	forgetNonces(db, "c", n)
	ns, err := noncestore.Open(noncestore.PathFor(db), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if _, err := ns.Get("c", "e1"); err == nil {
		t.Fatal("the nonce of an uncommitted entry was left behind")
	}
}
