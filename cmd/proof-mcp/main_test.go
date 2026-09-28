// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/bundle"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/verify"
)

// connect starts the server over an in-memory transport and returns a client
// session — a real MCP round trip, without a subprocess.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	return connectWith(t, commitConfig{})
}

// connectWith starts a server with the given launch configuration.
func connectWith(t *testing.T, cfg commitConfig) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: "aleutianchain", Version: "test"}, nil)
	if err := registerTools(server, cfg); err != nil {
		t.Fatal(err)
	}

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).
		Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call invokes a tool and returns its structured result decoded into v.
func call(t *testing.T, cs *mcp.ClientSession, name string, args any, v any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: name, Arguments: args,
	})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if v != nil && res.StructuredContent != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatalf("decode %s result: %v", name, err)
		}
	}
	return res
}

// writeChain writes a linked chain to a temp file and returns its path.
func writeChain(t *testing.T, n int, erase bool) string {
	t.Helper()

	base := time.Date(2026, 1, 20, 12, 0, 0, 123456000, time.UTC)
	entries := make([]verify.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)
		h, err := chainformat.ComputeChainHash(prev, "run_mcp", int64(i), ts, contentHash)
		if err != nil {
			t.Fatalf("link %d: %v", i, err)
		}
		entries = append(entries, verify.Entry{
			EntryID: "entry_" + hex.EncodeToString([]byte{byte(i)}), EntryType: "request",
			Timestamp: ts.Format("2006-01-02T15:04:05.000000Z"), RunID: "run_mcp",
			SequenceNum: int64(i), GlobalSeq: int64(i),
			ContentHash: contentHash, ChainHash: h,
		})
		prev = h
	}
	if erase && n > 1 {
		tomb, err := chainformat.GenerateTombstoneContentHash()
		if err != nil {
			t.Fatalf("tombstone: %v", err)
		}
		entries[1].EntryType = chainformat.TombstoneEntryType
		entries[1].EntryID = chainformat.TombstoneEntryIDPrefix + "550e8400-e29b-41d4-a716-446655440000"
		entries[1].ContentHash = tomb
	}

	path := filepath.Join(t.TempDir(), "entries.json")
	raw, _ := json.Marshal(entries)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// =============================================================================
// The security assertion
// =============================================================================

// TestNoKeyMaterialTools fails if a tool that could return key material or
// plaintext is ever registered.
//
// # Why this is a test and not a code review convention
//
// A seed or a decrypted payload returned in a tool result enters the model's
// context and is transmitted to a model provider, where it may be logged and
// retained. For a system whose central claim is that the operator never holds
// the customer's key, adding a `decrypt` tool would quietly falsify that claim —
// and it is exactly the kind of tool someone adds in good faith because it looks
// useful.
//
// The check is on NAMES rather than behaviour, deliberately: it is coarse, it
// will occasionally be annoying, and it fails closed. A reviewer who genuinely
// needs a tool matching one of these words has to come here and argue for it,
// which is the intended friction.
func TestNoKeyMaterialTools(t *testing.T) {
	forbidden := []string{
		"keygen", "key_gen", "generate_key", "private_key", "seed",
		"decrypt", "unwrap", "decapsulate", "unseal", "plaintext",
		// SIGNING is a key operation too. Added 2026-09-24 with `proof anchor`
		// (_35c): the anchor signer would have been named something like
		// "sign_anchor", which matched none of the terms above — this test would
		// have passed while a private key crossed the MCP boundary. Only
		// TestToolsAreTheExpectedSet would have caught it, and that one is about
		// surface stability rather than key safety.
		"sign", "signer", "signature_over",
	}

	// Both launch modes: the read-only server, and the one with --db, whose extra
	// tool must pass the same name check.
	for _, cs := range []*mcp.ClientSession{connect(t), connectWith(t, commitConfig{db: newCommitDB(t)})} {
		tools, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		if len(tools.Tools) == 0 {
			t.Fatal("no tools registered; this test would pass vacuously")
		}

		for _, tool := range tools.Tools {
			name := strings.ToLower(tool.Name)
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("tool %q suggests key or plaintext handling.\n"+
						"Tool results are transmitted to a model provider. Key material must "+
						"never cross that boundary — keygen and decryption belong in the "+
						"human-driven CLI. If this tool genuinely needs to exist, it must be "+
						"file-path in, file-path out, with its own threat model.", tool.Name)
				}
			}
		}
	}
}

// TestToolsAreTheExpectedSet pins the surface, so a tool cannot be added without
// someone updating this list and thinking about it.
func TestToolsAreTheExpectedSet(t *testing.T) {
	want := map[string]bool{
		"verify_chain": true, "compute_chain_hash": true,
		"canonicalize_leaf": true, "verify_inclusion": true,
		"verify_anchor": true, "verify_bundle": true,
		"explain_trust_model": true,
	}

	cs := connect(t)
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range tools.Tools {
		got[tool.Name] = true
		if !want[tool.Name] {
			t.Errorf("unexpected tool %q — add it to this test deliberately", tool.Name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("tool %q is missing", name)
		}
	}
}

// =============================================================================
// Tools
// =============================================================================

func TestVerifyChain_Intact(t *testing.T) {
	cs := connect(t)
	var out verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": writeChain(t, 5, false)}, &out)

	if out.Verdict != string(verify.VerdictIntact) {
		t.Fatalf("verdict = %q, want INTACT (breaks: %+v)", out.Verdict, out.Breaks)
	}
	if out.EntriesVerified != 5 {
		t.Errorf("entries_verified = %d, want 5", out.EntriesVerified)
	}
}

// TestVerifyChain_ErasedEntryIsNotABreak covers the case that shipped broken in
// three SDKs.
func TestVerifyChain_ErasedEntryIsNotABreak(t *testing.T) {
	cs := connect(t)
	var out verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": writeChain(t, 4, true)}, &out)

	if out.Verdict != string(verify.VerdictIntact) {
		t.Fatalf("a lawfully erased entry produced verdict %q (breaks: %+v)",
			out.Verdict, out.Breaks)
	}
	if out.TombstonesFound != 1 {
		t.Errorf("tombstones_found = %d, want 1", out.TombstonesFound)
	}
}

// TestVerifyChain_ResultCarriesTheBoundary asserts the result itself states what
// was NOT proven.
//
// A model relaying this to a human will summarise it. If the structured result
// only said "INTACT", the honest caveat would depend on the model choosing to
// add it. Putting it in the payload means the model has to actively discard it
// to overclaim.
func TestVerifyChain_ResultCarriesTheBoundary(t *testing.T) {
	cs := connect(t)
	var out verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": writeChain(t, 3, false)}, &out)

	if out.Proven == "" {
		t.Error("result does not say what WAS proven")
	}
	if !strings.Contains(out.NotProven, "anchor") {
		t.Errorf("result does not say an anchor is needed for the stronger claim: %q", out.NotProven)
	}
	if !strings.Contains(strings.ToLower(out.NotProven), "whole chain") {
		t.Errorf("result does not mention truncation: %q", out.NotProven)
	}
}

func TestVerifyChain_DetectsTampering(t *testing.T) {
	path := writeChain(t, 5, false)
	raw, _ := os.ReadFile(path)
	var entries []verify.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse: %v", err)
	}
	entries[2].ContentHash = strings.Repeat("f", 128)
	out, _ := json.Marshal(entries)
	os.WriteFile(path, out, 0o600)

	cs := connect(t)
	var res verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": path}, &res)

	if res.Verdict != string(verify.VerdictBroken) {
		t.Fatalf("verdict = %q, want BROKEN", res.Verdict)
	}
	if res.FirstBreak != 2 {
		t.Errorf("first_break = %d, want 2", res.FirstBreak)
	}
}

func TestComputeChainHash(t *testing.T) {
	// The v3 expectation comes from a chain the LINKER wrote, not from inputs this
	// test invents — so the tool is checked against what proof commit produces.
	st := memory.New()
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	var batch []linker.Input
	for i := 0; i < 2; i++ {
		batch = append(batch, linker.Input{
			EntryID: fmt.Sprintf("e%d", i), EntryType: "capture.request.v3",
			Timestamp:   base.Add(time.Duration(i) * time.Second),
			ContentHash: strings.Repeat(fmt.Sprintf("%02x", i+1), 64),
			IngestedAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	if _, err := l.Append(context.Background(), "c", batch); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Range(context.Background(), "c", 0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].FormatVersion != chainformat.FormatV3 {
		t.Fatalf("the linker wrote format %d; this test assumes v3 is its default", rows[1].FormatVersion)
	}
	v3ts := rows[1].Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z")

	v2ts := "2026-01-20T12:00:00.123456Z"
	ts2, _ := time.Parse(time.RFC3339Nano, v2ts)
	ch := strings.Repeat("a", 128)
	v2want := chainformat.ComputeChainHashUnchecked("", "run_mcp", 3, ts2, ch)

	v3 := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"format_version": 3, "previous_hash": rows[0].ChainHash,
			"timestamp": v3ts, "content_hash": rows[1].ContentHash,
			"global_seq": fmt.Sprint(rows[1].GlobalSeq),
		}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	v2 := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"format_version": 2, "previous_hash": "", "timestamp": v2ts,
			"content_hash": ch, "run_id": "run_mcp", "sequence_num": "3",
		}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}

	tests := []struct {
		name       string
		args       map[string]any
		wantHash   string
		wantFormat int
		wantErr    string
	}{
		{name: "v3 reproduces the linker", args: v3(nil), wantHash: rows[1].ChainHash, wantFormat: 3},
		{name: "v3 accepts an export row's structural zeros",
			args: v3(map[string]any{"run_id": "", "sequence_num": "0"}), wantHash: rows[1].ChainHash, wantFormat: 3},
		{name: "v2", args: v2(nil), wantHash: v2want, wantFormat: 2},

		{name: "format_version missing", args: v3(map[string]any{"format_version": nil}), wantErr: "missing properties: [\"format_version\"]"},
		{name: "format_version unknown", args: v3(map[string]any{"format_version": 4}), wantErr: "format_version must be 2 or 3"},
		{name: "v3 without global_seq", args: v3(map[string]any{"global_seq": nil}), wantErr: "global_seq is required"},
		{name: "v3 with a run_id", args: v3(map[string]any{"run_id": "r"}), wantErr: "does not bind run_id"},
		{name: "v3 with a sequence_num", args: v3(map[string]any{"sequence_num": "5"}), wantErr: "does not bind run_id or sequence_num"},
		{name: "v2 without sequence_num", args: v2(map[string]any{"sequence_num": nil}), wantErr: "sequence_num is required"},
		{name: "v2 with global_seq", args: v2(map[string]any{"global_seq": "1"}), wantErr: "does not use global_seq"},
		{name: "non-numeric global_seq", args: v3(map[string]any{"global_seq": "four"}), wantErr: "decimal integer"},
		{name: "negative global_seq", args: v3(map[string]any{"global_seq": "-1"}), wantErr: "must not be negative"},
		{name: "global_seq as a JSON number", args: v3(map[string]any{"global_seq": 1}), wantErr: "string"},
		// The checked path must run for v3 too, not only v2: a pipe in previous_hash
		// makes the preimage ambiguous.
		{name: "v3 malformed previous_hash", args: v3(map[string]any{"previous_hash": "abc|d"}), wantErr: "128 lowercase hex"},
	}

	cs := connect(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "compute_chain_hash", Arguments: tc.args,
			})
			if tc.wantErr != "" {
				msg := ""
				if err != nil {
					msg = err.Error()
				} else if res.IsError {
					for _, c := range res.Content {
						if tx, ok := c.(*mcp.TextContent); ok {
							msg += tx.Text
						}
					}
				} else {
					t.Fatalf("expected an error containing %q, got a result", tc.wantErr)
				}
				if !strings.Contains(msg, tc.wantErr) {
					t.Errorf("error %q does not contain %q", msg, tc.wantErr)
				}
				return
			}
			if err != nil || res.IsError {
				t.Fatalf("unexpected error: %v %+v", err, res)
			}
			var out computeChainHashOut
			raw, _ := json.Marshal(res.StructuredContent)
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.ChainHash != tc.wantHash {
				t.Errorf("chain_hash = %s\n want %s", out.ChainHash, tc.wantHash)
			}
			if out.FormatVersion != tc.wantFormat {
				t.Errorf("format_version = %d, want %d", out.FormatVersion, tc.wantFormat)
			}
			domain := fmt.Sprintf("aleutian.chain.v%d:", tc.wantFormat)
			if !strings.Contains(out.Preimage, domain) {
				t.Errorf("preimage_description does not name %s: %s", domain, out.Preimage)
			}
		})
	}
}

// TestComputeChainHash_SequenceAbove2To53IsExact pins why the sequence fields
// are strings: 2^53+1 as a JSON number used to come back as a hash for 2^53.
func TestComputeChainHash_SequenceAbove2To53IsExact(t *testing.T) {
	const big = int64(9007199254740993)
	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-20T12:00:01.123456Z")
	ch := strings.Repeat("a", 128)
	want := chainformat.ComputeChainHashV3Unchecked("", big, ts, ch)
	wrong := chainformat.ComputeChainHashV3Unchecked("", big-1, ts, ch)
	if want == wrong {
		t.Fatal("the two hashes are equal; this test cannot detect truncation")
	}

	cs := connect(t)
	var out computeChainHashOut
	call(t, cs, "compute_chain_hash", map[string]any{
		"format_version": 3, "previous_hash": "", "timestamp": "2026-01-20T12:00:01.123456Z",
		"content_hash": ch, "global_seq": "9007199254740993",
	}, &out)
	if out.ChainHash != want {
		t.Errorf("global_seq 2^53+1 was not hashed exactly (got the hash for 2^53: %v)", out.ChainHash == wrong)
	}
}

// TestComputeChainHash_RejectsMalformedPreviousHash pins that the tool uses the
// VALIDATED path.
//
// An unvalidated previous_hash makes the preimage ambiguous, and two different
// entries can collide (format-spec §3). A tool taking model-supplied input is
// exactly where that must not be reachable.
func TestComputeChainHash_RejectsMalformedPreviousHash(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "compute_chain_hash",
		Arguments: map[string]any{
			"format_version": 2,
			"previous_hash":  "abc|d", // a pipe: the collision vector
			"run_id":         "run_mcp",
			"sequence_num":   "0",
			"timestamp":      "2026-01-20T12:00:00.123456Z",
			"content_hash":   strings.Repeat("a", 128),
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("a pipe-bearing previous_hash was accepted; the tool must use the validated path")
	}
}

func TestCanonicalizeLeaf(t *testing.T) {
	entry := chainformat.CaptureRequestV3{
		Subject: "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA", SigningKeyID: "signer-1",
		TimestampMs: 1751068800000, CaptureMethod: "fetch_intercept",
		ContentHash: strings.Repeat("a", 128), EncryptionMode: "zero-knowledge",
		Model: "gpt-4o", PIIAction: "none", ProcessingMode: "zk",
		Provider: "openai", Region: "us", SourceType: "browser_extension",
		TrustLevel: "verified", UserID: strings.Repeat("b", 128),
	}
	cs := connect(t)
	var out canonicalizeLeafOut
	call(t, cs, "canonicalize_leaf", map[string]any{"entry": entry}, &out)

	_, wantHash, err := chainformat.EncodeAndHashV3(entry)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if out.ContentHash != wantHash {
		t.Errorf("content_hash = %s, want %s", out.ContentHash, wantHash)
	}
	if out.CanonicalByteLen == 0 || out.CanonicalBytesHex == "" {
		t.Error("canonical bytes were not returned; this tool exists to show them")
	}
}

// =============================================================================
// Hostile input
// =============================================================================

// TestVerifyChain_RejectsHostilePaths asserts that a model-supplied path cannot
// climb out or hang the server.
//
// Every tool argument is attacker-controlled under prompt injection: a document
// the agent reads can contain instructions to call a tool with a chosen path.
func TestVerifyChain_RejectsHostilePaths(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"traversal", "../../../../etc/passwd"},
		{"traversal mid-path", "/tmp/../etc/passwd"},
		{"empty", ""},
		{"directory", os.TempDir()},
		{"missing", filepath.Join(os.TempDir(), "definitely-not-here-9f3a.json")},
	}
	cs := connect(t)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "verify_chain", Arguments: map[string]any{"path": tc.path},
			})
			if err == nil && !res.IsError {
				t.Errorf("path %q was accepted", tc.path)
			}
		})
	}
}

// TestErrorsDoNotEchoFileContents pins that a failure message cannot be used to
// read a file a byte at a time.
//
// Tool results reach a model provider. An error that quoted the offending line
// would turn a parse failure into an exfiltration primitive: point the tool at a
// secret, read the secret back out of the error.
func TestErrorsDoNotEchoFileContents(t *testing.T) {
	secret := "SUPERSECRET-CANARY-VALUE"
	path := filepath.Join(t.TempDir(), "notjson.json")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "verify_chain", Arguments: map[string]any{"path": path},
	})

	var text string
	if err != nil {
		text = err.Error()
	}
	if res != nil {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text += tc.Text
			}
		}
	}
	if strings.Contains(text, secret) {
		t.Fatalf("the error echoed file contents, which makes it an exfiltration "+
			"primitive:\n%s", text)
	}
}

// =============================================================================
// verify_anchor · verify_bundle · explain_trust_model
// =============================================================================

// anchoredFixture writes an entries file and a matching anchor, and returns both
// paths plus the signing key (raw ML-DSA-65 public key bytes).
func anchoredFixture(t *testing.T, n int, truncateBy int) (entriesPath, anchorPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	type row struct {
		id, contentHash, chainHash string
		seq                        int64
		ts                         time.Time
	}
	var rows []row
	prev := ""
	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		ch := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)
		h, err := chainformat.ComputeChainHash(prev, "run_mcp", int64(i), ts, ch)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row{
			id:          "0192f3a1-0000-7000-8000-" + hex.EncodeToString([]byte{0, 0, 0, 0, 0, byte(i)}),
			contentHash: ch, chainHash: h, seq: int64(i), ts: ts,
		})
		prev = h
	}

	// The anchor commits to the FULL chain.
	a := anchor.Anchor{
		Version:          3,
		AnchorID:         "anchor_01234567-8901-2345-6789-012345678901",
		Subject:          "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		Range:            anchor.EntryRange{StartEntryID: rows[0].id, EndEntryID: rows[n-1].id},
		EntryCount:       int64(n),
		SigningKeyID:     "test-key-v1",
		CreatedAtMs:      base.UnixMilli(),
		PreviousAnchorID: anchor.SeedAnchorID,
	}
	ah, err := anchor.ChainHash(anchor.SeedAnchorHash, a.Subject,
		a.Range.StartEntryID, a.Range.EndEntryID, rows[n-1].chainHash)
	if err != nil {
		t.Fatal(err)
	}
	a.ChainHash = ah

	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(priv, canonical, nil, false, sig)
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	// Optionally truncate the ENTRIES (not the anchor) and re-link.
	kept := rows[truncateBy:]
	if truncateBy > 0 {
		prev = ""
		for i := range kept {
			kept[i].seq = int64(i)
			kept[i].chainHash = chainformat.ComputeChainHashUnchecked(
				prev, "run_mcp", int64(i), kept[i].ts, kept[i].contentHash)
			prev = kept[i].chainHash
		}
	}

	var entries []verify.Entry
	for _, r := range kept {
		entries = append(entries, verify.Entry{
			EntryID: r.id, EntryType: "request",
			Timestamp:   r.ts.UTC().Format("2006-01-02T15:04:05.000000Z"),
			RunID:       "run_mcp",
			SequenceNum: r.seq, GlobalSeq: r.seq,
			ContentHash: r.contentHash, ChainHash: r.chainHash,
		})
	}

	entriesPath = filepath.Join(dir, "entries.json")
	writeJSON(t, entriesPath, entries)
	anchorPath = filepath.Join(dir, "anchor.json")
	writeJSON(t, anchorPath, a)

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// PEM, through keyfile — the encoding `proof keygen` actually writes.
	//
	// This used to write RAW bytes to "key.bin", which is why nothing caught that
	// verify_anchor could not read a single key the tool itself produces: the test
	// invented a format, then confirmed the server agreed with the invention
	// (aleutianchain_54).
	pemBytes, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "ml-dsa-65-public.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return entriesPath, anchorPath, keyPath
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyAnchor_KeylessBindSucceeds covers the no-key path.
func TestVerifyAnchor_KeylessBindSucceeds(t *testing.T) {
	entries, anchorPath, _ := anchoredFixture(t, 5, 0)

	cs := connect(t)
	var out verifyAnchorOut
	call(t, cs, "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath,
	}, &out)

	if !out.Bound {
		t.Fatalf("expected a bound result: %+v", out)
	}
	if out.SignatureVerified {
		t.Error("a keyless call must not report a verified signature")
	}
	if !strings.Contains(out.NotProven, "genuine") {
		t.Errorf("a keyless result must say the anchor was not authenticated: %q", out.NotProven)
	}
}

// TestVerifyAnchor_DetectsTruncation is the tool's reason for existing.
func TestVerifyAnchor_DetectsTruncation(t *testing.T) {
	entries, anchorPath, _ := anchoredFixture(t, 5, 2)

	cs := connect(t)

	// Chain verification alone still says INTACT — that is the premise.
	var chainOut verifyChainOut
	call(t, cs, "verify_chain", map[string]any{"path": entries}, &chainOut)
	if chainOut.Verdict != string(verify.VerdictIntact) {
		t.Fatalf("the truncated chain should still verify as INTACT, got %q", chainOut.Verdict)
	}

	// The anchor catches it, and names the reason.
	var out verifyAnchorOut
	call(t, cs, "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath,
	}, &out)
	if out.Bound {
		t.Fatal("truncation survived anchor binding")
	}
	if out.Outcome != string(verify.BindRangeStartMismatch) {
		t.Fatalf("want range_start_mismatch, got %q: %s", out.Outcome, out.Detail)
	}
}

// TestVerifyAnchor_WithKeyReportsTrust covers the keyed path and pins that the
// trust level reaches the tool result.
func TestVerifyAnchor_WithKeyReportsTrust(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 4, 0)

	cs := connect(t)
	var out verifyAnchorOut
	call(t, cs, "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath,
		"public_key_path": keyPath, "key_trust": "provided",
	}, &out)

	if !out.Bound || !out.SignatureVerified {
		t.Fatalf("expected a bound, verified result: %+v", out)
	}
	if out.Trust != string(anchor.TrustProvided) {
		t.Errorf("trust = %q, want provided", out.Trust)
	}
	if out.TrustEstablishes == "" {
		t.Error("the result must spell out what the trust level establishes")
	}
}

// TestVerifyAnchor_DefaultsToTheWeakerTrustClaim pins that omitting key_trust
// does not silently assert the strongest claim.
func TestVerifyAnchor_DefaultsToTheWeakerTrustClaim(t *testing.T) {
	entries, anchorPath, keyPath := anchoredFixture(t, 3, 0)

	cs := connect(t)
	var out verifyAnchorOut
	call(t, cs, "verify_anchor", map[string]any{
		"entries_path": entries, "anchor_path": anchorPath,
		"public_key_path": keyPath,
	}, &out)

	if out.Trust == string(anchor.TrustPlatform) {
		t.Fatal("omitting key_trust must NOT default to the platform claim — " +
			"this process cannot know where a key came from")
	}
}

// TestVerifyBundle_IntactAndTampered covers both directions.
func TestVerifyBundle_IntactAndTampered(t *testing.T) {
	dir := t.TempDir()
	contents := map[string]string{
		"README.txt":          "readme",
		"chain/entries.jsonl": `{"entry":1}`,
	}
	var files []bundle.FileEntry
	for p, body := range contents {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha512.Sum512([]byte(body))
		files = append(files, bundle.FileEntry{Path: p, SHA512: hex.EncodeToString(sum[:])})
	}
	root, err := bundle.ManifestRoot(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"manifest_root": root, "files": files}
	writeJSON(t, filepath.Join(dir, "manifest.json"), manifest)

	// manifest.json is itself an unlisted file; list it so the bundle is clean.
	mraw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	msum := sha512.Sum512(mraw)
	files = append(files, bundle.FileEntry{Path: "manifest.json", SHA512: hex.EncodeToString(msum[:])})
	root, _ = bundle.ManifestRoot(files)
	writeJSON(t, filepath.Join(dir, "manifest.json"),
		map[string]any{"manifest_root": root, "files": files})

	cs := connect(t)
	var out verifyBundleOut
	call(t, cs, "verify_bundle", map[string]any{"dir": dir}, &out)
	// manifest.json's own hash changed when we rewrote it, so expect exactly that
	// one problem — which is itself a useful demonstration that the tool notices.
	for _, p := range out.Problems {
		if p.Path != "manifest.json" {
			t.Errorf("unexpected problem on %s: %s", p.Path, p.Detail)
		}
	}

	// Now tamper with a listed file and confirm it is reported.
	if err := os.WriteFile(filepath.Join(dir, "chain", "entries.jsonl"),
		[]byte(`{"entry":"TAMPERED"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out2 verifyBundleOut
	call(t, cs, "verify_bundle", map[string]any{"dir": dir}, &out2)
	if out2.Intact {
		t.Fatal("a tampered bundle verified as intact")
	}
	var sawMismatch bool
	for _, p := range out2.Problems {
		if p.Path == "chain/entries.jsonl" && p.Kind == string(bundle.ProblemContentMismatch) {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Fatalf("the swapped file was not reported: %+v", out2.Problems)
	}
	if !strings.Contains(out2.NotProven, "signature") {
		t.Errorf("the result must say no signature was checked: %q", out2.NotProven)
	}
}

// TestExplainTrustModel_CoversEveryCheck pins that the explanation stays in step
// with the tools that exist. An explanation that silently omits a check is worse
// than none, because it reads as complete.
func TestExplainTrustModel_CoversEveryCheck(t *testing.T) {
	cs := connect(t)
	var out explainTrustModelOut
	call(t, cs, "explain_trust_model", map[string]any{}, &out)

	if len(out.Claims) < 4 {
		t.Fatalf("want a claim entry per check, got %d", len(out.Claims))
	}
	for _, c := range out.Claims {
		if c.Proven == "" || c.NotProven == "" {
			t.Errorf("check %q must state BOTH what it proves and what it does not", c.Check)
		}
	}
	if len(out.TrustLevels) != 3 {
		t.Fatalf("want 3 trust levels, got %d", len(out.TrustLevels))
	}
	seen := map[string]bool{}
	for _, l := range out.TrustLevels {
		if seen[l.Establishes] {
			t.Errorf("two trust levels make the same claim: %q", l.Establishes)
		}
		seen[l.Establishes] = true
	}
	if !strings.Contains(out.WhyNoTrustStore, "rotation") {
		t.Error("the no-trust-store explanation should give the operational reason too")
	}
	if out.AnchorProvenance == "" {
		t.Error("the provenance caveat must be stated; a signature check does not say where the anchor came from")
	}
}

// TestModuleIsInstallable guards the README's install line.
//
// `go install github.com/aleutian-ai/proof/cmd/proof-mcp@latest` REFUSES any
// module whose go.mod contains a replace directive. This module carried
// `replace github.com/aleutian-ai/proof => ../..` until the library was first
// published, and the install command in the README failed for every user as a
// result — while every test here stayed green, because tests run the module as
// the main module, where replace is honoured.
//
// That asymmetry is why this has to be a test: nothing else in the suite can see
// the failure. Develop against unreleased library changes with a go.work at the
// repository root (gitignored) instead.
func TestModuleIsInstallable(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "replace ") || trimmed == "replace (" {
			t.Errorf("go.mod:%d has a replace directive — `go install ...@latest` will refuse "+
				"this module. Use a go.work for local development instead.", i+1)
		}
		if strings.Contains(trimmed, "github.com/aleutian-ai/proof v0.0.0-00010101000000") {
			t.Errorf("go.mod:%d requires the zero pseudo-version of the library, which only "+
				"resolves through a replace. Require a published tag.", i+1)
		}
	}
}

// =============================================================================
// Loader failure diagnosis — aleutianchain_54 and _55
// =============================================================================

// TestReadCapped_DistinguishesFailures pins that each cause says what it is.
//
// All four used to be reported as "cannot read the <X> file at that path". Three
// of them are not about the path, so a caller with a correct path was told the
// path was wrong. That is the bug _54 hid behind: a PEM key over a raw-bytes cap
// looked like a missing file.
func TestReadCapped_DistinguishesFailures(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(big, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		limit     int64
		wantErr   bool
		wantIs    error
		wantWords []string
		notWords  []string
	}{
		{
			name: "a readable file within the limit", path: small, limit: 1 << 20,
		},
		{
			name: "no such file", path: filepath.Join(dir, "absent.txt"), limit: 1 << 20,
			wantErr: true, wantIs: fs.ErrNotExist,
			wantWords: []string{"absent.txt"},
		},
		{
			name: "a directory", path: dir, limit: 1 << 20,
			wantErr: true, wantIs: errNotRegular,
			wantWords: []string{"directory"},
			// Must NOT claim the path is unreadable: the path is fine.
			notWords: []string{"cannot read"},
		},
		{
			name: "over the limit", path: big, limit: 16,
			wantErr: true, wantIs: errTooLarge,
			// The sizes are the actionable part. This is the exact shape of _54.
			wantWords: []string{"64 bytes", "16 byte limit"},
			notWords:  []string{"cannot read"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readCapped(tc.path, tc.limit)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error does not match its sentinel (so callers cannot "+
					"branch on the cause): %v", err)
			}
			for _, w := range tc.wantWords {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error is missing %q: %v", w, err)
				}
			}
			for _, w := range tc.notWords {
				if strings.Contains(err.Error(), w) {
					t.Errorf("error wrongly says %q when the path was fine: %v", w, err)
				}
			}
		})
	}
}

// TestLoadKeyRing_ReadsTheEncodingKeygenWrites is _54's core claim.
func TestLoadKeyRing_ReadsTheEncodingKeygenWrites(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, raw)
	if err != nil {
		t.Fatal(err)
	}

	// A PEM key is ~2.7 KB, well over the 1953-byte raw bound this used to use.
	if len(pemBytes) <= anchor.PublicKeySize+1 {
		t.Fatalf("this test cannot detect the _54 regression: the PEM is %d bytes, "+
			"within the old raw cap of %d", len(pemBytes), anchor.PublicKeySize+1)
	}

	path := filepath.Join(dir, "ml-dsa-65-public.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyRing(path, "provided", "k1"); err != nil {
		t.Fatalf("loadKeyRing rejected the encoding `proof keygen` writes: %v", err)
	}

	// Raw bytes are NOT silently accepted: the CLI and this server must agree on
	// one encoding, or they drift apart again.
	rawPath := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyRing(rawPath, "provided", "k1"); err == nil {
		t.Error("raw key bytes were accepted; the two surfaces can drift again")
	}
}

// TestLoadKeyRing_RefusesByAlgorithm pins that a wrong-algorithm key is reported
// as a wrong algorithm, naming both what was given and what is needed.
func TestLoadKeyRing_RefusesByAlgorithm(t *testing.T) {
	dir := t.TempDir()
	// A structurally valid ML-DSA-44 public key file. The BYTES need not be a real
	// key: the refusal must happen on the declared algorithm, before any use.
	pemBytes, err := keyfile.MarshalPublicKey(keyfile.MLDSA44, make([]byte, 1312))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ml-dsa-44-public.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = loadKeyRing(path, "provided", "k1")
	if err == nil {
		t.Fatal("an ML-DSA-44 key must be refused; anchors are ML-DSA-65")
	}
	for _, want := range []string{"ML-DSA-44", "ML-DSA-65"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q so the reader knows what to fix: %v", want, err)
		}
	}
}

// TestLoadKeyRing_ChecksTheTrustLabelBeforeTouchingDisk pins the ordering.
//
// A bad key_trust reported as a file problem sends the reader to the wrong place.
func TestLoadKeyRing_ChecksTheTrustLabelBeforeTouchingDisk(t *testing.T) {
	_, err := loadKeyRing(filepath.Join(t.TempDir(), "does-not-exist.pem"), "nonsense", "k1")
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), "key_trust") {
		t.Errorf("a bad key_trust must be reported as such, not as a file error: %v", err)
	}
}

// TestLoadAnchor_DistinguishesFailures: loadAnchor had the identical
// single-message shape and only loadKeyRing was under test.
func TestLoadAnchor_DistinguishesFailures(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-json.json")
	if err := os.WriteFile(bad, []byte("this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("no such file", func(t *testing.T) {
		_, err := loadAnchor(filepath.Join(dir, "absent.json"))
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a missing anchor file must match fs.ErrNotExist: %v", err)
		}
	})

	t.Run("a directory", func(t *testing.T) {
		_, err := loadAnchor(dir)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, errNotRegular) || !strings.Contains(err.Error(), "directory") {
			t.Errorf("a directory must be reported as a directory: %v", err)
		}
	})

	t.Run("not JSON", func(t *testing.T) {
		_, err := loadAnchor(bad)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "not valid JSON") {
			t.Errorf("a parse failure must say so, not blame the path: %v", err)
		}
		// The file's CONTENTS must not appear: an anchor can carry a subject, and
		// this message may be relayed to a model provider.
		if strings.Contains(err.Error(), "this is not json") {
			t.Errorf("the error echoes file contents: %v", err)
		}
	})
}
