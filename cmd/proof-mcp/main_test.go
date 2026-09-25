// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/aleutian-ai/proof/verify"
)

// connect starts the server over an in-memory transport and returns a client
// session — a real MCP round trip, without a subprocess.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: "aleutianchain", Version: "test"}, nil)
	registerTools(server)

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

	cs := connect(t)
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
	cs := connect(t)
	var out computeChainHashOut
	call(t, cs, "compute_chain_hash", map[string]any{
		"previous_hash": "",
		"run_id":        "run_mcp",
		"sequence_num":  0,
		"timestamp":     "2026-01-20T12:00:00.123456Z",
		"content_hash":  strings.Repeat("a", 128),
	}, &out)

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-20T12:00:00.123456Z")
	want := chainformat.ComputeChainHashUnchecked("", "run_mcp", 0, ts, strings.Repeat("a", 128))
	if out.ChainHash != want {
		t.Errorf("chain_hash = %s, want %s", out.ChainHash, want)
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
			"previous_hash": "abc|d", // a pipe: the collision vector
			"run_id":        "run_mcp",
			"sequence_num":  0,
			"timestamp":     "2026-01-20T12:00:00.123456Z",
			"content_hash":  strings.Repeat("a", 128),
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
	keyPath = filepath.Join(dir, "key.bin")
	if err := os.WriteFile(keyPath, pubBytes, 0o600); err != nil {
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
