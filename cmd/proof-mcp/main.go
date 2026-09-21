// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command proof-mcp exposes AleutianChain verification over the Model Context
// Protocol.
//
// # Description
//
// An MCP stdio server: the client spawns it as a subprocess and speaks JSON-RPC
// over stdin and stdout. There is no port, no network, and no credential. An
// agent can audit an Aleutian receipt without an account and without trusting
// the party that produced it.
//
//	claude mcp add aleutianchain -- proof-mcp
//
// # What it deliberately cannot do
//
// There is no key generation tool and no decryption tool, and there will not be.
// A seed or a plaintext returned in a tool result enters the model's context and
// is transmitted to a provider. For a system whose claim is that the operator
// never holds the customer's key, piping key material through an LLM transcript
// would be a self-inflicted wound.
//
// Key generation and decryption live in the human-driven CLI, with no model in
// the loop. TestNoKeyMaterialTools enforces this — it fails the build if a tool
// whose name suggests key handling is ever registered.
//
// # Trust boundary
//
// Every argument arrives from a model and must be treated as attacker-controlled
// under prompt injection. Paths are resolved and checked against a root; reads
// are size-bounded; nothing is shelled out.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/bundle"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/merkle"
	"github.com/aleutian-ai/proof/verify"
)

// maxEntriesFileBytes bounds a single read.
//
// A model-supplied path could point at anything on disk — /dev/zero, a multi-
// gigabyte log. The cap turns "the agent hung" into a clear error. 64 MiB is far
// beyond any plausible export while remaining bounded.
const maxEntriesFileBytes = 64 << 20

func main() {
	if err := run(); err != nil {
		log.Fatalf("proof-mcp: %v", err)
	}
}

func run() error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "aleutianchain",
		Version: "0.1.0",
	}, nil)

	registerTools(server)

	return server.Run(context.Background(), &mcp.StdioTransport{})
}

// registerTools wires every tool.
//
// Kept separate from run so tests can enumerate what is registered without
// starting a server — see TestNoKeyMaterialTools.
func registerTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "verify_chain",
		Description: "Verify an exported audit chain. Reports whether the linkage is " +
			"intact and, if not, the index of the FIRST break. Note the result " +
			"distinguishes consistency (nothing was edited) from existence (this is " +
			"the same chain) — only the first is provable without an anchor.",
	}, verifyChain)

	mcp.AddTool(s, &mcp.Tool{
		Name: "compute_chain_hash",
		Description: "Compute the chain hash for one entry's fields. Useful for " +
			"checking a single link by hand, or for showing how the linkage works.",
	}, computeChainHash)

	mcp.AddTool(s, &mcp.Tool{
		Name: "canonicalize_leaf",
		Description: "Show the exact canonical bytes a capture entry hashes to, as " +
			"hex, alongside its content hash. This is the 'show your work' tool: it " +
			"lets a skeptic re-hash the bytes themselves rather than trusting the " +
			"encoder.",
	}, canonicalizeLeaf)

	mcp.AddTool(s, &mcp.Tool{
		Name: "verify_inclusion",
		Description: "Verify that a leaf belongs to a Merkle tree with a given root, " +
			"using an inclusion proof.",
	}, verifyInclusion)

	mcp.AddTool(s, &mcp.Tool{
		Name: "verify_anchor",
		Description: "Check an exported chain against an anchor. This is what detects " +
			"TRUNCATION, which chain verification alone cannot: a chain with entries " +
			"removed from the front and the rest re-linked verifies as intact. Without " +
			"a public key this binds the chain to the anchor but does NOT establish " +
			"that the anchor is genuine; supply public_key_path for that.",
	}, verifyAnchorTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "verify_bundle",
		Description: "Verify an export bundle directory: recompute the manifest root " +
			"over the inventory, and re-hash every listed file to confirm the bytes on " +
			"disk match what the manifest claims. Reports every problem found, not just " +
			"the first.",
	}, verifyBundleTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "explain_trust_model",
		Description: "Explain what a verification result does and does not prove, and " +
			"why this tool ships no built-in trust store. Call this when a user asks " +
			"whether a chain is 'trusted', 'valid', or 'proven' — those words hide a " +
			"distinction that matters.",
	}, explainTrustModel)
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

type verifyChainIn struct {
	Path string `json:"path" jsonschema:"path to an exported entries file (JSON array or JSONL)"`
}

type verifyChainOut struct {
	Verdict         string `json:"verdict"`
	EntriesVerified int    `json:"entries_verified"`
	TombstonesFound int    `json:"tombstones_found"`
	FirstBreak      int    `json:"first_break"`
	Breaks          []brk  `json:"breaks,omitempty"`

	// Proven and NotProven spell out the boundary in the result itself, so a
	// model relaying this to a human cannot honestly flatten it to "verified".
	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

type brk struct {
	Position int    `json:"position"`
	EntryID  string `json:"entry_id"`
	Type     string `json:"break_type"`
	Detail   string `json:"detail,omitempty"`
}

func verifyChain(ctx context.Context, req *mcp.CallToolRequest, in verifyChainIn) (
	*mcp.CallToolResult, verifyChainOut, error) {

	entries, err := loadEntries(in.Path)
	if err != nil {
		return nil, verifyChainOut{}, err
	}
	res, err := verify.Chain(entries, verify.Options{MaxBreaks: 20})
	if err != nil {
		return nil, verifyChainOut{}, err
	}

	out := verifyChainOut{
		Verdict:         string(res.Verdict),
		EntriesVerified: res.EntriesVerified,
		TombstonesFound: res.TombstonesFound,
		FirstBreak:      res.FirstBreak,
		Proven:          "Nothing was edited by anyone unable to also rewrite every entry after it.",
		NotProven: "That this is the whole chain. Entries could have been removed from the " +
			"front and the rest re-linked; detecting that requires an anchor, which was " +
			"not checked here.",
	}
	for _, b := range res.Breaks {
		out.Breaks = append(out.Breaks, brk{
			Position: b.Position, EntryID: b.EntryID,
			Type: string(b.Type), Detail: b.Detail,
		})
	}
	if res.Verdict == verify.VerdictBroken && len(res.Breaks) > 1 {
		out.NotProven += " Note: one altered entry breaks every entry after it, so the " +
			"break count is a blast radius. Entry " + fmt.Sprint(res.FirstBreak) +
			" is the place to look."
	}
	return nil, out, nil
}

// ---------------------------------------------------------------------------
// compute_chain_hash
// ---------------------------------------------------------------------------

type computeChainHashIn struct {
	PreviousHash string `json:"previous_hash" jsonschema:"the preceding entry's chain hash; empty for the first entry"`
	RunID        string `json:"run_id" jsonschema:"the batch run identifier"`
	SequenceNum  int64  `json:"sequence_num" jsonschema:"position within the run (not chain-wide)"`
	Timestamp    string `json:"timestamp" jsonschema:"RFC3339 with microseconds, e.g. 2026-01-20T12:00:01.123456Z"`
	ContentHash  string `json:"content_hash" jsonschema:"128 hex characters, or a TOMBSTONE: value"`
}

type computeChainHashOut struct {
	ChainHash string `json:"chain_hash"`
	Preimage  string `json:"preimage_description"`
}

func computeChainHash(ctx context.Context, req *mcp.CallToolRequest, in computeChainHashIn) (
	*mcp.CallToolResult, computeChainHashOut, error) {

	ts, err := time.Parse(time.RFC3339Nano, in.Timestamp)
	if err != nil {
		return nil, computeChainHashOut{}, fmt.Errorf(
			"timestamp must be RFC3339 (e.g. 2026-01-20T12:00:01.123456Z): %w", err)
	}
	// The validated form: a malformed previous_hash makes the preimage ambiguous
	// and two different entries can collide. See docs/format-spec.md §3.
	hash, err := chainformat.ComputeChainHash(
		in.PreviousHash, in.RunID, in.SequenceNum, ts, in.ContentHash)
	if err != nil {
		return nil, computeChainHashOut{}, err
	}
	return nil, computeChainHashOut{
		ChainHash: hash,
		Preimage: `SHA-512("aleutian.chain.v2:" ‖ previous_hash ‖ "|" ‖ run_id ‖ "|" ‖ ` +
			`sequence_num ‖ "|" ‖ timestamp ‖ "|" ‖ content_hash)`,
	}, nil
}

// ---------------------------------------------------------------------------
// canonicalize_leaf
// ---------------------------------------------------------------------------

// canonicalizeLeafIn embeds the entry type directly rather than taking raw JSON.
//
// The MCP SDK infers a tool's input schema from this Go type, so embedding
// CaptureRequestV3 means the model is handed the real field list — names, types
// and all — instead of "send me some JSON" and a guess. It also means a
// malformed entry fails at the protocol boundary rather than inside the encoder.
type canonicalizeLeafIn struct {
	Entry chainformat.CaptureRequestV3 `json:"entry" jsonschema:"a capture.request.v3 entry"`
}

type canonicalizeLeafOut struct {
	CanonicalBytesHex string `json:"canonical_bytes_hex"`
	CanonicalByteLen  int    `json:"canonical_byte_len"`
	ContentHash       string `json:"content_hash"`
	HowToCheck        string `json:"how_to_check"`
}

func canonicalizeLeaf(ctx context.Context, req *mcp.CallToolRequest, in canonicalizeLeafIn) (
	*mcp.CallToolResult, canonicalizeLeafOut, error) {

	canonical, contentHash, err := chainformat.EncodeAndHashV3(in.Entry)
	if err != nil {
		return nil, canonicalizeLeafOut{}, err
	}
	return nil, canonicalizeLeafOut{
		CanonicalBytesHex: hex.EncodeToString(canonical),
		CanonicalByteLen:  len(canonical),
		ContentHash:       contentHash,
		HowToCheck: "content_hash is SHA-512 of the ASCII prefix " +
			`"aleutian.chain.entry.v3:" followed by these canonical bytes. ` +
			"You can reproduce it with any SHA-512 implementation; nothing about " +
			"this step requires trusting Aleutian.",
	}, nil
}

// ---------------------------------------------------------------------------
// verify_inclusion
// ---------------------------------------------------------------------------

type verifyInclusionIn struct {
	LeafContentHash string   `json:"leaf_content_hash" jsonschema:"the leaf's content hash, 128 hex characters"`
	LeafIndex       int      `json:"leaf_index" jsonschema:"zero-based position of the leaf in the tree"`
	TreeSize        int      `json:"tree_size" jsonschema:"total number of leaves"`
	ProofHex        []string `json:"proof_hex" jsonschema:"the audit path, each element hex-encoded"`
	RootHex         string   `json:"root_hex" jsonschema:"the expected Merkle root, hex-encoded"`
}

type verifyInclusionOut struct {
	Included bool   `json:"included"`
	Detail   string `json:"detail"`
}

func verifyInclusion(ctx context.Context, req *mcp.CallToolRequest, in verifyInclusionIn) (
	*mcp.CallToolResult, verifyInclusionOut, error) {

	// Leaves are hashed over the RAW bytes of the content hash, not its hex text.
	// Hashing the text produces roots nobody else reproduces.
	raw, err := hex.DecodeString(in.LeafContentHash)
	if err != nil {
		return nil, verifyInclusionOut{}, fmt.Errorf("leaf_content_hash is not hex: %w", err)
	}
	root, err := hex.DecodeString(in.RootHex)
	if err != nil {
		return nil, verifyInclusionOut{}, fmt.Errorf("root_hex is not hex: %w", err)
	}
	proof := make([][]byte, 0, len(in.ProofHex))
	for i, p := range in.ProofHex {
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, verifyInclusionOut{}, fmt.Errorf("proof element %d is not hex: %w", i, err)
		}
		proof = append(proof, b)
	}

	ok := merkle.VerifyInclusion(merkle.LeafHash(raw), in.LeafIndex, in.TreeSize, proof, root)
	detail := "The leaf is committed to by this root."
	if !ok {
		detail = "The proof does not connect this leaf to this root. Either the leaf " +
			"is not in the tree, the proof is for a different position, or the root " +
			"belongs to a different tree."
	}
	return nil, verifyInclusionOut{Included: ok, Detail: detail}, nil
}

// ---------------------------------------------------------------------------
// Hostile-input handling
// ---------------------------------------------------------------------------

// loadEntries reads an exported entries file supplied by a model.
//
// # Trust boundary
//
// The path is attacker-controlled under prompt injection. Three defences:
//
//   - `..` is refused outright, so a crafted path cannot climb out of wherever
//     the operator pointed the agent
//   - the read is size-bounded (see maxEntriesFileBytes)
//   - only regular files are opened, so a path naming a device or a FIFO fails
//     rather than blocking forever
//
// Errors deliberately do not echo file contents; a tool result is transmitted to
// a model provider, and an error message is an easy way to exfiltrate a byte at
// a time.
func loadEntries(path string) ([]verify.Entry, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("path must not contain '..'")
	}

	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("cannot read the file at that path")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path is not a regular file")
	}
	if info.Size() > maxEntriesFileBytes {
		return nil, fmt.Errorf("file exceeds the %d byte limit", int64(maxEntriesFileBytes))
	}

	raw, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("cannot read the file at that path")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("the file is empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var entries []verify.Entry
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return nil, fmt.Errorf("the file is not a valid JSON array of entries")
		}
		return entries, nil
	}
	var entries []verify.Entry
	for i, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e verify.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("line %d is not a valid entry", i+1)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// verify_anchor
// ---------------------------------------------------------------------------

type verifyAnchorIn struct {
	EntriesPath   string `json:"entries_path" jsonschema:"path to an exported entries file (JSON array or JSONL)"`
	AnchorPath    string `json:"anchor_path" jsonschema:"path to an anchor JSON file"`
	PublicKeyPath string `json:"public_key_path,omitempty" jsonschema:"optional path to a raw ML-DSA-65 public key (1952 bytes). Without it the anchor's signature is NOT checked."`
	KeyTrust      string `json:"key_trust,omitempty" jsonschema:"where the key came from: platform, provided, or self. Defaults to provided. This decides what a successful verification actually claims."`
}

type verifyAnchorOut struct {
	Outcome           string `json:"outcome"`
	Bound             bool   `json:"bound"`
	Detail            string `json:"detail,omitempty"`
	EntriesCovered    int64  `json:"entries_covered"`
	SignatureVerified bool   `json:"signature_verified"`
	Trust             string `json:"trust,omitempty"`
	TrustEstablishes  string `json:"trust_establishes,omitempty"`

	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

func verifyAnchorTool(ctx context.Context, req *mcp.CallToolRequest, in verifyAnchorIn) (
	*mcp.CallToolResult, verifyAnchorOut, error) {

	entries, err := loadEntries(in.EntriesPath)
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}
	a, err := loadAnchor(in.AnchorPath)
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}

	var res verify.BindResult
	if in.PublicKeyPath == "" {
		res, err = verify.BindAnchor(a, entries)
	} else {
		var ring *anchor.KeyRing
		ring, err = loadKeyRing(in.PublicKeyPath, in.KeyTrust, a.SigningKeyID)
		if err != nil {
			return nil, verifyAnchorOut{}, err
		}
		res, err = verify.VerifyAnchor(a, entries, ring)
	}
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}

	out := verifyAnchorOut{
		Outcome:           string(res.Outcome),
		Bound:             res.Bound,
		Detail:            res.Detail,
		EntriesCovered:    res.EntriesCovered,
		SignatureVerified: res.SignatureVerified,
		Trust:             string(res.Trust),
		Proven:            res.Proven,
		NotProven:         res.NotProven,
	}
	if res.Trust != "" {
		out.TrustEstablishes = res.Trust.Establishes()
	}
	return nil, out, nil
}

// ---------------------------------------------------------------------------
// verify_bundle
// ---------------------------------------------------------------------------

type verifyBundleIn struct {
	Dir string `json:"dir" jsonschema:"path to an export bundle directory containing manifest.json"`
}

type bundleProblem struct {
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type verifyBundleOut struct {
	Intact       bool            `json:"intact"`
	FilesChecked int             `json:"files_checked"`
	Problems     []bundleProblem `json:"problems,omitempty"`

	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

// bundleManifest is the subset of manifest.json this tool reads.
type bundleManifest struct {
	ManifestRoot string             `json:"manifest_root"`
	Files        []bundle.FileEntry `json:"files"`
}

func verifyBundleTool(ctx context.Context, req *mcp.CallToolRequest, in verifyBundleIn) (
	*mcp.CallToolResult, verifyBundleOut, error) {

	clean := filepath.Clean(in.Dir)
	raw, err := readCapped(filepath.Join(clean, "manifest.json"), maxEntriesFileBytes)
	if err != nil {
		return nil, verifyBundleOut{}, fmt.Errorf("cannot read manifest.json in that directory")
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, verifyBundleOut{}, fmt.Errorf("manifest.json is not valid JSON")
	}
	if len(m.Files) == 0 {
		return nil, verifyBundleOut{}, fmt.Errorf("manifest.json lists no files")
	}

	res, err := bundle.VerifyDir(clean, m.Files, m.ManifestRoot, 0)
	if err != nil {
		return nil, verifyBundleOut{}, err
	}

	out := verifyBundleOut{
		Intact:       res.Intact,
		FilesChecked: res.FilesChecked,
		Proven:       res.Proven,
		NotProven:    res.NotProven,
	}
	for _, p := range res.Problems {
		out.Problems = append(out.Problems, bundleProblem{
			Path: p.Path, Kind: string(p.Kind), Detail: p.Detail,
		})
	}
	return nil, out, nil
}

// ---------------------------------------------------------------------------
// explain_trust_model
// ---------------------------------------------------------------------------

type explainTrustModelIn struct{}

type trustLevelDoc struct {
	Level       string `json:"level"`
	Establishes string `json:"establishes"`
}

type explainTrustModelOut struct {
	Claims           []claimDoc      `json:"what_each_check_proves"`
	TrustLevels      []trustLevelDoc `json:"trust_levels"`
	WhyNoTrustStore  string          `json:"why_no_built_in_trust_store"`
	AnchorProvenance string          `json:"anchor_provenance_caveat"`
}

type claimDoc struct {
	Check     string `json:"check"`
	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

func explainTrustModel(ctx context.Context, req *mcp.CallToolRequest, in explainTrustModelIn) (
	*mcp.CallToolResult, explainTrustModelOut, error) {

	out := explainTrustModelOut{
		Claims: []claimDoc{
			{
				Check:     "verify_chain (linkage only)",
				Proven:    "Nothing was edited by anyone unable to also rewrite every entry after it.",
				NotProven: "That this is the whole chain. Front-truncation followed by re-linking is undetectable here.",
			},
			{
				Check:     "verify_anchor without a key",
				Proven:    "The chain in front of you is the one this anchor committed to, including where the range started — so truncation IS detected.",
				NotProven: "That the anchor is genuine. Whoever can rewrite the chain can also mint a matching unsigned anchor.",
			},
			{
				Check:     "verify_anchor with a key",
				Proven:    "The chain matches the anchor AND the anchor was signed by the holder of that key.",
				NotProven: "Anything about entries after the anchored range, or that the anchor reached you by a path its subject could not rewrite.",
			},
			{
				Check:     "verify_bundle",
				Proven:    "Every file listed in the manifest is present and its bytes match the digest claimed.",
				NotProven: "That the manifest is genuine. Whoever built the bundle could have made the files and the manifest agree.",
			},
		},
		TrustLevels: []trustLevelDoc{
			{Level: string(anchor.TrustPlatform), Establishes: anchor.TrustPlatform.Establishes()},
			{Level: string(anchor.TrustProvided), Establishes: anchor.TrustProvided.Establishes()},
			{Level: string(anchor.TrustSelf), Establishes: anchor.TrustSelf.Establishes()},
		},
		WhyNoTrustStore: "This tool ships no embedded public keys. Doing so would decide, at " +
			"build time, whose attestations count — and the premise of an offline verifier is " +
			"that the person running it need not take anyone's word for that. It would also tie " +
			"key rotation to a software release: rotate a key, and every user's verification " +
			"breaks until they upgrade. You supply keys, and you say where they came from.",
		AnchorProvenance: "A signature check answers 'was this signed by the holder of key K'. " +
			"It does not answer 'should I believe K', and it does not say where you got the " +
			"anchor. An anchor read back from the same store as the chain proves consistency; " +
			"only a copy the chain's operator cannot rewrite proves external commitment.",
	}
	return nil, out, nil
}

// ---------------------------------------------------------------------------
// shared loaders
// ---------------------------------------------------------------------------

// loadAnchor reads an anchor JSON file.
func loadAnchor(path string) (anchor.Anchor, error) {
	raw, err := readCapped(filepath.Clean(path), maxEntriesFileBytes)
	if err != nil {
		return anchor.Anchor{}, fmt.Errorf("cannot read the anchor file at that path")
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return anchor.Anchor{}, fmt.Errorf("the anchor file is not valid JSON")
	}
	return a, nil
}

// loadKeyRing reads a raw ML-DSA-65 public key and binds it to a trust level.
//
// The trust level is the caller's assertion about PROVENANCE, which this process
// cannot determine for itself. Defaulting to "provided" rather than "platform"
// is deliberate: the weaker claim is the safe default.
func loadKeyRing(path, trustLabel, keyID string) (*anchor.KeyRing, error) {
	raw, err := readCapped(filepath.Clean(path), anchor.PublicKeySize+1)
	if err != nil {
		return nil, fmt.Errorf("cannot read the public key file at that path")
	}
	trust := anchor.TrustProvided
	switch trustLabel {
	case "", string(anchor.TrustProvided):
	case string(anchor.TrustPlatform):
		trust = anchor.TrustPlatform
	case string(anchor.TrustSelf):
		trust = anchor.TrustSelf
	default:
		return nil, fmt.Errorf("key_trust must be one of: platform, provided, self")
	}
	return anchor.NewKeyRing(trust, map[string][]byte{keyID: raw})
}

// readCapped reads a regular file, refusing anything larger than cap.
func readCapped(path string, cap int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > cap {
		return nil, fmt.Errorf("file exceeds the %d byte limit", cap)
	}
	return os.ReadFile(path)
}
