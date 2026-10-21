// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command proof-mcp exposes AleutianChain verification, and with --db a commit
// tool, over the Model Context Protocol.
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
// the loop. The guard is the exact allowlist of tool names in
// TestToolsAreTheExpectedSet and TestToolsAreTheExpectedSet_WithDB: a tool
// cannot be added without changing those lists. TestNoKeyMaterialTools is a
// second, coarser check on tool names; it catches a careless addition and can
// be passed by choosing a different name.
//
// # Trust boundary
//
// Every argument arrives from a model and must be treated as attacker-controlled
// under prompt injection.
//
//   - A path in a tool call must be inside one directory, --root (default: the
//     working directory at launch). A relative path is relative to it; an
//     absolute path must be under it. Files are opened through os.Root, which
//     refuses a symbolic link that leaves the root. A path outside the root
//     gets one fixed error whatever is or is not there. See paths.go.
//   - Reads are size-bounded, and errors never include file contents.
//   - What a key establishes (platform, provided, self) is never an argument.
//     A key named in a tool call is "provided"; only --trusted-key, set at
//     launch, binds a key to another level. See trust.go.
//   - Nothing is shelled out.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/bundle"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/exportbundle"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/merkle"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// defaultMaxDBBytes is the default for --max-db-bytes.
const defaultMaxDBBytes = 1 << 30

// serverConfig is fixed by the human at launch. No tool call can change it.
type serverConfig struct {
	// root is the only directory tree a path in a tool call may name.
	root fileRoot

	// trusted holds the public keys bound to a trust level with --trusted-key.
	trusted []trustedKey

	// bundleTrust holds the keys verify_export_bundle trusts, from
	// --bundle-checkpoint-key and --bundle-record-trust.
	bundleTrust exportbundle.Trust

	// db is the evidence database the commit tool writes. Empty means the commit
	// tool is not registered at all.
	db     string
	chains map[string]bool // nil means any valid chain: only via an explicit --chains '*'

	// maxDBBytes refuses a commit once the database file has reached this size.
	// 0 means no limit.
	maxDBBytes int64
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("proof-mcp: %v", err)
	}
}

func run() error {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "aleutianchain",
		Version: serverVersion(),
	}, nil)

	if err := registerTools(server, cfg); err != nil {
		return err
	}

	return server.Run(context.Background(), &mcp.StdioTransport{})
}

// parseFlags reads the launch-time configuration.
//
// These are the HUMAN's choices, made when the server is registered with a
// client. None of them can be set by a tool call. Without --db the server is
// read-only: the commit tool is not registered at all.
//
// Diagnostics go to stderr: stdout carries the JSON-RPC stream.
func parseFlags(args []string) (serverConfig, error) {
	fs := flag.NewFlagSet("proof-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rootDir := fs.String("root", "", "the only directory tool calls may read files from (default: the working directory)")
	var trusted trustedKeyFlag
	fs.Var(&trusted, "trusted-key", "LEVEL=PATH: bind a PEM ML-DSA-65 public key to a trust level, platform or self; "+
		"repeatable. A key named in a tool call is always 'provided'")
	var bundleCheckpoint, bundleRecord bundleKeyFlag
	fs.Var(&bundleCheckpoint, "bundle-checkpoint-key", "PATH: a PEM ML-DSA-65 public key verify_export_bundle "+
		"trusts for checkpoints; repeatable")
	fs.Var(&bundleRecord, "bundle-record-trust", "PATH: a PEM ML-DSA-65 public key verify_export_bundle "+
		"trusts for record signatures; repeatable")
	db := fs.String("db", "", "evidence database the commit tool writes to; omit for a read-only server")
	chains := fs.String("chains", "", "chains commit may write, comma-separated; required with --db. '*' allows any valid chain id")
	maxDBBytes := fs.Int64("max-db-bytes", defaultMaxDBBytes, "with --db: refuse commits once the database file "+
		"has reached this many bytes; 0 means no limit")
	if err := fs.Parse(args); err != nil {
		return serverConfig{}, err
	}
	if fs.NArg() > 0 {
		return serverConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	if *rootDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return serverConfig{}, fmt.Errorf("--root: cannot determine the working directory: %w", err)
		}
		*rootDir = wd
	}
	root, err := newFileRoot(*rootDir)
	if err != nil {
		return serverConfig{}, fmt.Errorf("--root: %w", err)
	}

	cfg := serverConfig{root: root, trusted: trusted.keys, db: *db,
		bundleTrust: exportbundle.Trust{Checkpoint: bundleCheckpoint.keys, Record: bundleRecord.keys}}
	for _, ck := range cfg.bundleTrust.Checkpoint {
		for _, rk := range cfg.bundleTrust.Record {
			if ck.ID() == rk.ID() {
				fmt.Fprintf(os.Stderr, "proof-mcp: warning: key %s is trusted for checkpoints and for "+
					"records: one compromise forges both\n", ck.ID())
			}
		}
	}
	if *chains != "" && *db == "" {
		return serverConfig{}, fmt.Errorf("--chains only applies with --db")
	}
	if *db != "" && *chains == "" {
		// An explicit choice, not a default: without it, an injected prompt could
		// append to any chain in the file, including ones the CLI writes.
		return serverConfig{}, fmt.Errorf("--db requires --chains: name the chains agents may " +
			"write (e.g. --chains agent-actions,payments), or '*' to allow any")
	}
	if *chains != "" && *chains != "*" {
		cfg.chains = map[string]bool{}
		for _, c := range strings.Split(*chains, ",") {
			c = strings.TrimSpace(c)
			if !idPattern.MatchString(c) {
				return serverConfig{}, fmt.Errorf("--chains: %q is not a valid chain id "+
					"(lowercase letters, digits, . _ -, max 64)", c)
			}
			cfg.chains[c] = true
		}
	}
	if *maxDBBytes < 0 {
		return serverConfig{}, fmt.Errorf("--max-db-bytes must not be negative; 0 means no limit")
	}
	if *db != "" {
		cfg.maxDBBytes = *maxDBBytes
	} else if *maxDBBytes != defaultMaxDBBytes {
		return serverConfig{}, fmt.Errorf("--max-db-bytes only applies with --db")
	}
	if cfg.db != "" {
		// Fail at launch, not on the first tool call: open (creating it if needed)
		// and close again. Each commit reopens, so the CLI can share the file.
		st, err := boltstore.Open(cfg.db, boltstore.WithLockTimeout(dbLockTimeout))
		if err != nil {
			return serverConfig{}, fmt.Errorf("--db %s: %w", cfg.db, err)
		}
		if err := st.Close(); err != nil {
			return serverConfig{}, fmt.Errorf("--db %s: %w", cfg.db, err)
		}
		ns, err := noncestore.Open(noncestore.PathFor(cfg.db), dbLockTimeout)
		if err != nil {
			return serverConfig{}, fmt.Errorf("--db %s: nonce file: %w", cfg.db, err)
		}
		if err := ns.Close(); err != nil {
			return serverConfig{}, fmt.Errorf("--db %s: nonce file: %w", cfg.db, err)
		}
	}
	return cfg, nil
}

// registerTools wires every tool.
//
// Kept separate from run so tests can enumerate what is registered without
// starting a server — see TestToolsAreTheExpectedSet.
func registerTools(s *mcp.Server, cfg serverConfig) error {
	// readOnly marks every tool except commit. TestExactlyOneToolWrites pins it.
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}

	inclusionSchema, err := verifyInclusionInputSchema()
	if err != nil {
		return err
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_chain",
		Annotations: readOnly,
		Description: "Verify an exported audit chain. Reports whether the linkage is " +
			"intact and, if not, the index of the FIRST break. Note the result " +
			"distinguishes consistency (nothing was edited) from existence (this is " +
			"the same chain) — only the first is provable without an anchor. The file " +
			"must be inside the directory this server was started with.",
	}, cfg.verifyChain)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "compute_chain_hash",
		Annotations: readOnly,
		Description: "Compute the chain hash for one entry's fields. format_version is " +
			"required: 3 for chains written by proof commit (binds global_seq), 2 for " +
			"older chains (binds run_id and sequence_num). Sequence numbers are decimal " +
			"strings, not JSON numbers.",
	}, computeChainHash)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "canonicalize_leaf",
		Annotations: readOnly,
		Description: "Show the exact canonical bytes a capture entry hashes to, as " +
			"hex, alongside its content hash. This is the 'show your work' tool: it " +
			"lets a skeptic re-hash the bytes themselves rather than trusting the " +
			"encoder.",
	}, canonicalizeLeaf)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_inclusion",
		Annotations: readOnly,
		InputSchema: inclusionSchema,
		Description: "Verify that a leaf belongs to a Merkle tree with a given root, " +
			"using an inclusion proof.",
	}, verifyInclusion)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_anchor",
		Annotations: readOnly,
		Description: "Check an exported chain against an anchor. This is what detects " +
			"TRUNCATION, which chain verification alone cannot: a chain with entries " +
			"removed from the front and the rest re-linked verifies as intact. Without " +
			"a public key this binds the chain to the anchor but does NOT establish " +
			"that the anchor is genuine; supply public_key_path for that. A key you " +
			"supply is reported as trust 'provided'. You cannot set the trust level: " +
			"only a key the server was started with (--trusted-key) is reported as " +
			"'platform' or 'self'. Files must be inside the directory this server was " +
			"started with.",
	}, cfg.verifyAnchor)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_bundle",
		Annotations: readOnly,
		Description: "Verify a directory bundle (a manifest.json plus the files it lists; " +
			"not a sink export bundle.json, which `proof sink verify-bundle` checks): recompute the manifest root " +
			"over the inventory, and re-hash every listed file to confirm the bytes on " +
			"disk match what the manifest claims. Reports every problem found, not just " +
			"the first. The directory must be inside the directory this server was " +
			"started with.",
	}, cfg.verifyBundle)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_export_bundle",
		Annotations: readOnly,
		Description: "Verify a sink export bundle (bundle.json, from `proof sink export`): that every " +
			"chain links, every disclosed record matches what was committed, and every entry is " +
			"authenticated by a key this server was started with. The keys are set at launch " +
			"(--bundle-checkpoint-key, --bundle-record-trust) and cannot be named in a call: with none, " +
			"a consistent bundle is 'unauthenticated', never 'ok'. Reports problem codes and indexes, " +
			"never values from the bundle. The file must be inside the directory this server was " +
			"started with.",
	}, cfg.verifyExportBundle)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "explain_trust_model",
		Annotations: readOnly,
		Description: "Explain what a verification result does and does not prove, and " +
			"why this tool ships no built-in trust store. Call this when a user asks " +
			"whether a chain is 'trusted', 'valid', or 'proven' — those words hide a " +
			"distinction that matters.",
	}, explainTrustModel)

	return registerCommit(s, cfg)
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

type verifyChainIn struct {
	Path string `json:"path" jsonschema:"path to an exported entries file (JSON array or JSONL), inside the directory this server was started with"`
}

type verifyChainOut struct {
	Verdict         string `json:"verdict"`
	EntriesVerified int    `json:"entries_verified"`
	TombstonesFound int    `json:"tombstones_found"`
	LastTombstone   int    `json:"last_tombstone"` // index of the last v2/v3 tombstone, -1 if none
	ErasedFound     int    `json:"erased_found"`   // v4 entries carrying erased: true
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

func (c serverConfig) verifyChain(ctx context.Context, req *mcp.CallToolRequest, in verifyChainIn) (
	*mcp.CallToolResult, verifyChainOut, error) {

	entries, err := c.loadEntries(in.Path)
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
		LastTombstone:   res.LastTombstone,
		ErasedFound:     res.ErasedFound,
		FirstBreak:      res.FirstBreak,
	}
	out.Proven, out.NotProven = chainClaims(res)
	for _, b := range res.Breaks {
		out.Breaks = append(out.Breaks, brk{
			Position: b.Position, EntryID: b.EntryID,
			Type: string(b.Type), Detail: b.Detail,
		})
	}
	return nil, out, nil
}

// notWholeChain is what linkage alone can never show.
const notWholeChain = "that this is the whole chain. Entries could have been removed from the " +
	"front and the rest re-linked; detecting that requires an anchor, which was " +
	"not checked here."

// chainClaims words what a verify_chain result proves and does not prove.
//
// The claim depends on the verdict. A broken chain proves nothing. An intact
// chain that holds a v2/v3 tombstone proves something only about the entries
// after the last one: a tombstone's chain hash is taken as stored, so nothing
// links the entries before it to the entries after it. See
// docs/verification-model.md, "What a tombstone leaves unverified". A v4
// erasure keeps every link checked, and is itself unauthenticated.
func chainClaims(res verify.Result) (proven, notProven string) {
	proven, notProven = linkageClaims(res)
	if res.Verdict != verify.VerdictBroken && res.ErasedFound > 0 {
		notProven += " " + erasureNotProven(res.ErasedFound)
	}
	return proven, notProven
}

// erasureNotProven is what n erased v4 entries leave unproven, as `proof
// verify` says it.
func erasureNotProven(n int) string {
	return fmt.Sprintf("Also not proven: who erased the %d erased entries, or that they were allowed to. "+
		"An erasure is not authenticated by the chain: whoever can write the store can erase a "+
		"live entry and the chain still verifies. erased: true says the export withholds the "+
		"entry's fields, not why.", n)
}

func linkageClaims(res verify.Result) (proven, notProven string) {
	switch {
	case res.Verdict == verify.VerdictBroken:
		proven = "Nothing. The chain does not verify."
		notProven = fmt.Sprintf("That any entry is unedited: the chain does not verify, and "+
			"the first break is at entry %d.", res.FirstBreak)
		if len(res.Breaks) > 1 {
			notProven += fmt.Sprintf(" Note: one altered entry breaks every entry after it, so "+
				"the break count is a blast radius. Entry %d is the place to look.", res.FirstBreak)
		}
	case res.TombstonesFound > 0:
		proven = fmt.Sprintf("Nothing after entry %d, the last v2/v3 tombstone, was edited by anyone "+
			"unable to also rewrite every entry after it.", res.LastTombstone)
		notProven = fmt.Sprintf("That entries 0 to %d are unedited: they are not verified. A "+
			"tombstone's chain hash is taken as stored, so whoever can write the chain can "+
			"replace everything up to and including it. Also not proven: ", res.LastTombstone) +
			notWholeChain
	default:
		proven = "Nothing was edited by anyone unable to also rewrite every entry after it."
		notProven = "T" + notWholeChain[1:]
	}
	return proven, notProven
}

// ---------------------------------------------------------------------------
// compute_chain_hash
// ---------------------------------------------------------------------------

// computeChainHashIn takes any of the three formats. The caller must say which.
//
// Sequence numbers are decimal STRINGS: the MCP SDK routes arguments through a
// map[string]any, so a JSON number becomes a float64 and anything above 2^53 is
// silently changed before it reaches this struct.
type computeChainHashIn struct {
	FormatVersion int    `json:"format_version" jsonschema:"REQUIRED: 4 for chains written by proof commit, 3 or 2 for older chains"`
	PreviousHash  string `json:"previous_hash" jsonschema:"the preceding entry's chain hash; empty for the first entry"`
	Timestamp     string `json:"timestamp" jsonschema:"RFC3339 with microseconds, e.g. 2026-01-20T12:00:01.123456Z"`
	ContentHash   string `json:"content_hash,omitempty" jsonschema:"128 hex characters (v2 and v3: or a TOMBSTONE: value); omitted for an erased v4 entry"`

	// v3 and v4, and required for both.
	GlobalSeq string `json:"global_seq,omitempty" jsonschema:"v3 and v4, required: chain-wide sequence number as a decimal string, e.g. \"4\""`

	// v4 only. A live entry gives entry_id, entry_type, content_hash and salt,
	// and the leaf hash is computed; an erased entry gives leaf_hash alone.
	EntryID   string `json:"entry_id,omitempty" jsonschema:"v4 live entry: the entry id, exactly as stored"`
	EntryType string `json:"entry_type,omitempty" jsonschema:"v4 live entry: the entry type, exactly as stored"`
	Salt      string `json:"salt,omitempty" jsonschema:"v4 live entry: the salt, 64 hex characters"`
	LeafHash  string `json:"leaf_hash,omitempty" jsonschema:"v4 erased entry: the stored leaf hash, instead of entry_id, entry_type, content_hash and salt"`

	// v2 only, and required for v2.
	RunID       string `json:"run_id,omitempty" jsonschema:"v2 only: the batch run identifier"`
	SequenceNum string `json:"sequence_num,omitempty" jsonschema:"v2 only, required: position within the run as a decimal string, e.g. \"3\""`
}

type computeChainHashOut struct {
	ChainHash string `json:"chain_hash"`
	LeafHash  string `json:"leaf_hash,omitempty"`

	FormatVersion int    `json:"format_version"`
	Preimage      string `json:"preimage_description"`
}

const (
	preimageV2 = `SHA-512("aleutian.chain.v2:" ‖ previous_hash ‖ "|" ‖ run_id ‖ "|" ‖ ` +
		`sequence_num ‖ "|" ‖ timestamp ‖ "|" ‖ content_hash)`
	preimageV3 = `SHA-512("aleutian.chain.v3:" ‖ previous_hash ‖ "|" ‖ global_seq ‖ "|" ‖ ` +
		`timestamp ‖ "|" ‖ content_hash)`
	preimageV4 = `SHA-512("aleutian.chain.v4:" ‖ previous_hash ‖ "|" ‖ global_seq ‖ "|" ‖ ` +
		`timestamp ‖ "|" ‖ leaf_hash), leaf_hash = SHA-512("aleutian.chain.leaf.v4:" ‖ len(entry_id) ‖ ` +
		`entry_id ‖ len(entry_type) ‖ entry_type ‖ content_hash ‖ salt), len a 4-byte big-endian byte count`
)

// parseSeq reads a decimal sequence string.
//
// An empty string is "absent" and yields (0, false, nil); the caller decides
// whether that is legal for the format. Anything non-numeric or out of int64
// range is an error, never a silent zero.
func parseSeq(field, s string) (int64, bool, error) {
	if s == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("%s must be a decimal integer that fits in int64, got %q", field, s)
	}
	if n < 0 {
		return 0, false, fmt.Errorf("%s must not be negative, got %d", field, n)
	}
	return n, true, nil
}

func computeChainHash(ctx context.Context, req *mcp.CallToolRequest, in computeChainHashIn) (
	*mcp.CallToolResult, computeChainHashOut, error) {

	ts, err := time.Parse(time.RFC3339Nano, in.Timestamp)
	if err != nil {
		return nil, computeChainHashOut{}, fmt.Errorf(
			"timestamp must be RFC3339 (e.g. 2026-01-20T12:00:01.123456Z): %w", err)
	}

	seqNum, haveSeqNum, err := parseSeq("sequence_num", in.SequenceNum)
	if err != nil {
		return nil, computeChainHashOut{}, err
	}
	globalSeq, haveGlobalSeq, err := parseSeq("global_seq", in.GlobalSeq)
	if err != nil {
		return nil, computeChainHashOut{}, err
	}

	// The checked ComputeChainHash* are used, not the Unchecked variants: a
	// malformed previous_hash makes the preimage ambiguous (format-spec §3), and a
	// single-shot tool should say so rather than hash it.
	v4Only := in.EntryID != "" || in.EntryType != "" || in.Salt != "" || in.LeafHash != ""
	if v4Only && in.FormatVersion != chainformat.FormatV4 {
		return nil, computeChainHashOut{}, fmt.Errorf(
			"entry_id, entry_type, salt and leaf_hash are v4 inputs; format_version %d hashes none of them",
			in.FormatVersion)
	}
	switch in.FormatVersion {
	case chainformat.FormatV4:
		if in.RunID != "" || seqNum != 0 {
			return nil, computeChainHashOut{}, fmt.Errorf(
				"format_version 4 does not bind run_id or sequence_num; remove them")
		}
		if !haveGlobalSeq {
			return nil, computeChainHashOut{}, fmt.Errorf("global_seq is required for format_version 4")
		}
		leaf := in.LeafHash
		if leaf != "" {
			if in.EntryID != "" || in.EntryType != "" || in.ContentHash != "" || in.Salt != "" {
				return nil, computeChainHashOut{}, fmt.Errorf("an erased v4 entry gives leaf_hash alone; " +
					"a live one gives entry_id, entry_type, content_hash and salt, and no leaf_hash")
			}
		} else if leaf, err = chainformat.ComputeLeafHashV4(in.EntryID, in.EntryType, in.ContentHash, in.Salt); err != nil {
			return nil, computeChainHashOut{}, err
		}
		hash, err := chainformat.ComputeChainHashV4(in.PreviousHash, globalSeq, ts, leaf)
		if err != nil {
			return nil, computeChainHashOut{}, err
		}
		return nil, computeChainHashOut{
			ChainHash: hash, LeafHash: leaf, FormatVersion: chainformat.FormatV4, Preimage: preimageV4,
		}, nil

	case chainformat.FormatV2:
		if haveGlobalSeq {
			return nil, computeChainHashOut{}, fmt.Errorf(
				"format_version 2 does not use global_seq; v2 binds run_id and sequence_num")
		}
		if !haveSeqNum {
			// 0 is a real position, so a missing value is an error, not a default.
			return nil, computeChainHashOut{}, fmt.Errorf("sequence_num is required for format_version 2")
		}
		hash, err := chainformat.ComputeChainHash(in.PreviousHash, in.RunID, seqNum, ts, in.ContentHash)
		if err != nil {
			return nil, computeChainHashOut{}, err
		}
		return nil, computeChainHashOut{
			ChainHash: hash, FormatVersion: chainformat.FormatV2, Preimage: preimageV2,
		}, nil

	case chainformat.FormatV3:
		// Refused on value, not presence: export rows always carry run_id "" and
		// sequence_num 0, and copying one should work.
		if in.RunID != "" || seqNum != 0 {
			return nil, computeChainHashOut{}, fmt.Errorf(
				"format_version 3 does not bind run_id or sequence_num; remove them")
		}
		if !haveGlobalSeq {
			// 0 is a real sequence number, so a missing value is an error, not a default.
			return nil, computeChainHashOut{}, fmt.Errorf("global_seq is required for format_version 3")
		}
		hash, err := chainformat.ComputeChainHashV3(in.PreviousHash, globalSeq, ts, in.ContentHash)
		if err != nil {
			return nil, computeChainHashOut{}, err
		}
		return nil, computeChainHashOut{
			ChainHash: hash, FormatVersion: chainformat.FormatV3, Preimage: preimageV3,
		}, nil

	default:
		return nil, computeChainHashOut{}, fmt.Errorf(
			"format_version must be 4, 3 or 2, got %d", in.FormatVersion)
	}
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

// maxInclusionProofNodes bounds verify_inclusion's proof array.
const maxInclusionProofNodes = 63

// verifyInclusionInputSchema is the inferred schema plus explicit limits, so the
// SDK rejects an oversized proof before the handler runs and a model is told
// the limits up front. The handler keeps its own check on the proof length.
//
// Every hash is SHA-512, so no hex value is longer than 128 characters.
func verifyInclusionInputSchema() (*jsonschema.Schema, error) {
	s, err := jsonschema.For[verifyInclusionIn](nil)
	if err != nil {
		return nil, fmt.Errorf("infer verify_inclusion schema: %w", err)
	}
	const maxHashHex = 2 * merkle.HashSize
	s.Properties["leaf_content_hash"].MaxLength = jsonschema.Ptr(maxHashHex)
	s.Properties["root_hex"].MaxLength = jsonschema.Ptr(maxHashHex)
	s.Properties["leaf_index"].Minimum = jsonschema.Ptr(0.0)
	s.Properties["tree_size"].Minimum = jsonschema.Ptr(0.0)
	proof := s.Properties["proof_hex"]
	proof.MaxItems = jsonschema.Ptr(maxInclusionProofNodes)
	proof.Items.MaxLength = jsonschema.Ptr(maxHashHex)
	return s, nil
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
	// A proof has one node per level, and a tree of at most 2^63 leaves has at
	// most 63 levels. Anything longer cannot verify; refuse it before decoding.
	if len(in.ProofHex) > maxInclusionProofNodes {
		return nil, verifyInclusionOut{}, fmt.Errorf("proof_hex has %d elements; an inclusion proof has at most %d",
			len(in.ProofHex), maxInclusionProofNodes)
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
// The path is attacker-controlled under prompt injection. The file is read by
// fileRoot.read: inside the root only, a regular file only, and size-bounded
// (see maxEntriesFileBytes).
//
// Errors deliberately do not echo file contents, and the JSON decoder's own
// error is never passed on: a tool result is transmitted to a model provider,
// and an error message is an easy way to exfiltrate a byte at a time.
func (c serverConfig) loadEntries(path string) ([]verify.Entry, error) {
	if path == "" {
		return nil, fmt.Errorf("the path to the entries file is required")
	}
	raw, err := c.root.read(path, maxEntriesFileBytes)
	if err != nil {
		return nil, err
	}
	// The same strict decoder the CLI uses: a file that is not entries is an
	// error, never a chain to report as broken, and its errors quote no value.
	entries, err := verify.DecodeEntries(raw)
	if err != nil {
		return nil, fmt.Errorf("the file is not exported entries: %w", err)
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// verify_anchor
// ---------------------------------------------------------------------------

type verifyAnchorIn struct {
	EntriesPath   string `json:"entries_path" jsonschema:"path to an exported entries file (JSON array or JSONL)"`
	AnchorPath    string `json:"anchor_path" jsonschema:"path to an anchor JSON file"`
	PublicKeyPath string `json:"public_key_path,omitempty" jsonschema:"optional path to a PEM-encoded ML-DSA-65 public key, as proof keygen writes it. Without it the signature is checked only against keys the server was started with, if any. The trust level is not an argument: a key supplied here is 'provided' unless the server was started with that same key"`

	// An anchor commits to its predecessor's chain hash, and names its
	// predecessor only by id — so the hash cannot be recovered from the anchor
	// being checked. Without it, only the FIRST anchor in a chain can be
	// verified, and every later one comes back looking like tamper evidence.
	PreviousAnchorHash string `json:"previous_anchor_hash,omitempty" jsonschema:"the previous anchor's chain_hash (128 lowercase hex). For a v7 anchor, optional: the anchor signs its own, and when given it must match. For an older anchor, required unless it is the first in its chain: omitting it for a later one reports a head mismatch, which looks like tampering but is not."`

	// The anchor's signature proves who signed it, not what it is about. Without
	// an expected subject, a genuine anchor for another chain binds too.
	Subject string `json:"subject,omitempty" jsonschema:"the subject the anchor must be for. Optional; when omitted the result's not_proven says the subject was not checked, and a genuine anchor for another chain would bind"`
}

type verifyAnchorOut struct {
	Outcome string `json:"outcome"`
	Bound   bool   `json:"bound"`

	// AssumedGenesis records that no previous_anchor_hash was supplied, so the
	// anchor was checked as if it were the first in its chain. A reader seeing
	// a head mismatch alongside this knows to suspect the missing input before
	// suspecting an attacker.
	AssumedGenesis bool   `json:"assumed_genesis,omitempty"`
	SubjectChecked bool   `json:"subject_checked"`
	Detail         string `json:"detail,omitempty"`
	EntriesCovered int64  `json:"entries_covered"`

	// Tombstones is how many v2/v3 tombstones the chain holds. EntriesNotBound
	// is how many entries, counted from the first, the anchor does not bind:
	// every entry up to and including the last tombstone. ErasedFound is how
	// many v4 entries are erased; they are bound like any other.
	Tombstones      int   `json:"tombstones"`
	EntriesNotBound int64 `json:"entries_not_bound"`
	ErasedFound     int   `json:"erased_found"`

	SignatureVerified bool `json:"signature_verified"`

	// Trust is decided by this server, never by the caller: "provided" for a key
	// named in the call, or the level a matching key was bound to at launch.
	Trust            string `json:"trust,omitempty"`
	TrustEstablishes string `json:"trust_establishes,omitempty"`

	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

func (c serverConfig) verifyAnchor(ctx context.Context, req *mcp.CallToolRequest, in verifyAnchorIn) (
	*mcp.CallToolResult, verifyAnchorOut, error) {

	entries, err := c.loadEntries(in.EntriesPath)
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}
	a, err := c.loadAnchor(in.AnchorPath)
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}

	// Default to the genesis sentinel, because that is the only predecessor a
	// caller who supplied none could have meant. The tool reports which
	// assumption it made, so a head mismatch on a chained anchor is traceable to
	// the missing input rather than read as evidence of tampering.
	// A v7 anchor carries its predecessor's hash, so nothing is assumed for it.
	expect := verify.Expect{Subject: in.Subject, PreviousAnchorHash: in.PreviousAnchorHash}
	assumedGenesis := false
	if expect.PreviousAnchorHash == "" && a.Version != anchor.SequenceRangeVersion {
		expect.PreviousAnchorHash, assumedGenesis = anchor.SeedAnchorHash, true
	}

	// Which key, and what it establishes, is decided here and never by the call.
	// A key named in the call is "provided" unless the human bound those same
	// bytes to a level at launch. With no key named, the keys bound at launch are
	// tried; if none verifies the signature, the result is a keyless bind.
	var ring *anchor.KeyRing
	if in.PublicKeyPath != "" {
		pub, err := c.loadPublicKey(in.PublicKeyPath)
		if err != nil {
			return nil, verifyAnchorOut{}, err
		}
		ring, err = anchor.NewKeyRing(c.trustOf(pub), map[string][]byte{a.SigningKeyID: pub})
		if err != nil {
			return nil, verifyAnchorOut{}, err
		}
	} else {
		ring = c.trustedKeyRing(a)
	}

	var res verify.BindResult
	if ring == nil {
		res, err = verify.BindAnchor(a, entries, expect)
	} else {
		res, err = verify.VerifyAnchor(a, entries, expect, ring)
	}
	if err != nil {
		return nil, verifyAnchorOut{}, err
	}

	out := verifyAnchorOut{
		Outcome:           string(res.Outcome),
		Bound:             res.Bound,
		AssumedGenesis:    assumedGenesis,
		SubjectChecked:    res.SubjectChecked,
		Detail:            res.Detail,
		EntriesCovered:    res.EntriesCovered,
		Tombstones:        res.Tombstones,
		EntriesNotBound:   res.EntriesNotBound,
		SignatureVerified: res.SignatureVerified,
		Trust:             string(res.Trust),
		Proven:            res.Proven,
		NotProven:         res.NotProven,
	}
	if res.Trust != "" {
		out.TrustEstablishes = res.Trust.Establishes()
	}
	for _, e := range entries {
		if e.FormatVersion == chainformat.FormatV4 && e.Erased {
			out.ErasedFound++
		}
	}
	if out.ErasedFound > 0 {
		out.NotProven = strings.TrimSpace(out.NotProven + " " + erasureNotProven(out.ErasedFound))
	}
	if ring == nil && len(c.trusted) > 0 {
		// Say so, or a reader assumes the keys the server holds were not tried.
		out.NotProven = strings.TrimSpace(out.NotProven + " Note: the signature does not verify " +
			"under any key this server was started with (--trusted-key).")
	}
	return nil, out, nil
}

// loadAnchor reads an anchor JSON file named in a tool call.
//
// A file that does not parse is reported as not valid JSON and nothing more.
// The decoder's own error quotes the offending bytes, and this error is returned
// to a model.
func (c serverConfig) loadAnchor(path string) (anchor.Anchor, error) {
	if path == "" {
		return anchor.Anchor{}, fmt.Errorf("anchor_path is required")
	}
	raw, err := c.root.read(path, maxEntriesFileBytes)
	if err != nil {
		return anchor.Anchor{}, err
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return anchor.Anchor{}, fmt.Errorf("%s is not valid JSON for an anchor", path)
	}
	return a, nil
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

// maxBundleManifestFiles caps how many files one verify_bundle call will hash.
// Each listed file costs an open and a read of up to the bundle package's
// per-file limit, so the count has to be bounded as well as the manifest's size.
const maxBundleManifestFiles = 10_000

func (c serverConfig) verifyBundle(ctx context.Context, req *mcp.CallToolRequest, in verifyBundleIn) (
	*mcp.CallToolResult, verifyBundleOut, error) {

	if in.Dir == "" {
		return nil, verifyBundleOut{}, fmt.Errorf("dir is required")
	}
	// The manifest is read first, through the root: that is what refuses a
	// directory outside it, or one reached by a symbolic link that leaves it.
	raw, err := c.root.read(filepath.Join(in.Dir, "manifest.json"), maxEntriesFileBytes)
	if err != nil {
		return nil, verifyBundleOut{}, err
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, verifyBundleOut{}, fmt.Errorf("manifest.json is not valid JSON")
	}
	if len(m.Files) == 0 {
		return nil, verifyBundleOut{}, fmt.Errorf("manifest.json lists no files")
	}
	if len(m.Files) > maxBundleManifestFiles {
		return nil, verifyBundleOut{}, fmt.Errorf("manifest.json lists %d files; this tool verifies "+
			"at most %d", len(m.Files), maxBundleManifestFiles)
	}

	// The directory is opened through the launch root, and VerifyDir reads
	// every listed file through it: nothing can be reached outside the root.
	dir, err := c.root.openDir(in.Dir)
	if err != nil {
		return nil, verifyBundleOut{}, err
	}
	defer dir.Close()
	res, err := bundle.VerifyDir(dir, m.Files, m.ManifestRoot, 0)
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
				Check:  "verify_chain (linkage only)",
				Proven: "Nothing was edited by anyone unable to also rewrite every entry after it.",
				NotProven: "That this is the whole chain. Front-truncation followed by re-linking is undetectable here. " +
					"Nor, in a v2 or v3 chain, anything about entries up to and including a tombstone: its chain hash is taken as stored. " +
					"A v4 erasure keeps every link checked, but is not authenticated: whoever can write the store can erase. " +
					"A chain that does not verify proves nothing.",
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
				Check: "verify_export_bundle",
				Proven: "Every chain in the sink export links, every disclosed record matches what was committed, " +
					"and every entry is authenticated by a key the person who launched this server trusts.",
				NotProven: "That the bundle holds every chain or every entry, that erased content is gone anywhere, " +
					"that a timestamp is true time, or that a record's content is true (a model's output can be " +
					"recorded faithfully and still be wrong). Nothing against a writer holding every trusted key.",
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
			"breaks until they upgrade. Keys come from two places, and the trust level " +
			"follows the place, never an argument: a key named in a verify_anchor call is " +
			"always 'provided'; a key the person who launched this server bound with " +
			"--trusted-key is 'platform' or 'self', as they declared. A tool call cannot " +
			"raise a key's level.",
		AnchorProvenance: "A signature check answers 'was this signed by the holder of key K'. " +
			"It does not answer 'should I believe K', and it does not say where you got the " +
			"anchor. An anchor read back from the same store as the chain proves consistency; " +
			"only a copy the chain's operator cannot rewrite proves external commitment.",
	}
	return nil, out, nil
}
