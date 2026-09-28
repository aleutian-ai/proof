// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// ---------------------------------------------------------------------------
// commit — the ONE tool that writes.
//
// Every other tool on this server is read-only, so the worst a prompt injection
// could do was produce a wrong answer. This tool raises that to a wrong WRITE,
// persisted in the artefact whose integrity is the product. The design keeps
// the model's reach as narrow as possible:
//
//   - The database is fixed at launch (--db), never an argument, and so is the
//     set of chains it may write (--chains, required with --db).
//   - The model supplies only content (or a content hash), an optional label,
//     and which chain. EVERYTHING that is hashed into position — entry id,
//     timestamp, global_seq, previous hash, chain hash — is assigned here.
//   - Nonces for salted commitments are kept in a local sidecar file, never
//     returned: a model cannot keep them, and a transcript cannot be erased.
//   - It can only append. It cannot edit, reorder, remove, or import.
//
// What a committed entry proves is "this was recorded, and has not changed
// since" — not that it is true. An injected false claim is recorded as exactly
// that: a claim.
// ---------------------------------------------------------------------------

const (
	// maxCommitEntries caps one call.
	maxCommitEntries = 100

	// maxCommitContentBytes caps each entry's content, in bytes.
	maxCommitContentBytes = 64 << 10

	// Entry types are server-set, so a verifier can tell which check an entry
	// needs and an agent cannot mimic another writer's types (e.g. "tombstone"
	// or the CLI's). The caller may only append a label. ADVISORY: entry_type is
	// not part of the chain hash, so it records intent, not proof.
	entryTypeSalted = "mcp.salted" // content → salted commitment (commitment.Verify)
	entryTypeDigest = "mcp.digest" // caller's own SHA-512 (plain comparison)
)

// dbLockTimeout bounds the wait for another PROCESS holding a file. A variable
// only so tests can shorten it.
var dbLockTimeout = 2 * time.Second

// commitMu serialises commits within this server. Models issue parallel tool
// calls; without it the second would wait on the file lock and then fail as
// "busy" although no other process is involved.
var commitMu sync.Mutex

// idPattern validates chain ids: short, lowercase, safe anywhere. It rules out
// email addresses, but a NAME or a number can still pass — which is why the
// chains an agent may write are fixed by the human at launch.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// labelPattern validates the optional label appended to the entry type. The
// result, e.g. "mcp.salted.agent-action", stays within 64 characters.
var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

// contentHashPattern is a SHA-512 digest in lowercase hex.
var contentHashPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

// commitConfig is fixed by the human at launch. The zero value (no database)
// means the commit tool is not registered at all.
type commitConfig struct {
	db     string
	chains map[string]bool // nil means any valid chain: only via an explicit --chains '*'
}

type commitEntryIn struct {
	Content     *string `json:"content,omitempty" jsonschema:"the evidence as text. NOTE: it passes through this conversation, so it is visible to the model provider. The server stores only a salted commitment and keeps the nonce locally. Exactly one of content or content_hash"`
	ContentHash *string `json:"content_hash,omitempty" jsonschema:"a SHA-512 digest you computed yourself (128 lowercase hex). Use it for HIGH-ENTROPY input only, such as randomized ciphertext: a plain hash of short or predictable text can be guessed. Exactly one of content or content_hash"`
	Label       string  `json:"label,omitempty" jsonschema:"optional label appended to the entry type, e.g. agent-action (lowercase letters, digits, . _ -, max 48). Never a name, email or other identifier: it is stored permanently"`
}

type commitIn struct {
	Chain   string          `json:"chain" jsonschema:"which chain to append to: one of the chains this server was started with. A topic or a pseudonym, never a name, email or other identifier: it is stored permanently"`
	Entries []commitEntryIn `json:"entries" jsonschema:"1 to 100 entries, committed in this order, atomically"`
}

type committedEntry struct {
	EntryID     string `json:"entry_id"`
	EntryType   string `json:"entry_type"`
	GlobalSeq   string `json:"global_seq"` // decimal string: JSON numbers lose precision in transit
	Timestamp   string `json:"timestamp"`
	Commitment  string `json:"commitment"`
	NonceStored bool   `json:"nonce_stored"` // true for content entries: the nonce is in the server's local nonce file
}

type commitOut struct {
	Chain     string           `json:"chain"`
	Committed int              `json:"committed"`
	HeadHash  string           `json:"head_hash"`
	Entries   []committedEntry `json:"entries"`
	Warning   string           `json:"warning,omitempty"`
}

// commitInputSchema is the inferred schema plus explicit limits, so the SDK
// rejects an oversized request before the handler runs and a model is told the
// limits up front.
//
// It does NOT bound memory: the SDK has no stdio message-size limit, so one
// enormous message is still decoded before it is validated.
func commitInputSchema() (*jsonschema.Schema, error) {
	s, err := jsonschema.For[commitIn](nil)
	if err != nil {
		return nil, fmt.Errorf("infer commit schema: %w", err)
	}
	s.Properties["chain"].MaxLength = jsonschema.Ptr(64)
	entries := s.Properties["entries"]
	entries.MinItems = jsonschema.Ptr(1)
	entries.MaxItems = jsonschema.Ptr(maxCommitEntries)
	item := entries.Items
	// Characters, not bytes: a coarse pre-filter. The byte cap is checked below.
	item.Properties["content"].MaxLength = jsonschema.Ptr(maxCommitContentBytes)
	item.Properties["content_hash"].MaxLength = jsonschema.Ptr(128)
	item.Properties["label"].MaxLength = jsonschema.Ptr(48)
	return s, nil
}

// registerCommit adds the commit tool, and only when a database was configured.
func registerCommit(s *mcp.Server, cfg commitConfig) error {
	if cfg.db == "" {
		return nil
	}
	schema, err := commitInputSchema()
	if err != nil {
		return err
	}
	no := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "commit",
		Description: "WRITES to the evidence chain — the only tool on this server that " +
			"changes state. Appends entries to a chain permanently; nothing can be " +
			"edited or removed afterwards. Use it to record evidence of something that " +
			"happened (an action taken, a decision, a result), not to verify anything — " +
			"use the verify_* tools for that. Send each entry's content as text: the " +
			"server stores a salted commitment and keeps the nonce locally, so the entry " +
			"can be proven later by whoever runs this server. The content itself passes " +
			"through this conversation. The server assigns entry ids, timestamps and " +
			"positions. A committed entry proves the content was recorded and not changed " +
			"since, not that it is true.",
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: false, DestructiveHint: &no, IdempotentHint: false, OpenWorldHint: &no,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in commitIn) (*mcp.CallToolResult, commitOut, error) {
		return commitTool(ctx, cfg, in)
	})
	return nil
}

// prepared is one validated entry, before anything touches disk.
type prepared struct {
	input linker.Input
	nonce []byte
}

// commitTool validates everything, then commits the batch in one atomic append.
//
// All validation happens BEFORE any file is opened, so a rejected call cannot
// touch the store.
func commitTool(ctx context.Context, cfg commitConfig, in commitIn) (*mcp.CallToolResult, commitOut, error) {
	if !idPattern.MatchString(in.Chain) {
		return nil, commitOut{}, fmt.Errorf("chain must be lowercase letters, digits, . _ - " +
			"(max 64), starting with a letter or digit; use a topic or a pseudonym, never an email")
	}
	if cfg.chains != nil && !cfg.chains[in.Chain] {
		return nil, commitOut{}, fmt.Errorf("chain %q is not one this server was started to write "+
			"(see --chains)", in.Chain)
	}
	if n := len(in.Entries); n == 0 || n > maxCommitEntries {
		return nil, commitOut{}, fmt.Errorf("send between 1 and %d entries, got %d", maxCommitEntries, n)
	}

	batch := make([]prepared, len(in.Entries))
	for i, e := range in.Entries {
		p, err := prepare(i, e)
		if err != nil {
			return nil, commitOut{}, err
		}
		batch[i] = p
	}

	commitMu.Lock()
	defer commitMu.Unlock()

	st, err := boltstore.Open(cfg.db, boltstore.WithLockTimeout(dbLockTimeout))
	if err != nil {
		if errors.Is(err, boltstore.ErrLocked) {
			return nil, commitOut{}, fmt.Errorf("the evidence database is held by another " +
				"process (for example the proof CLI); nothing was committed, retry when it is done")
		}
		return nil, commitOut{}, fmt.Errorf("open the evidence database: %w", err)
	}
	defer st.Close()

	// Timestamps are taken NOW, holding the file, so entries are stamped in the
	// order they are written. Entry i gets now + i microseconds: the linker orders
	// a batch by arrival and hashes timestamps at microsecond precision. They are
	// still wall-clock and ADVISORY — global_seq is the authoritative order.
	now := time.Now().UTC().Truncate(time.Microsecond)
	inputs := make([]linker.Input, len(batch))
	nonces := map[string][]byte{}
	for i := range batch {
		stamp := now.Add(time.Duration(i) * time.Microsecond)
		batch[i].input.Timestamp, batch[i].input.IngestedAt = stamp, stamp
		inputs[i] = batch[i].input
		if batch[i].nonce != nil {
			nonces[batch[i].input.EntryID] = batch[i].nonce
		}
	}

	// Nonces are stored BEFORE the append: a nonce without an entry is harmless
	// garbage, but an entry without its nonce could never be proven.
	if len(nonces) > 0 {
		if err := storeNonces(cfg.db, in.Chain, nonces); err != nil {
			return nil, commitOut{}, err
		}
	}

	l, err := linker.New(st)
	if err != nil {
		forgetNonces(cfg.db, in.Chain, nonces)
		return nil, commitOut{}, fmt.Errorf("prepare the chain: %w", err)
	}
	res, err := l.Append(ctx, in.Chain, inputs)
	warning := ""
	switch {
	case errors.Is(err, linker.ErrHeadStateStale):
		// Committed. Say so, so the caller does not retry and commit twice.
		warning = "committed, but the saved head record was not updated; this repairs " +
			"itself on the next commit. Do not retry."
	case err != nil:
		forgetNonces(cfg.db, in.Chain, nonces)
		return nil, commitOut{}, fmt.Errorf("commit: %w; nothing was committed", err)
	}

	// Report what the STORE now holds, not what was sent: read the range back.
	rows, err := st.Range(ctx, in.Chain, res.FirstSeq, res.LastSeq, 0)
	if err != nil {
		return nil, commitOut{}, fmt.Errorf("committed, but reading it back failed: %w; do not retry", err)
	}
	out := commitOut{Chain: in.Chain, Committed: res.Appended, HeadHash: res.HeadHash, Warning: warning}
	for _, r := range rows {
		_, salted := nonces[r.EntryID]
		out.Entries = append(out.Entries, committedEntry{
			EntryID:     r.EntryID,
			EntryType:   r.EntryType,
			GlobalSeq:   strconv.FormatInt(r.GlobalSeq, 10),
			Timestamp:   r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			Commitment:  r.ContentHash,
			NonceStored: salted,
		})
	}
	return nil, out, nil
}

// prepare validates one entry and computes what will be committed. It touches
// no files. The timestamp is filled in later, under the file lock.
func prepare(i int, e commitEntryIn) (prepared, error) {
	var p prepared
	var entryType string
	switch {
	case e.Content != nil && e.ContentHash != nil:
		return p, fmt.Errorf("entry %d: send content or content_hash, not both", i)
	case e.ContentHash != nil:
		if !contentHashPattern.MatchString(*e.ContentHash) {
			return p, fmt.Errorf("entry %d: content_hash must be 128 lowercase hex characters (SHA-512)", i)
		}
		p.input.ContentHash = *e.ContentHash
		entryType = entryTypeDigest
	case e.Content != nil:
		if *e.Content == "" {
			return p, fmt.Errorf("entry %d: content is empty; there is nothing to commit", i)
		}
		if len(*e.Content) > maxCommitContentBytes {
			return p, fmt.Errorf("entry %d: content is %d bytes, over the %d byte limit",
				i, len(*e.Content), maxCommitContentBytes)
		}
		c, nonce, err := commitment.Salted([]byte(*e.Content))
		if err != nil {
			return p, fmt.Errorf("entry %d: %w", i, err)
		}
		p.input.ContentHash, p.nonce = c, nonce
		entryType = entryTypeSalted
	default:
		return p, fmt.Errorf("entry %d: send content or content_hash", i)
	}
	if e.Label != "" {
		if !labelPattern.MatchString(e.Label) {
			return p, fmt.Errorf("entry %d: label must be lowercase letters, digits, . _ - (max 48)", i)
		}
		entryType += "." + e.Label
	}
	id, err := newEntryID()
	if err != nil {
		return p, err
	}
	p.input.EntryID, p.input.EntryType = id, entryType
	return p, nil
}

// storeNonces writes a batch's nonces to the sidecar file, atomically.
func storeNonces(db, chain string, nonces map[string][]byte) error {
	ns, err := noncestore.Open(noncestore.PathFor(db), dbLockTimeout)
	if err != nil {
		return fmt.Errorf("open the nonce file: %w; nothing was committed", err)
	}
	defer ns.Close()
	if err := ns.PutBatch(chain, nonces); err != nil {
		return fmt.Errorf("store nonces: %w; nothing was committed", err)
	}
	return nil
}

// forgetNonces removes nonces whose entries were not committed. Best effort:
// an orphaned nonce opens nothing, so failing to remove it is harmless.
func forgetNonces(db, chain string, nonces map[string][]byte) {
	if len(nonces) == 0 {
		return
	}
	ns, err := noncestore.Open(noncestore.PathFor(db), dbLockTimeout)
	if err != nil {
		return
	}
	defer ns.Close()
	for id := range nonces {
		_ = ns.Delete(chain, id)
	}
}

// newEntryID returns a random id. Server-assigned so a caller can neither
// collide with an existing entry nor choose an id that means something.
func newEntryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("draw entry id: %w", err)
	}
	return "mcp-" + hex.EncodeToString(b), nil
}
