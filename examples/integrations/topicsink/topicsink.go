// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package topicsink commits a keyed stream to one proof chain per key.
//
// Logging and streaming tools split their data by key: a user, a topic, a
// tenant. topicsink keeps that split. Each key gets its own chain, all in one
// file, and each chain is checkpointed, verified and erased on its own. The
// service examples (NATS, Redis Streams, Kafka, OpenTelemetry, log shippers) put
// a consumer in front of this package and nothing else.
//
//	records ──► ChainFor(key) ──► Commit ──► evidence.db          one chain per key
//	                              (salted)   evidence.db.nonces   the secret half, per entry
//	                                         content/<chain>/     the events themselves
//	            Checkpoint ─────────────────► anchors/<chain>/    one signed checkpoint series per chain
//	            Verify: every chain, on its own
//	            Erase(chain): content and nonces gone; the chain still verifies
//
// Every event is committed as a salted commitment (package commitment): the
// chain holds a fingerprint that cannot be reversed or guessed, even for short
// or predictable events, so the chain file can be shared. The event itself and
// its nonce stay in this folder.
//
// # Erasure
//
// Erase deletes a chain's events and their nonces, so none of them can ever be
// opened again. It first commits an erasure entry to that chain, so the erasure
// is itself on the record: Verify reports entries before an erasure entry as
// ERASED, and an event missing with no erasure entry after it as MISSING —
// which is what deleting files by hand looks like.
//
// # Limits
//
//   - One checkpoint series per chain. Thousands of chains means thousands of
//     signatures per checkpoint run; one checkpoint over all chain heads is a
//     separate design.
//   - Keys must already be pseudonyms. A chain id is stored permanently and is
//     signed into every checkpoint, so an email address is refused, not
//     transformed.
//   - One process at a time: the files are locked while in use.
//   - Checkpoints prove what they cover only if they are kept where the writer
//     cannot rewrite them. Verify checks the checkpoints it finds; a folder
//     cannot prove none were deleted. The same goes for an erasure entry made
//     after the last checkpoint: until a checkpoint covers it, it is only as
//     trustworthy as the folder. Checkpoint after erasing, and publish the
//     checkpoints.
package topicsink

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

const (
	// MaxBatch caps the records in one Commit call.
	MaxBatch = 1000

	// MaxContentBytes caps one record's content.
	MaxContentBytes = 64 << 10

	// EntryTypeEvent marks an event: a salted commitment, opened with its nonce.
	EntryTypeEvent = "topicsink.event"

	// EntryTypeErasure marks an erasure: every event before it on the chain was
	// erased. Its content is a plain SHA-512 of the erasure record, which holds
	// nothing personal and is kept.
	EntryTypeErasure = "topicsink.erasure"

	dbName = "evidence.db"
)

// lockTimeout bounds the wait for ANOTHER PROCESS holding the files. Callers in
// this process queue on Sink.mu instead. A variable only so tests can shorten it.
var lockTimeout = 5 * time.Second

// ErrInvalidKey is returned for a routing key that is not a valid chain id.
var ErrInvalidKey = errors.New("topicsink: key is not a valid chain id: lowercase letters, " +
	"digits, . _ - (max 64), starting with a letter or digit. Use a topic or a pseudonym, " +
	"never an email or a name")

// idPattern is the chain-id rule the MCP commit tool uses, so a chain written
// here can also be written through proof-mcp.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// entryIDPattern is the only entry id this sink assigns. Ids read back from the
// evidence file are checked against it before any path is built from them: the
// file can be shared, so its contents are input, not trusted state.
var entryIDPattern = regexp.MustCompile(`^ts-[0-9a-f]{32}$`)

// Record is one event to commit.
type Record struct {
	// Key routes the record: it names the chain. It must pass ChainFor.
	Key string
	// Content is the event's exact bytes. They are what gets committed.
	Content []byte
	// Source, if set, is where the record sat upstream: a stream name and
	// sequence, a topic/partition/offset. It makes Commit idempotent: a record
	// whose Source is already committed on its chain is skipped, not committed
	// again. It is stored permanently, so it is a position, NEVER content or
	// anything identifying a person. At most MaxSourceBytes.
	//
	// A Source must NEVER be reused for a different record: a reused one is
	// taken as already committed, and the new record is dropped. Include
	// whatever makes a position unique for good. For a stream that can be
	// deleted and recreated, that means its incarnation, not just its sequence.
	Source string
}

// Committed reports what one chain received.
type Committed struct {
	Chain   string `json:"chain"`
	Entries int    `json:"entries"` // newly committed
	// Duplicates were records whose Source was already committed on this chain,
	// or repeated within the batch. They were skipped.
	Duplicates int `json:"duplicates,omitempty"`
}

// Checkpointed reports one checkpoint written.
type Checkpointed struct {
	Chain   string `json:"chain"`
	File    string `json:"file"`
	Entries int64  `json:"entries"`
}

// ChainReport is what Verify found on one chain.
type ChainReport struct {
	Chain       string `json:"chain"`
	Entries     int    `json:"entries"`
	Opened      int    `json:"opened"`      // events whose stored content opens their commitment
	Erased      int    `json:"erased"`      // events removed by a recorded erasure
	Checkpoints int    `json:"checkpoints"` // checkpoints that verified
	Unanchored  int    `json:"unanchored"`  // entries after the last checkpoint
	// Problems lists every failure. Empty means the chain verifies.
	Problems []string `json:"problems,omitempty"`
}

// Report is what Verify found on every chain.
type Report struct {
	Chains []ChainReport `json:"chains"`
}

// OK reports whether every chain verified.
func (r Report) OK() bool {
	for _, c := range r.Chains {
		if len(c.Problems) > 0 {
			return false
		}
	}
	return true
}

// EraseResult reports one erasure.
type EraseResult struct {
	Chain string `json:"chain"`
	// Events is how many events were erased (their content and nonces deleted).
	Events int `json:"events"`
	// ErasureEntryID is the entry that records the erasure on the chain.
	ErasureEntryID string `json:"erasure_entry_id"`
}

// Sink is a folder holding one evidence file with a chain per key.
//
// Safe for concurrent use. Calls on one Sink queue; anything else touching the
// folder — another process, or a second Sink on the same folder — waits on the
// file lock, and fails after a few seconds.
type Sink struct {
	dir string
	mu  sync.Mutex
}

// ChainFor turns a routing key into a chain id, or refuses it.
//
// # Description
//
// This is the router the service examples share. A key is used as the chain id
// unchanged, and only if it is already a valid one. Nothing is lowercased,
// trimmed or hashed: a key that needs transforming is a key that has not been
// pseudonymised yet, and that belongs upstream.
//
// # Outputs
//
//   - string: the chain id
//   - error: ErrInvalidKey. The key is never echoed into the error, because a
//     refused key is often exactly the personal data this rule keeps out.
func ChainFor(key string) (string, error) {
	if !idPattern.MatchString(key) {
		return "", ErrInvalidKey
	}
	return key, nil
}

// RecordFromJSON makes a Record from one JSON object, keyed by one of its fields.
//
// # Description
//
// The field must hold a JSON string. The record's content is the line exactly as
// given — no trimming, no re-encoding — so what is committed is what arrived.
//
// # Outputs
//
//   - Record: the record, with Key not yet validated (Commit does that)
//   - error: the line is not a JSON object, or the field is absent or not a string
func RecordFromJSON(line []byte, field string) (Record, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return Record{}, fmt.Errorf("not a JSON object: %w", err)
	}
	raw, ok := obj[field]
	if !ok {
		return Record{}, fmt.Errorf("no %q field to route by", field)
	}
	// Checked explicitly: null decodes into a string without error, as "".
	var key string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &key) != nil {
		return Record{}, fmt.Errorf("field %q is not a string", field)
	}
	return Record{Key: key, Content: append([]byte(nil), line...)}, nil
}

// Open opens a sink folder, creating it if needed.
//
// # Inputs
//
//   - dir: the folder. It holds secrets (the nonce file), so it is created 0700.
//
// # Outputs
//
//   - *Sink: the sink. It opens its files per operation, not here.
//   - error: the folder cannot be created
func Open(dir string) (*Sink, error) {
	if dir == "" {
		return nil, errors.New("topicsink: a folder is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("topicsink: create %s: %w", dir, err)
	}
	return &Sink{dir: dir}, nil
}

// DBPath is the evidence file: the chains, and nothing secret.
func (s *Sink) DBPath() string { return filepath.Join(s.dir, dbName) }

func (s *Sink) contentPath(chain, entryID string) string {
	return filepath.Join(s.dir, "content", chain, entryID+".json")
}

func (s *Sink) anchorDir(chain string) string { return filepath.Join(s.dir, "anchors", chain) }

// Commit commits records, each to the chain its key names.
//
// # Description
//
// Every record is validated before any file is touched. Records are then
// grouped by chain, keeping their order, and each chain gets one atomic append.
// For each record: a salted commitment goes on the chain, the content goes to
// content/<chain>/, and the nonce to the nonce file. Content and nonces are
// written BEFORE the append, and removed again if it fails: an entry whose
// content was never stored could never be opened.
//
// Entry ids and timestamps are assigned here, never taken from the records.
//
// A record with a Source is committed at most once per chain, across calls and
// crashes: its position is recorded (in evidence.db.sources) before the append,
// and checked against the chain on every later Commit of that Source. A crash
// between the two leaves a recorded position that is not on the chain, and the
// record is then committed normally. This is what lets a streaming consumer
// acknowledge after committing without committing a redelivery twice.
//
// # Inputs
//
//   - ctx: honoured by the append
//   - records: 1 to MaxBatch records
//
// # Outputs
//
//   - []Committed: per chain, in order of first appearance. On error, the chains
//     committed before the failure.
//   - error: a record is invalid (nothing written), or one chain's append failed.
//     Each chain is atomic; the batch as a whole is not.
func (s *Sink) Commit(ctx context.Context, records []Record) ([]Committed, error) {
	if n := len(records); n == 0 || n > MaxBatch {
		return nil, fmt.Errorf("topicsink: commit 1 to %d records, got %d", MaxBatch, n)
	}
	var order []string
	groups := map[string][]Record{}
	sourced := false
	for i, r := range records {
		chain, err := ChainFor(r.Key)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		if len(r.Content) == 0 {
			return nil, fmt.Errorf("record %d: content is empty; there is nothing to commit", i)
		}
		if len(r.Content) > MaxContentBytes {
			return nil, fmt.Errorf("record %d: content is %d bytes, over the %d byte limit",
				i, len(r.Content), MaxContentBytes)
		}
		if len(r.Source) > MaxSourceBytes {
			return nil, fmt.Errorf("record %d: source is %d bytes, over the %d byte limit",
				i, len(r.Source), MaxSourceBytes)
		}
		if r.Source != "" {
			sourced = true
		}
		if _, seen := groups[chain]; !seen {
			order = append(order, chain)
		}
		groups[chain] = append(groups[chain], r)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st, ns, err := s.openFiles()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	defer ns.Close()
	// Opened only when needed, so a sink that never sees a Source has no
	// sources file. Always after the other two: one lock order everywhere.
	var src *sourcesStore
	if sourced {
		if src, err = openSources(s.sourcesPath()); err != nil {
			return nil, err
		}
		defer src.Close()
	}
	l, err := linker.New(st)
	if err != nil {
		return nil, fmt.Errorf("topicsink: prepare the chains: %w", err)
	}

	var done []Committed
	for _, chain := range order {
		c, err := s.commitChain(ctx, l, st, ns, src, chain, groups[chain])
		if err != nil {
			return done, fmt.Errorf("topicsink: chain %s: %w (chains before it in this batch were committed)",
				chain, err)
		}
		done = append(done, c)
	}
	return done, nil
}

func (s *Sink) sourcesPath() string { return s.DBPath() + ".sources" }

// dropDuplicates removes records whose Source is already committed on the
// chain, or repeated earlier in the batch.
func dropDuplicates(ctx context.Context, st *boltstore.Store, src *sourcesStore, chain string,
	recs []Record) ([]Record, int, error) {
	if src == nil {
		return recs, 0, nil
	}
	keep := make([]Record, 0, len(recs))
	inBatch := map[string]bool{}
	dups := 0
	for _, r := range recs {
		if r.Source == "" {
			keep = append(keep, r)
			continue
		}
		if inBatch[r.Source] {
			dups++
			continue
		}
		inBatch[r.Source] = true
		p, found, err := src.get(chain, r.Source)
		if err != nil {
			return nil, 0, err
		}
		if found {
			// Recorded. Committed only if the chain holds that entry at that
			// position; otherwise the earlier attempt stopped before its append.
			rows, err := st.Range(ctx, chain, p.seq, p.seq, 1)
			if err != nil {
				return nil, 0, fmt.Errorf("check source position: %w", err)
			}
			if len(rows) == 1 && rows[0].EntryID == p.entryID {
				dups++
				continue
			}
		}
		keep = append(keep, r)
	}
	return keep, dups, nil
}

// commitChain appends one chain's records in a single atomic append.
func (s *Sink) commitChain(ctx context.Context, l *linker.Linker, st *boltstore.Store,
	ns *noncestore.Store, src *sourcesStore, chain string, recs []Record) (Committed, error) {
	recs, dups, err := dropDuplicates(ctx, st, src, chain, recs)
	if err != nil {
		return Committed{}, err
	}
	out := Committed{Chain: chain, Entries: len(recs), Duplicates: dups}
	if len(recs) == 0 {
		return out, nil
	}
	if err := s.appendChain(ctx, l, st, ns, src, chain, recs); err != nil {
		return Committed{}, err
	}
	return out, nil
}

// appendChain writes content, nonces and source positions, then appends.
func (s *Sink) appendChain(ctx context.Context, l *linker.Linker, st *boltstore.Store,
	ns *noncestore.Store, src *sourcesStore, chain string, recs []Record) error {
	if err := os.MkdirAll(filepath.Join(s.dir, "content", chain), 0o700); err != nil {
		return fmt.Errorf("create content folder: %w", err)
	}
	// The sequence the first entry will get. Nothing else can append meanwhile:
	// this process holds Sink.mu and the evidence file's lock.
	next := int64(0)
	if _, tail, err := st.ReadTail(ctx, chain); err == nil {
		next = tail + 1
	} else if !errors.Is(err, store.ErrEmptyChain) {
		return fmt.Errorf("read chain tail: %w", err)
	}
	positions := map[string]position{}
	// Stamped now, one microsecond apart: the linker orders a batch by arrival
	// and hashes timestamps at microsecond precision. The chain's sequence, not
	// these, is the authoritative order.
	now := time.Now().UTC().Truncate(time.Microsecond)
	inputs := make([]linker.Input, len(recs))
	nonces := make(map[string][]byte, len(recs))
	var written []string
	cleanup := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
		ids := make([]string, 0, len(nonces))
		for id := range nonces {
			ids = append(ids, id)
		}
		_ = ns.DeleteBatch(chain, ids)
	}

	for i, r := range recs {
		id, err := newEntryID()
		if err != nil {
			cleanup()
			return err
		}
		c, nonce, err := commitment.Salted(r.Content)
		if err != nil {
			cleanup()
			return err
		}
		path := s.contentPath(chain, id)
		if err := writeNew(path, r.Content, 0o600); err != nil {
			cleanup()
			return err
		}
		written = append(written, path)
		nonces[id] = nonce
		stamp := now.Add(time.Duration(i) * time.Microsecond)
		inputs[i] = linker.Input{EntryID: id, EntryType: EntryTypeEvent,
			Timestamp: stamp, ContentHash: c, IngestedAt: stamp}
		if r.Source != "" {
			// Strictly increasing stamps keep the linker's arrival order equal to
			// this order, so entry i lands at next+i.
			positions[r.Source] = position{entryID: id, seq: next + int64(i)}
		}
	}
	if err := ns.PutBatch(chain, nonces); err != nil {
		cleanup()
		return fmt.Errorf("store nonces: %w", err)
	}
	// Positions go down BEFORE the append. A position with no entry behind it is
	// harmless: the next Commit of that source sees it is not on the chain. An
	// entry with no position is the duplicate this exists to prevent.
	if len(positions) > 0 {
		if err := src.putBatch(chain, positions); err != nil {
			cleanup()
			return fmt.Errorf("record sources: %w", err)
		}
	}
	res, err := l.Append(ctx, chain, inputs)
	if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
		// ErrHeadStateStale means the entries ARE written; only the saved head
		// record lags, and the next append repairs it. Anything else: nothing was
		// written, so nothing may be left behind.
		cleanup()
		return fmt.Errorf("append: %w", err)
	}
	if len(positions) > 0 && res.FirstSeq != next {
		// Cannot happen while this process holds the file. If it ever does, the
		// entries ARE committed, so this must not look like a failure (the caller
		// would retry and commit twice). Re-record the positions from the actual
		// sequence instead: the batch order is kept, so entry i is at FirstSeq+i.
		for i, r := range recs {
			if r.Source != "" {
				positions[r.Source] = position{entryID: inputs[i].EntryID, seq: res.FirstSeq + int64(i)}
			}
		}
		if err := src.putBatch(chain, positions); err != nil {
			return fmt.Errorf("committed, but correcting the source positions failed: %w; "+
				"a redelivery of this batch may be committed again", err)
		}
	}
	return nil
}

// Checkpoint signs one checkpoint for every chain with entries since its last.
//
// # Description
//
// Each checkpoint is a v6 anchor over the whole chain so far, linked to the
// chain's previous checkpoint, with the chain id as its subject. build.Anchor
// verifies the chain before it will sign anything about it.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - signer: an ML-DSA-65 signer, e.g. from a `proof keygen --alg ml-dsa-65` key
//
// # Outputs
//
//   - []Checkpointed: the checkpoints written, by chain id. Empty if every chain
//     was already checkpointed.
//   - error: a chain is broken, signing failed, or a file could not be written.
//     Checkpoints written before the error remain and are valid.
func (s *Sink) Checkpoint(ctx context.Context, signer anchor.ContextSigner) ([]Checkpointed, error) {
	if signer == nil {
		return nil, errors.New("topicsink: a signer is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.openStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	chains, err := st.Chains(ctx)
	if err != nil {
		return nil, fmt.Errorf("topicsink: %w", err)
	}

	signerID, signerPub, err := anchor.KeyIDOf(signer)
	if err != nil {
		return nil, fmt.Errorf("topicsink: %w", err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{signerID: signerPub})
	if err != nil {
		return nil, fmt.Errorf("topicsink: %w", err)
	}

	var out []Checkpointed
	for _, chain := range chains {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !idPattern.MatchString(chain) {
			return out, fmt.Errorf("topicsink: the evidence file holds a chain id this sink never writes (%q); "+
				"refusing to checkpoint it", chain)
		}
		entries, err := readChain(ctx, st, chain)
		if err != nil {
			return out, err
		}
		anchors, err := s.readAnchors(chain)
		if err != nil {
			return out, err
		}
		var previous *anchor.Anchor
		if len(anchors) > 0 {
			previous = &anchors[len(anchors)-1]
			if previous.EntryCount == int64(len(entries)) {
				continue // nothing new since the last checkpoint
			}
			// Never sign on top of a series that does not verify: a planted or
			// damaged checkpoint would be extended instead of reported.
			check := ChainReport{Chain: chain}
			s.verifyCheckpoints(&check, entries, anchors, ring)
			if len(check.Problems) > 0 {
				return out, fmt.Errorf("topicsink: chain %s: its checkpoints do not verify under this key: %s",
					chain, check.Problems[0])
			}
		}
		unsigned, err := build.Anchor(ctx, build.Input{
			Subject: chain, Entries: entries, Previous: previous,
		})
		if err != nil {
			return out, fmt.Errorf("topicsink: chain %s: %w", chain, err)
		}
		signed, err := anchor.SignAnchor(ctx, signer, unsigned)
		if err != nil {
			return out, fmt.Errorf("topicsink: chain %s: %w", chain, err)
		}
		raw, err := json.MarshalIndent(signed, "", "  ")
		if err != nil {
			return out, fmt.Errorf("topicsink: chain %s: %w", chain, err)
		}
		if err := os.MkdirAll(s.anchorDir(chain), 0o755); err != nil {
			return out, fmt.Errorf("topicsink: %w", err)
		}
		name := fmt.Sprintf("%04d.json", len(anchors)+1)
		if err := writeNew(filepath.Join(s.anchorDir(chain), name), raw, 0o644); err != nil {
			return out, err
		}
		out = append(out, Checkpointed{Chain: chain,
			File: filepath.Join("anchors", chain, name), Entries: signed.EntryCount})
	}
	return out, nil
}

// Verify checks every chain in the evidence file, each on its own.
//
// # Description
//
// For every chain:
//
//  1. The links are intact: no entry edited, reordered or removed mid-chain.
//  2. Every checkpoint is signed by a key in keys, is for this chain, and binds
//     the entries it covered. This is what catches entries removed from the
//     front, which step 1 cannot.
//  3. Every event's stored content opens its commitment with its nonce, and
//     every erasure record matches its digest.
//  4. Events before an erasure entry are gone: content and nonce both deleted.
//     They count as erased. An event missing WITHOUT an erasure after it is a
//     problem, not an erasure.
//
// Steps 1 and 2 need only the evidence file, the checkpoints and a public key.
// Step 3 needs the content folder and the nonce file, which only the operator
// holds.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - keys: the public keys checkpoints may be signed with
//
// # Outputs
//
//   - Report: per chain, in chain-id order. Report.OK is the verdict.
//   - error: only when verification could not run (a file unreadable). A broken
//     chain is a finding in the Report, not an error.
func (s *Sink) Verify(ctx context.Context, keys anchor.KeySource) (Report, error) {
	if keys == nil {
		return Report{}, errors.New("topicsink: a key source is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ns, err := s.openFiles()
	if err != nil {
		return Report{}, err
	}
	defer st.Close()
	defer ns.Close()
	chains, err := st.Chains(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("topicsink: %w", err)
	}

	var rep Report
	inStore := map[string]bool{}
	for _, chain := range chains {
		inStore[chain] = true
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if !idPattern.MatchString(chain) {
			// Never build a path from it: it could be "../../somewhere".
			rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("%q", chain),
				Problems: []string{"the evidence file holds a chain id this sink never writes; it was not read"}})
			continue
		}
		entries, err := readChain(ctx, st, chain)
		if err != nil {
			return rep, err
		}
		anchors, err := s.readAnchors(chain)
		if err != nil {
			return rep, err
		}
		cr := ChainReport{Chain: chain, Entries: len(entries)}
		s.verifyLinks(&cr, entries)
		s.verifyCheckpoints(&cr, entries, anchors, keys)
		if err := s.verifyContent(&cr, ns, entries); err != nil {
			return rep, err
		}
		rep.Chains = append(rep.Chains, cr)
	}

	// A chain removed from the evidence file leaves its checkpoints and content
	// behind. They are the only trace of it, so look for them.
	for _, sub := range []string{"anchors", "content"} {
		dirs, err := os.ReadDir(filepath.Join(s.dir, sub))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return rep, fmt.Errorf("topicsink: %w", err)
		}
		for _, d := range dirs {
			if inStore[d.Name()] {
				continue
			}
			inStore[d.Name()] = true // report each once
			rep.Chains = append(rep.Chains, ChainReport{Chain: fmt.Sprintf("%q", d.Name()),
				Problems: []string{fmt.Sprintf("%s/ has a folder for this chain, but the evidence file "+
					"has no entries for it: the chain was REMOVED", sub)}})
		}
	}
	sort.Slice(rep.Chains, func(i, j int) bool { return rep.Chains[i].Chain < rep.Chains[j].Chain })
	return rep, nil
}

func (s *Sink) verifyLinks(cr *ChainReport, entries []verify.Entry) {
	res, err := verify.Chain(entries, verify.Options{MaxBreaks: 1})
	if err != nil {
		cr.Problems = append(cr.Problems, "links: "+err.Error())
		return
	}
	if len(res.Breaks) > 0 {
		cr.Problems = append(cr.Problems, fmt.Sprintf("links BROKEN at entry %d: %s",
			res.FirstBreak, res.Breaks[0].Type))
	}
}

func (s *Sink) verifyCheckpoints(cr *ChainReport, entries []verify.Entry, anchors []anchor.Anchor,
	keys anchor.KeySource) {
	previousHash := anchor.SeedAnchorHash
	covered := int64(0)
	for i, a := range anchors {
		n := i + 1
		switch {
		case a.Subject != cr.Chain:
			cr.Problems = append(cr.Problems, fmt.Sprintf("checkpoint %04d is for another chain", n))
			return
		case a.EntryCount < 1 || a.EntryCount > int64(len(entries)):
			cr.Problems = append(cr.Problems, fmt.Sprintf("checkpoint %04d claims %d entries; the chain has %d",
				n, a.EntryCount, len(entries)))
			return
		}
		// A checkpoint commits to the chain as it was when signed, so it is
		// checked against the entries it covered, not the entries added since.
		br, err := verify.VerifyAnchor(a, entries[:a.EntryCount], previousHash, keys)
		if err != nil {
			cr.Problems = append(cr.Problems, fmt.Sprintf("checkpoint %04d: %v", n, err))
			return
		}
		if !br.Bound || !br.SignatureVerified {
			cr.Problems = append(cr.Problems, fmt.Sprintf("checkpoint %04d does NOT verify: %s", n, br.Detail))
			return
		}
		cr.Checkpoints++
		covered = a.EntryCount
		previousHash = a.ChainHash
	}
	cr.Unanchored = len(entries) - int(covered)
}

func (s *Sink) verifyContent(cr *ChainReport, ns *noncestore.Store, entries []verify.Entry) error {
	lastErasure := -1
	for i, e := range entries {
		if e.EntryType == EntryTypeErasure {
			lastErasure = i
		}
	}
	known := map[string]bool{}
	for i, e := range entries {
		if !entryIDPattern.MatchString(e.EntryID) {
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %q has an id this sink never assigns; "+
				"it was not read", e.EntryID))
			continue
		}
		known[e.EntryID+".json"] = true
		content, missing, problem, err := readContent(s.contentPath(cr.Chain, e.EntryID))
		if err != nil {
			return err
		}
		if problem != "" {
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s: %s", e.EntryID, problem))
			continue
		}
		nonce, nerr := ns.Get(cr.Chain, e.EntryID)
		noNonce := errors.Is(nerr, noncestore.ErrNotFound)
		if nerr != nil && !noNonce {
			return fmt.Errorf("topicsink: nonce for %s: %w", e.EntryID, nerr)
		}

		switch {
		case e.EntryType == EntryTypeErasure:
			sum := sha512.Sum512(content)
			if missing || hex.EncodeToString(sum[:]) != e.ContentHash {
				cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s is missing or MODIFIED", e.EntryID))
			}
		case e.EntryType != EntryTypeEvent:
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s has type %q, which this sink never writes",
				e.EntryID, e.EntryType))
		case i < lastErasure:
			if !missing || !noNonce {
				cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was erased, but its content or nonce "+
					"is still here: run erase again", e.EntryID))
				continue
			}
			cr.Erased++
		case missing:
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s is MISSING: the chain records it, "+
				"its content is gone, and no erasure was recorded", e.EntryID))
		case noNonce:
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s cannot be opened: its nonce is gone, "+
				"and no erasure was recorded", e.EntryID))
		case !commitment.Verify(e.ContentHash, nonce, content):
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was MODIFIED: its content no longer "+
				"opens the commitment", e.EntryID))
		default:
			cr.Opened++
		}
	}

	// A file matching no entry is content that was never committed: a commit
	// that stopped before its append. It is still personal data, so say so.
	files, err := os.ReadDir(filepath.Join(s.dir, "content", cr.Chain))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("topicsink: %w", err)
	}
	for _, f := range files {
		if !known[f.Name()] {
			cr.Problems = append(cr.Problems, fmt.Sprintf("content file %q matches no entry (a commit "+
				"that did not finish?); erase the chain or remove it", f.Name()))
		}
	}
	return nil
}

// Erase erases every event on one chain, and records that it did.
//
// # Description
//
// In this order:
//
//  1. Commit an erasure entry to the chain. Its content, kept, is a small record
//     with nothing personal in it. Doing this first means a crash part-way leaves
//     a chain that says "erased, but the content is still here: run erase
//     again", never one that looks tampered with.
//  2. Delete every nonce of the chain, in one transaction.
//  3. Delete every content file of the chain except erasure records. Both
//     steps also catch leftovers of a commit that stopped before its append.
//
// Afterwards no event before the erasure entry can be opened by anyone, and the
// chain, including its checkpoints, still verifies: it only ever held
// commitments. Events committed to the chain later are unaffected.
//
// # Inputs
//
//   - ctx: honoured by the append
//   - chain: the chain id to erase
//
// # Outputs
//
//   - EraseResult: how many events were erased, and the erasure entry's id
//   - error: the chain id is invalid or has no entries, or a file operation
//     failed. Erase is safe to run again after a failure.
//
// # Limitations
//
//   - Reaches only this folder: not backups, and not anyone the content or a
//     nonce was already disclosed to.
//   - The chain id itself stays: it is in the chain and in every checkpoint.
func (s *Sink) Erase(ctx context.Context, chain string) (EraseResult, error) {
	if _, err := ChainFor(chain); err != nil {
		return EraseResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ns, err := s.openFiles()
	if err != nil {
		return EraseResult{}, err
	}
	defer st.Close()
	defer ns.Close()

	entries, err := readChain(ctx, st, chain)
	if err != nil {
		return EraseResult{}, err
	}
	if len(entries) == 0 {
		return EraseResult{}, fmt.Errorf("topicsink: chain %s has no entries", chain)
	}
	events := 0
	keep := map[string]bool{} // erasure records stay
	for _, e := range entries {
		switch e.EntryType {
		case EntryTypeEvent:
			events++
		case EntryTypeErasure:
			keep[e.EntryID+".json"] = true
		}
	}

	// 1. The erasure goes on the record first.
	id, err := newEntryID()
	if err != nil {
		return EraseResult{}, err
	}
	record, err := json.Marshal(erasureRecord{
		Erased:           "every earlier event on this chain",
		ThroughGlobalSeq: entries[len(entries)-1].GlobalSeq,
	})
	if err != nil {
		return EraseResult{}, fmt.Errorf("topicsink: %w", err)
	}
	path := s.contentPath(chain, id)
	if err := writeNew(path, record, 0o600); err != nil {
		return EraseResult{}, err
	}
	sum := sha512.Sum512(record)
	now := time.Now().UTC().Truncate(time.Microsecond)
	l, err := linker.New(st)
	if err != nil {
		_ = os.Remove(path)
		return EraseResult{}, fmt.Errorf("topicsink: prepare the chain: %w", err)
	}
	_, err = l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
		Timestamp: now, ContentHash: hex.EncodeToString(sum[:]), IngestedAt: now}})
	if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
		_ = os.Remove(path)
		return EraseResult{}, fmt.Errorf("topicsink: record the erasure: %w; nothing was erased", err)
	}

	keep[id+".json"] = true

	// 2. Nonces: without one, a commitment can never be opened. Every nonce of
	// the chain, including any left by a commit that stopped before its append.
	if _, err := ns.DeleteChain(chain); err != nil {
		return EraseResult{}, fmt.Errorf("topicsink: the erasure is recorded but deleting nonces "+
			"failed: %w; run erase again", err)
	}
	// 3. Content: every file in the chain's folder except erasure records, so
	// content a stopped commit left behind goes too. Names come from this
	// folder, never from the evidence file.
	files, err := os.ReadDir(filepath.Join(s.dir, "content", chain))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return EraseResult{}, fmt.Errorf("topicsink: the erasure is recorded but listing content "+
			"failed: %w; run erase again", err)
	}
	for _, f := range files {
		if keep[f.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, "content", chain, f.Name())); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return EraseResult{}, fmt.Errorf("topicsink: the erasure is recorded but deleting content "+
				"failed: %w; run erase again", err)
		}
	}
	return EraseResult{Chain: chain, Events: events, ErasureEntryID: id}, nil
}

// erasureRecord is the content of an erasure entry.
type erasureRecord struct {
	Erased           string `json:"erased"`
	ThroughGlobalSeq int64  `json:"through_global_seq"`
}

// readContent reads one content file, refusing anything that is not a small
// regular file. A symlink is refused rather than followed: it could point
// anywhere.
//
// Outputs: the content; whether it is missing; a problem to report (the file
// is there but unusable); and an error only when the file could not be examined.
func readContent(path string) ([]byte, bool, string, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, "", nil
	}
	if err != nil {
		return nil, false, "", fmt.Errorf("topicsink: %w", err)
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, false, "its content is not a regular file", nil
	case fi.Size() > MaxContentBytes:
		return nil, false, fmt.Sprintf("its content is %d bytes, over the %d byte limit", fi.Size(), MaxContentBytes), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, "", fmt.Errorf("topicsink: %w", err)
	}
	return b, false, "", nil
}

// openStore opens the evidence file.
func (s *Sink) openStore() (*boltstore.Store, error) {
	st, err := boltstore.Open(s.DBPath(), boltstore.WithLockTimeout(lockTimeout))
	if err != nil {
		if errors.Is(err, boltstore.ErrLocked) {
			return nil, fmt.Errorf("topicsink: %s is in use by another process", s.DBPath())
		}
		return nil, fmt.Errorf("topicsink: open %s: %w", s.DBPath(), err)
	}
	return st, nil
}

// openFiles opens the evidence file, then the nonce file. Always in that order,
// so two processes cannot each hold one while waiting for the other.
func (s *Sink) openFiles() (*boltstore.Store, *noncestore.Store, error) {
	st, err := s.openStore()
	if err != nil {
		return nil, nil, err
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), lockTimeout)
	if err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("topicsink: %w", err)
	}
	return st, ns, nil
}

// readChain returns one chain's entries in order, in the form verify reads.
func readChain(ctx context.Context, st *boltstore.Store, chain string) ([]verify.Entry, error) {
	rows, err := st.Range(ctx, chain, 0, 1<<62, 0)
	if err != nil {
		return nil, fmt.Errorf("topicsink: read chain %s: %w", chain, err)
	}
	entries := make([]verify.Entry, len(rows))
	for i, r := range rows {
		entries[i] = verify.Entry{
			EntryID: r.EntryID, EntryType: r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion, GlobalSeq: r.GlobalSeq,
			ContentHash: r.ContentHash, ChainHash: r.ChainHash,
		}
	}
	return entries, nil
}

// readAnchors returns one chain's checkpoints in order.
func (s *Sink) readAnchors(chain string) ([]anchor.Anchor, error) {
	names, err := filepath.Glob(filepath.Join(s.anchorDir(chain), "*.json"))
	if err != nil {
		return nil, fmt.Errorf("topicsink: %w", err)
	}
	sort.Strings(names)
	out := make([]anchor.Anchor, 0, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(n)
		if err != nil {
			return nil, fmt.Errorf("topicsink: %w", err)
		}
		var a anchor.Anchor
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("topicsink: %s: %w", n, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// writeNew writes a file that must not already exist.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("topicsink: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("topicsink: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("topicsink: close %s: %w", path, err)
	}
	return nil
}

// newEntryID returns a random entry id: assigned here so a record can neither
// collide with an existing entry nor choose an id that means something.
func newEntryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("topicsink: draw entry id: %w", err)
	}
	return "ts-" + hex.EncodeToString(b), nil
}
