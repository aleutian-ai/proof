// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package sink commits events about subjects to opaque proof chains, one per
// (class, subject) pair, and checkpoints, verifies and erases them.
//
// # Description
//
// Logging and streaming systems carry events about someone: a user, an
// account, a device. A sink keeps each subject's evidence of each class on its
// own chain, and it is where real event systems meet proof's deterministic
// core. The integrations under examples/integrations (NATS, Redis/Valkey, Kafka,
// …) are consumers in front of this package and nothing more.
//
//	records ──► Commit ──► evidence.db           opaque chains <class>.<32 hex>   shareable
//	            (salted)   evidence.db.nonces    the secret half, per entry       SECRET
//	                       evidence.db.sources   upstream positions, idempotency  SECRET
//	                       evidence.db.subjects  subject ↔ chain index            SECRET
//	                       content/<chain>/      the events themselves            SECRET
//	            Checkpoint ─────────────────► anchors/<chain>/   one signed series per chain
//	            Verify: every chain, on its own
//	            EraseSubject: content, nonces and the index rows gone; the chains still verify
//
// Chain ids are random, never derived from the subject: only the secret subject
// index links a subject to its chains, so the evidence file and checkpoints name
// no one. Every event is committed as a salted commitment (package commitment):
// the chain holds a fingerprint that cannot be reversed or guessed, even for
// short or predictable events. The evidence file is still pseudonymous personal
// data (per-chain counts and timestamps, erasures): see docs/sink-format.md
// before sharing it.
//
// The folder layout, entry types, erasure record and verification rules are
// specified in docs/sink-format.md. The bbolt files are this package's
// implementation, documented there but not an interface: other languages
// verify an exported bundle, not the files.
//
// # Idempotency
//
// A Record may carry a Source: its position upstream, including the source's
// incarnation. A record whose Source is already committed on its chain is
// skipped, across calls and across crashes. That is what lets a consumer
// acknowledge upstream only after committing, without committing a redelivery
// twice. Erasing a subject deletes its chains' sources, and a later event for
// the subject goes to a new chain, so a redelivery after an erasure is
// committed again: consumers should acknowledge before erasing.
//
// # Erasure
//
// EraseSubject (or EraseSubjectClass, for one class) forgets the subject in the
// index, then commits a genuine erasure entry to each of its chains and deletes
// their events, nonces and source positions, and rewrites the secret files, so
// none can be opened from this folder again. Verify reports events before an
// erasure entry as ERASED, and an event missing with no erasure after it as
// MISSING, which is what deleting files by hand looks like. An interrupted
// erasure is completed by ResumeErasures. Erasure reaches only the live files:
// not backups, snapshots, SSD blocks, or anyone the content was disclosed to.
//
// # Limitations
//
//   - One checkpoint series per chain. Thousands of chains means thousands of
//     signatures per checkpoint run.
//   - Subjects must already be pseudonyms. A subject is stored only in the
//     secret index, but also sits in its events' content. ValidSubject refuses
//     an email address or anything upper-case, but it checks characters only:
//     "john.smith" passes. Pseudonymizing is the caller's job, upstream.
//   - Correlation leakage: erasing a subject erases all its chains within the
//     same moment, and a returning subject's new chain starts soon after, so an
//     observer of the evidence file may infer which opaque chains belonged to
//     one subject. Timestamps are never altered to hide it. Kept copies of the
//     subjects file re-link every chain, erased or not.
//   - One process at a time: the files are locked while in use. Calls on one
//     Sink queue.
//   - Checkpoints prove what they cover only if they are kept where the writer
//     cannot rewrite them. A folder cannot prove none were deleted, and an
//     erasure made after the last checkpoint is only as trustworthy as the
//     folder until a checkpoint covers it.
//   - The bolt store only.
package sink

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

const (
	// MaxBatch caps the records in one Commit call.
	MaxBatch = 1000

	// MaxContentBytes caps one record's content.
	MaxContentBytes = 64 << 10

	// EntryTypeEvent marks an event: a salted commitment, opened with its nonce.
	EntryTypeEvent = "sink.event"

	// EntryTypeErasure marks an erasure: every event before it on the chain was
	// erased. Its content_hash is the domain-separated hash of a fixed record
	// (docs/sink-format.md §4), which is kept.
	EntryTypeErasure = "sink.erasure"

	dbName = "evidence.db"
)

// DefaultLockTimeout bounds the wait for another process holding a sink's
// files. Calls on one Sink queue on the Sink instead; see WithLockTimeout.
const DefaultLockTimeout = 5 * time.Second

// Option configures a Sink at Open.
type Option func(*Sink)

// WithLockTimeout sets how long an operation waits for another process (or
// another Sink on the same folder) to release the files before failing.
//
// # Inputs
//
//   - d: the wait; zero or negative keeps DefaultLockTimeout
//
// # Example
//
//	s, err := sink.Open("sink-data", sink.WithLockTimeout(30*time.Second))
func WithLockTimeout(d time.Duration) Option {
	return func(s *Sink) {
		if d > 0 {
			s.lockTimeout = d
		}
	}
}

// Record is one event to commit.
type Record struct {
	// Class is the kind of evidence: payments, auth, events. It is in the clear
	// in chain ids, so it must never identify a person. It must pass ValidClass.
	Class string
	// Subject is who the record is about: a pseudonym, never a name or an email
	// (ValidSubject checks characters only). It is stored ONLY in the secret
	// subject index, never in the evidence file or a checkpoint: a subject's
	// chains have opaque ids, and erasing the subject deletes the index rows.
	Subject string
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

// Committed reports what one (class, subject) pair's chain received.
//
// SENSITIVE: a Committed pairs a subject with its chain, which is exactly what
// the secret subject index exists to hold, and what erasure deletes. Subject is
// here only so a streaming consumer can acknowledge upstream per subject. Do not
// log, print or persist it: a logged pairing re-identifies the chain forever,
// after any erasure. To make that hard to do by accident, Subject is never
// encoded to JSON, and a Committed formats with the subject redacted (%v, %+v,
// %#v, %s).
type Committed struct {
	Chain   string `json:"chain"` // the opaque chain id
	Class   string `json:"class"`
	Subject string `json:"-"`       // as the caller gave it; SENSITIVE, see above
	Entries int    `json:"entries"` // newly committed
	// Duplicates were records whose Source was already committed on this chain,
	// or repeated within the batch. They were skipped.
	Duplicates int `json:"duplicates,omitempty"`
}

// String formats c with its subject redacted.
func (c Committed) String() string {
	return fmt.Sprintf("{Chain:%s Class:%s Subject:[redacted] Entries:%d Duplicates:%d}",
		c.Chain, c.Class, c.Entries, c.Duplicates)
}

// GoString formats c for %#v, with its subject redacted.
func (c Committed) GoString() string { return "sink.Committed" + c.String() }

// Checkpointed reports one chain's checkpoint: written, or refused.
type Checkpointed struct {
	Chain   string `json:"chain"`
	File    string `json:"file,omitempty"`    // empty when Problem is set
	Entries int64  `json:"entries,omitempty"` // entries the checkpoint covers
	// Problem, when set, is why this chain was NOT checkpointed: a broken chain,
	// a malformed or unverifiable series, an id this sink never writes. The
	// chain id is reported raw; quote it before printing.
	Problem string `json:"problem,omitempty"`
}

// ChainReport is what Verify found on one chain.
type ChainReport struct {
	// Chain is the chain id, raw. It may come from a crafted evidence file or a
	// stray folder name: quote it before printing (the CLI does).
	Chain string `json:"chain"`
	// Anomaly is set when this is not an ordinary chain: "invalid-id" (the
	// evidence file holds an id this sink never writes; nothing was read) or
	// "removed" (checkpoint or content folders exist, but no entries), or
	// "invalid-folder" (content/ or anchors/ is not a real directory).
	Anomaly     string `json:"anomaly,omitempty"`
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

// OK reports whether every chain verified: true only when no chain has a
// problem. Unanchored entries are not problems.
func (r Report) OK() bool {
	for _, c := range r.Chains {
		if len(c.Problems) > 0 {
			return false
		}
	}
	return true
}

// SubjectErasure reports one EraseSubject or EraseSubjectClass call.
type SubjectErasure struct {
	// Class is empty for a subject erasure (every class; the subject is
	// forgotten), and names the one class erased for a class-scoped erasure (the
	// subject is still known through its other classes).
	Class string `json:"class,omitempty"`
	// Erased are this call's chains. None means the sink held nothing for the
	// subject in scope.
	Erased []EraseResult `json:"erased"`
	// Resumed are chains of earlier, interrupted erasures, completed first.
	Resumed []EraseResult `json:"resumed,omitempty"`
}

// EraseResult reports one chain's erasure.
type EraseResult struct {
	Chain string `json:"chain"`
	// Events is how many events this erasure newly covers: those since the
	// chain's previous erasure (their content and nonces deleted).
	Events int `json:"events"`
	// ErasureEntryID is the entry that records the erasure on the chain. Empty
	// when the chain had no entries (see Leftovers).
	ErasureEntryID string `json:"erasure_entry_id,omitempty"`
	// Leftovers counts what was removed for a chain with NO entries: content
	// files, nonces and source positions left by a first commit that stopped
	// before its append. No erasure entry is written: there is no chain to hold it.
	Leftovers int `json:"leftovers,omitempty"`
}

// Sink is a folder holding one evidence file with a chain per (class, subject).
//
// Safe for concurrent use. Calls on one Sink queue; anything else touching the
// folder — another process, or a second Sink on the same folder — waits on the
// file lock, and fails after a few seconds.
type Sink struct {
	dir         string
	lockTimeout time.Duration
	mu          sync.Mutex
	// mintChainID mints a new chain id: newChainID, always, outside tests. A
	// field (not a package variable) so a test can force a collision on one Sink.
	mintChainID func(class string) (string, error)
	// compact rewrites one secret file: compactFile, always, outside tests. A
	// field so a test can make one compaction fail.
	compact func(path string, lockTimeout time.Duration) error
}

// Open opens a sink folder, creating it if needed.
//
// # Description
//
// Nothing is created, read or locked here: each operation opens the files it
// needs and releases them when it returns, so several processes can take turns
// on one folder. Only Commit creates the folder; Verify, Checkpoint and Erase on
// a folder that is not a sink fail without creating anything.
//
// # Inputs
//
//   - dir: the folder. It holds secrets (the nonce file), so Commit creates it 0700.
//   - opts: e.g. WithLockTimeout
//
// # Outputs
//
//   - *Sink: the sink
//   - error: dir is empty
//
// # Example
//
//	s, err := sink.Open("sink-data")
//	if err != nil {
//	    return err
//	}
//	done, err := s.Commit(ctx, []sink.Record{{Class: "events", Subject: "u-81", Content: event}})
//
// # Limitations
//
//   - Does not check that the folder is a sink; the first operation does.
func Open(dir string, opts ...Option) (*Sink, error) {
	if dir == "" {
		return nil, errors.New("sink: a folder is required")
	}
	s := &Sink{dir: dir, lockTimeout: DefaultLockTimeout, mintChainID: newChainID, compact: compactFile}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// DBPath returns the path of the evidence file: the chains, holding no event
// content (but see docs/sink-format.md for what it does reveal).
// It is the file to export from (`proof export --db`) or to share. The nonce and
// sources files sit beside it as DBPath()+".nonces" and DBPath()+".sources".
func (s *Sink) DBPath() string { return filepath.Join(s.dir, dbName) }

// contentName is a content file's name inside the sink folder (for os.Root).
func contentName(chain, entryID string) string {
	return filepath.Join("content", chain, entryID+".json")
}

// contentPath is a content file's full path (tests use it to tamper).
func (s *Sink) contentPath(chain, entryID string) string {
	return filepath.Join(s.dir, "content", chain, entryID+".json")
}

func (s *Sink) anchorDir(chain string) string { return filepath.Join(s.dir, "anchors", chain) }

func (s *Sink) subjectsPath() string { return s.DBPath() + ".subjects" }

func (s *Sink) sourcesPath() string { return s.DBPath() + ".sources" }
