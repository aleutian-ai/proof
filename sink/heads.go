// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/internal/osfile"
)

// CheckpointHeads remembers, per chain, how many checkpoints exist and the
// last one's anchor chain hash.
//
// # Description
//
// A sink folder cannot vouch for its own checkpoints: with anchors/<chain>/
// removed, the next Checkpoint signs a new 0001.json over the chain as it
// stands, and nothing inside the folder remembers that a longer series
// existed. A CheckpointHeads is that memory, kept where the folder's writer
// cannot rewrite it. Checkpoint (TrackHeads) refuses to extend a series that
// is shorter than its head or differs from it, and records the new head after
// each checkpoint it writes; Verify (WithCheckpointHeads) reports the same as
// a problem. FileHeads is the implementation that ships.
//
// # Limitations
//
//   - It is asked about chains the evidence file holds. A chain removed whole,
//     entries and checkpoints both, is not noticed through it.
//   - It protects only against someone who cannot write it too.
//
// # Assumptions
//
//   - Implementations are safe for concurrent use.
type CheckpointHeads interface {
	// Head returns the head recorded for chain: how many checkpoints its series
	// had, and the anchor chain hash (the checkpoint's chain_hash field) of the
	// last. ok is false when none is recorded.
	Head(ctx context.Context, chain string) (count int, lastHash string, ok bool, err error)
	// SetHead records chain's head. It is called after a checkpoint was written
	// and made durable, with the series' new length and that checkpoint's
	// anchor chain hash.
	SetHead(ctx context.Context, chain string, count int, lastHash string) error
}

// headsBatch is implemented by a CheckpointHeads that can record several heads
// in one write. FileHeads does: it rewrites its whole file per write.
type headsBatch interface {
	setHeads(ctx context.Context, heads []chainHead) error
}

// headsFormat names the heads file's format.
const headsFormat = "aleutian.proof.sink.heads.v1"

// maxHeadsBytes caps the heads file (about five million chains).
const maxHeadsBytes = 1 << 30

// anchorHashPattern is an anchor chain hash: 128 lowercase hex.
var anchorHashPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

// chainHead is one chain's recorded head.
type chainHead struct {
	chain string
	count int
	hash  string
}

// headRecord is one chain's head as stored.
type headRecord struct {
	Checkpoints     int    `json:"checkpoints"`
	AnchorChainHash string `json:"anchor_chain_hash"`
}

// headsDocument is the heads file.
type headsDocument struct {
	Format string                `json:"format"`
	Heads  map[string]headRecord `json:"heads"`
}

// HeadsFile is a CheckpointHeads kept in one JSON file. See FileHeads.
//
// Safe for concurrent use within a process.
type HeadsFile struct {
	path string

	// start: made by NewFileHeads, so the file must not exist yet when it is
	// first read; started: that first read found it absent.
	start, started bool

	mu     sync.Mutex
	loaded bool
	stamp  os.FileInfo // the file the cache was read from; nil when it was absent
	heads  map[string]headRecord
}

// FileHeads returns a CheckpointHeads kept in one JSON file at path.
//
// # Description
//
// The file maps each chain id to its number of checkpoints and the last one's
// anchor chain hash. It is created by the first SetHead. Every write goes to a
// temporary file beside it, which is synced and renamed over it, and the
// folder is then synced: a crash leaves the old file or the new one, never
// half of either. A symlink at path is refused, for reading and for writing.
//
// Keep it OUTSIDE the sink folder, on storage whoever can write the sink
// folder cannot write: Checkpoint and Verify refuse a path inside the folder,
// where it would protect nothing. It lists chain ids, counts and hashes, as
// anchors/ does: no subject and no content, and still pseudonymous personal
// data.
//
// # Inputs
//
//   - path: the file; nothing is read or created until it is used
//
// # Outputs
//
//   - *HeadsFile: for TrackHeads and WithCheckpointHeads
//
// # Example
//
//	heads := sink.FileHeads("/var/lib/proof-heads/sink-data.heads.json")
//	done, err := s.Checkpoint(ctx, signer, nil, sink.TrackHeads(heads))
//	rep, err := s.Verify(ctx, keys, sink.WithCheckpointHeads(heads))
//
// # Limitations
//
//   - One checkpointing process at a time: two writing at once can lose one's
//     update, which leaves a head behind its series. That is not reported as a
//     problem, and the next Checkpoint records it again.
//   - The whole file is rewritten on every write (Checkpoint batches them).
//   - A head only grows: SetHead refuses a lower count, or another hash at the
//     same count. To restart a series on purpose, edit the file.
//
// # Assumptions
//
//   - The path's folder exists and is writable by the checkpointing process
//     only.
func FileHeads(path string) *HeadsFile { return &HeadsFile{path: path} }

// ErrHeadsFileMissing is returned when a heads file named by FileHeads does
// not exist. A missing record of a series is what deleting it looks like, so it
// is never taken as an empty one: start a record with NewFileHeads.
var ErrHeadsFileMissing = errors.New("sink: checkpoint heads: the heads file does not exist; it is the record " +
	"that a series was not restarted, so a missing one is refused. Start one with NewFileHeads " +
	"(`proof sink checkpoint --heads FILE --first`) only when this sink has no record yet")

// ErrHeadsFileExists is returned when NewFileHeads names a file that exists.
var ErrHeadsFileExists = errors.New("sink: checkpoint heads: the heads file already exists; a record is " +
	"started once (use FileHeads, without --first)")

// NewFileHeads is FileHeads for a record that does not exist yet: the first
// checkpoint of a sink, the one moment the writer is trusted on its word
// (docs/sink-format.md §5.2). The file must not exist when it is first read
// (ErrHeadsFileExists); it is created by the first SetHead, and from then on
// this HeadsFile is FileHeads.
func NewFileHeads(path string) *HeadsFile { return &HeadsFile{path: path, start: true} }

// Path returns the file's path.
func (h *HeadsFile) Path() string { return h.path }

// Head returns the head recorded for chain.
//
// # Inputs
//
//   - ctx: checked before reading
//   - chain: a chain id
//
// # Outputs
//
//   - count, lastHash: the recorded head
//   - ok: false when the file records none for chain (or, from NewFileHeads,
//     does not exist yet)
//   - error: ErrHeadsFileMissing, ErrHeadsFileExists, or the file could not
//     be read, is a symlink, or is not a heads file
//
// # Example
//
//	count, hash, ok, err := heads.Head(ctx, chain)
//
// # Limitations
//
//   - The file is read again whenever it changed on disk since the last call.
//
// # Assumptions
//
//   - None.
func (h *HeadsFile) Head(ctx context.Context, chain string) (int, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", false, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(); err != nil {
		return 0, "", false, err
	}
	r, ok := h.heads[chain]
	return r.Checkpoints, r.AnchorChainHash, ok, nil
}

// SetHead records chain's head and makes it durable before returning.
//
// # Inputs
//
//   - ctx: checked before writing
//   - chain: a chain id this sink mints
//   - count: the series' length, at least 1
//   - lastHash: the last checkpoint's anchor chain hash, 128 lowercase hex
//
// # Outputs
//
//   - error: an invalid argument; a head that would go backwards (a lower
//     count, or another hash at the same count); or the file could not be
//     read or written (it is then unchanged)
//
// # Example
//
//	err := heads.SetHead(ctx, chain, 3, signed.ChainHash)
//
// # Limitations
//
//   - As FileHeads'.
//
// # Assumptions
//
//   - The checkpoint the head names is already durable.
func (h *HeadsFile) SetHead(ctx context.Context, chain string, count int, lastHash string) error {
	return h.setHeads(ctx, []chainHead{{chain: chain, count: count, hash: lastHash}})
}

// setHeads records several heads in one write.
func (h *HeadsFile) setHeads(ctx context.Context, heads []chainHead) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(heads) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(); err != nil {
		return err
	}
	next := make(map[string]headRecord, len(h.heads)+len(heads))
	for k, v := range h.heads {
		next[k] = v
	}
	for _, u := range heads {
		if err := validHead(u.chain, u.count, u.hash); err != nil {
			return fmt.Errorf("sink: checkpoint heads: %w", err)
		}
		if old, ok := next[u.chain]; ok {
			if old.Checkpoints > u.count || (old.Checkpoints == u.count && old.AnchorChainHash != u.hash) {
				return fmt.Errorf("sink: checkpoint heads: chain %s has a head at checkpoint %04d; a head "+
					"only grows (refusing to record %04d over it)", u.chain, old.Checkpoints, u.count)
			}
		}
		next[u.chain] = headRecord{Checkpoints: u.count, AnchorChainHash: u.hash}
	}
	if err := h.write(next); err != nil {
		h.loaded = false // whatever is on disk now, read it again
		return err
	}
	return nil
}

// validHead checks one head's shape.
func validHead(chain string, count int, hash string) error {
	switch {
	case !ValidChainID(chain):
		return errors.New("not a chain id this sink mints")
	case count < 1:
		return fmt.Errorf("a head at checkpoint %d (a series starts at 1)", count)
	case !anchorHashPattern.MatchString(hash):
		return errors.New("an anchor chain hash that is not 128 lowercase hex")
	}
	return nil
}

// load reads the file into the cache unless the cache is of the file now on
// disk. The caller holds h.mu.
func (h *HeadsFile) load() error {
	if h.path == "" {
		return errors.New("sink: checkpoint heads: a file path is required")
	}
	fi, err := os.Lstat(h.path)
	switch {
	case errors.Is(err, os.ErrNotExist) && (h.started || (h.start && !h.loaded)):
		h.started = true
		h.loaded, h.stamp, h.heads = true, nil, map[string]headRecord{}
		return nil
	case errors.Is(err, os.ErrNotExist):
		return ErrHeadsFileMissing
	case err == nil && h.start && !h.started:
		return ErrHeadsFileExists
	case err != nil:
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("sink: checkpoint heads: %s is not a regular file (a symlink is never followed)",
			filepath.Base(h.path))
	}
	if h.loaded && h.stamp != nil && os.SameFile(h.stamp, fi) && h.stamp.Size() == fi.Size() &&
		h.stamp.ModTime().Equal(fi.ModTime()) {
		return nil
	}
	f, err := osfile.OpenNoFollow(h.path, os.O_RDONLY|osfile.NonBlock, 0)
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w (a symlink is never followed)", err)
	}
	defer f.Close()
	// What was opened, not what was named a moment ago.
	if fi, err = f.Stat(); err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("sink: checkpoint heads: %s is not a regular file", filepath.Base(h.path))
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxHeadsBytes+1))
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	if len(raw) > maxHeadsBytes {
		return fmt.Errorf("sink: checkpoint heads: %s is over the %d byte limit", filepath.Base(h.path), maxHeadsBytes)
	}
	var doc headsDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("sink: checkpoint heads: %s is not a heads file: %w", filepath.Base(h.path), err)
	}
	if doc.Format != headsFormat {
		return fmt.Errorf("sink: checkpoint heads: %s is not a heads file (format %q, want %q)",
			filepath.Base(h.path), doc.Format, headsFormat)
	}
	for chain, r := range doc.Heads {
		if err := validHead(chain, r.Checkpoints, r.AnchorChainHash); err != nil {
			return fmt.Errorf("sink: checkpoint heads: %s holds %w", filepath.Base(h.path), err)
		}
	}
	if doc.Heads == nil {
		doc.Heads = map[string]headRecord{}
	}
	h.loaded, h.stamp, h.heads = true, fi, doc.Heads
	return nil
}

// write replaces the file with heads: a temporary file beside it, synced,
// renamed over it, and the folder synced. The caller holds h.mu.
func (h *HeadsFile) write(heads map[string]headRecord) error {
	raw, err := json.MarshalIndent(headsDocument{Format: headsFormat, Heads: heads}, "", "  ")
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	raw = append(raw, '\n')
	dir, base := filepath.Split(h.path)
	if dir == "" {
		dir = "."
	}
	// Exclusive, with an unpredictable name: nothing planted beforehand can
	// receive the write.
	tf, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	tmp := tf.Name()
	fail := func(err error) error {
		tf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sink: checkpoint heads: write %s: %w", filepath.Base(h.path), err)
	}
	if _, err := tf.Write(raw); err != nil {
		return fail(err)
	}
	if err := tf.Sync(); err != nil {
		return fail(err)
	}
	if err := tf.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, h.path); err != nil {
		return fail(err)
	}
	if err := syncFile(dir); err != nil {
		return fmt.Errorf("sink: checkpoint heads: sync the folder of %s: %w", filepath.Base(h.path), err)
	}
	fi, err := os.Lstat(h.path)
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	h.loaded, h.stamp, h.heads = true, fi, heads
	return nil
}

// headsOutsideFolder refuses a HeadsFile kept inside the sink folder: whoever
// can rewrite the folder could rewrite it too. Other implementations keep
// their state wherever they keep it.
func (s *Sink) headsOutsideFolder(h CheckpointHeads) error {
	hf, ok := h.(*HeadsFile)
	if !ok {
		return nil
	}
	if hf.path == "" {
		return errors.New("sink: checkpoint heads: a file path is required")
	}
	inside, err := pathWithin(hf.path, s.dir)
	if err != nil {
		return fmt.Errorf("sink: checkpoint heads: %w", err)
	}
	if inside {
		return errors.New("sink: checkpoint heads: the heads file is inside the sink folder, where " +
			"whoever can rewrite the checkpoints can rewrite it too; keep it somewhere else")
	}
	return nil
}

// pathWithin reports whether path is dir itself or inside it. Both are made
// absolute, and the deepest part of each that exists is resolved through
// symlinks. The comparison ignores case, as the default macOS file system
// does: two paths differing only in case count as one, a refusal at worst.
func pathWithin(path, dir string) (bool, error) {
	p, err := resolveExistingPath(path)
	if err != nil {
		return false, err
	}
	d, err := resolveExistingPath(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(strings.ToLower(d), strings.ToLower(p))
	if err != nil {
		return false, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// resolveExistingPath makes path absolute and resolves symlinks in its deepest
// existing ancestor, keeping the part that does not exist yet as written.
func resolveExistingPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := abs; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// headProblem compares a chain's checkpoint series with its recorded head. It
// returns "" when the series is the head, or grew from it.
func headProblem(anchors []anchor.Anchor, count int, lastHash string) string {
	switch {
	case count < 1:
		return ""
	case len(anchors) < count:
		return fmt.Sprintf("the checkpoint series was cut or restarted: it holds %s, and checkpoint %04d was "+
			"recorded as its head", plural(len(anchors), "checkpoint", "checkpoints"), count)
	case anchors[count-1].ChainHash != lastHash:
		return fmt.Sprintf("the checkpoint series was cut or restarted: checkpoint %04d is not the one "+
			"recorded as its head (another anchor chain hash)", count)
	}
	return ""
}

// headRecorder collects the heads one Checkpoint run records and writes them
// in batches: a CheckpointHeads may rewrite its whole state per write.
type headRecorder struct {
	heads   CheckpointHeads
	pending []chainHead
}

// headBatchSize is how many heads are held before they are written.
const headBatchSize = 1024

// add queues a head, writing the queue when it is full.
func (r *headRecorder) add(ctx context.Context, chain string, count int, hash string) error {
	r.pending = append(r.pending, chainHead{chain: chain, count: count, hash: hash})
	if len(r.pending) >= headBatchSize {
		return r.flush(ctx)
	}
	return nil
}

// flush writes the queued heads.
func (r *headRecorder) flush(ctx context.Context) error {
	if len(r.pending) == 0 {
		return nil
	}
	pending := r.pending
	r.pending = nil
	if b, ok := r.heads.(headsBatch); ok {
		if err := b.setHeads(ctx, pending); err != nil {
			return fmt.Errorf("sink: record checkpoint heads: %w", err)
		}
		return nil
	}
	for _, h := range pending {
		if err := r.heads.SetHead(ctx, h.chain, h.count, h.hash); err != nil {
			return fmt.Errorf("sink: record checkpoint heads: %w", err)
		}
	}
	return nil
}
