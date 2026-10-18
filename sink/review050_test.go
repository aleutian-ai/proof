// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

// Checkpoint heads and the erasure-unsigned rule, as the v0.5.0 pre-tag review
// attacked them.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	bolt "go.etcd.io/bbolt"
)

// readHeads reads the heads file.
func readHeads(t *testing.T, path string) map[string]headRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc headsDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Heads
}

// TestReview050_Heads_CutRestartLag — a cut series is refused; a restarted
// series is refused; a series one longer than its head (crash after the
// checkpoint, before the head) is recovered without --first; the checkpoint
// written is a v7 anchor with the v7 context, subject = chain id.
func TestReview050_Heads_CutRestartLag(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	hp := filepath.Join(t.TempDir(), "heads.json")

	// FileHeads on a missing file is refused; NewFileHeads starts it.
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp))); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing heads accepted: %v", err)
	}
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp))); err != nil {
		t.Fatal(err)
	}
	h := readHeads(t, hp)
	if h[chain].Checkpoints != 1 {
		t.Fatalf("head: %+v", h)
	}
	// NewFileHeads on an existing file is refused.
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp))); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("--first on an existing file: %v", err)
	}

	// The checkpoint file: v7, subject = chain id, verifies with the v7 context.
	raw, err := os.ReadFile(filepath.Join(s.dir, "anchors", chain, "0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.Version != 7 || a.Subject != chain || a.Range.StartSeq != 0 || a.Range.EndSeq != 1 || a.EntryCount != 2 {
		t.Errorf("checkpoint: %+v", a)
	}
	if _, err := anchor.VerifySignature(a, ring); err != nil {
		t.Errorf("checkpoint signature: %v", err)
	}
	if a.PreviousAnchorHash != anchor.SeedAnchorHash || a.PreviousAnchorID != anchor.SeedAnchorID {
		t.Errorf("first checkpoint predecessor: %s %s", a.PreviousAnchorID, a.PreviousAnchorHash[:8])
	}

	// Second checkpoint.
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp))); err != nil {
		t.Fatal(err)
	}
	h = readHeads(t, hp)
	if h[chain].Checkpoints != 2 {
		t.Fatalf("head after 2: %+v", h)
	}
	raw2, _ := os.ReadFile(filepath.Join(s.dir, "anchors", chain, "0002.json"))

	// Cut: delete 0002. Verify reports; Checkpoint refuses.
	if err := os.Remove(filepath.Join(s.dir, "anchors", chain, "0002.json")); err != nil {
		t.Fatal(err)
	}
	r := verifyWith(t, s, ring, WithCheckpointHeads(FileHeads(hp)))
	if cr := chainReport(t, r, chain); !hasProblemWith(cr, "cut or restarted") {
		t.Errorf("cut series not reported: %+v", cr)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	done, err := s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp)))
	if err != nil || !strings.Contains(problemFor(done, chain), "cut or restarted") {
		t.Errorf("cut series extended: %+v %v", done, err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "anchors", chain, "0003.json")); err == nil {
		t.Error("a checkpoint was written on a cut series")
	}
	// Restore 0002: the series is the head again; checkpoint 3 is written.
	if err := os.WriteFile(filepath.Join(s.dir, "anchors", chain, "0002.json"), raw2, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp))); err != nil {
		t.Fatal(err)
	}
	if h = readHeads(t, hp); h[chain].Checkpoints != 3 {
		t.Fatalf("head after restore: %+v", h)
	}

	// Restart: remove the whole anchors/<chain> folder; a new 0001 must not
	// be written, and verify reports.
	if err := os.RemoveAll(filepath.Join(s.dir, "anchors", chain)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	done, err = s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp)))
	if err != nil || !strings.Contains(problemFor(done, chain), "cut or restarted") {
		t.Errorf("restarted series extended: %+v %v", done, err)
	}
	r = verifyWith(t, s, ring, WithCheckpointHeads(FileHeads(hp)))
	if cr := chainReport(t, r, chain); !hasProblemWith(cr, "cut or restarted") {
		t.Errorf("restart not reported: %+v", cr)
	}

	// Lag: with the folder untouched, roll the heads file back by one
	// (crash after writing the checkpoint, before the head). Checkpoint
	// without --first verifies the chain and records the head; a verify
	// reports no problem (a series longer than its head is not one).
	s2, _ := Open(t.TempDir())
	if _, err := s2.Commit(ctx, events("u-9", 2)); err != nil {
		t.Fatal(err)
	}
	chain2 := cid(t, s2, "u-9")
	hp2 := filepath.Join(t.TempDir(), "heads2.json")
	if _, err := s2.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp2))); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := os.ReadFile(hp2)
	if _, err := s2.Commit(ctx, events("u-9", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp2))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hp2, snapshot, 0o600); err != nil { // the head lags: 1, series has 2
		t.Fatal(err)
	}
	r = verifyWith(t, s2, ring, WithCheckpointHeads(FileHeads(hp2)))
	if cr := chainReport(t, r, chain2); len(cr.Problems) != 0 {
		t.Errorf("lagging head reported as a problem: %+v", cr)
	}
	done, err = s2.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(hp2)))
	if err != nil || problemFor(done, chain2) != "" {
		t.Errorf("lagging head: %+v %v", done, err)
	}
	if h = readHeads(t, hp2); h[chain2].Checkpoints != 2 {
		t.Errorf("lagging head not caught up: %+v", h)
	}
	// A head that lags AND whose series was then cut back to the head: fine
	// (it is the head). A head that lags by one and the series was cut to
	// the head MINUS one: refused.
	if err := os.Remove(filepath.Join(s2.dir, "anchors", chain2, "0002.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hp2, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	r = verifyWith(t, s2, ring, WithCheckpointHeads(FileHeads(hp2)))
	if cr := chainReport(t, r, chain2); len(cr.Problems) != 0 {
		t.Errorf("series == lagging head reported: %+v", cr)
	}
	// Now the attacker's window: a head that lags by one lets the attacker
	// delete the newest checkpoint undetected. Inherent (documented: "a crash
	// between the two").
}

// TestReview050_Heads_FirstRaceAndPrePlant — NewFileHeads "once": the file's
// absence is checked at first read, and the write is a rename, which
// overwrites a file planted (or written by a second --first process) in
// between.
func TestReview050_Heads_FirstRaceAndPrePlant(t *testing.T) {
	ctx := context.Background()
	hp := filepath.Join(t.TempDir(), "heads.json")
	chain := "ev_" + strings.Repeat("ab", 16) // shape only
	if !ValidChainID(chain) {
		// find a valid id
		s, _ := Open(t.TempDir())
		if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
			t.Fatal(err)
		}
		chain = cid(t, s, "u-1")
	}
	h1 := NewFileHeads(hp)
	h2 := NewFileHeads(hp)
	// Both read first (both see the file absent).
	if _, _, ok, err := h1.Head(ctx, chain); err != nil || ok {
		t.Fatal(err)
	}
	if _, _, ok, err := h2.Head(ctx, chain); err != nil || ok {
		t.Fatal(err)
	}
	if err := h1.SetHead(ctx, chain, 5, strings.Repeat("a", 128)); err != nil {
		t.Fatal(err)
	}
	// The second "first" process writes over it: the record of 5 is lost.
	err := h2.SetHead(ctx, chain, 1, strings.Repeat("b", 128))
	got := readHeads(t, hp)
	if err == nil || got[chain].Checkpoints != 5 {
		t.Errorf("a second NewFileHeads wrote over the first's record: err=%v, head now %+v", err, got[chain])
	}
	// Pre-planted between first read and write, from outside.
	hp3 := filepath.Join(t.TempDir(), "heads3.json")
	h3 := NewFileHeads(hp3)
	if _, _, _, err := h3.Head(ctx, chain); err != nil {
		t.Fatal(err)
	}
	planted := `{"format":"aleutian.proof.sink.heads.v1","heads":{"` + chain + `":{"checkpoints":9,"anchor_chain_hash":"` + strings.Repeat("c", 128) + `"}}}`
	if err := os.WriteFile(hp3, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	err = h3.SetHead(ctx, chain, 1, strings.Repeat("d", 128))
	got = readHeads(t, hp3)
	if err == nil || got[chain].Checkpoints != 9 {
		t.Errorf("a file planted between the first read and the write was replaced: err=%v, head now %+v", err, got[chain])
	}
	// Symlink at the path: refused for reading; and for writing?
	hp4 := filepath.Join(t.TempDir(), "heads4.json")
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, hp4); err != nil {
		t.Fatal(err)
	}
	h4 := FileHeads(hp4)
	_, _, _, err = h4.Head(ctx, chain)
	t.Logf("symlink heads file read: %v", err)
	if err == nil {
		t.Error("symlink followed")
	}
	// And when the symlink appears after a successful load (TOCTOU on write):
	// the write renames the temp file over the symlink itself; the target is
	// untouched.
	hp5 := filepath.Join(t.TempDir(), "heads5.json")
	h5 := NewFileHeads(hp5)
	if _, _, _, err := h5.Head(ctx, chain); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, hp5); err != nil {
		t.Fatal(err)
	}
	err = h5.SetHead(ctx, chain, 1, strings.Repeat("d", 128))
	keep, _ := os.ReadFile(target)
	fi, _ := os.Lstat(hp5)
	t.Logf("symlink planted before write: err=%v target=%q path is symlink=%v", err, keep, fi != nil && fi.Mode()&os.ModeSymlink != 0)
	if string(keep) != "keep" {
		t.Error("symlink target clobbered")
	}
}

// TestReview050_ErasureUnsigned_Bypasses — can a signing sink's forged erasure
// avoid erasure-unsigned? A junk signature row with the erasure's entry id,
// a row replayed from another entry, a signing mode cleared, an emptied
// signatures file; and does any of these get the forged erasure
// CHECKPOINTED (the thing that matters)?
func TestReview050_ErasureUnsigned_Bypasses(t *testing.T) {
	ctx := context.Background()
	signer, ring := newSigner(t)
	hp := filepath.Join(t.TempDir(), "heads.json")

	type variant struct {
		name  string
		plant func(t *testing.T, s *Sink, chain, forgedID string)
	}
	variants := []variant{
		{"no row (baseline)", func(t *testing.T, s *Sink, chain, id string) {}},
		{"junk row of the right size", func(t *testing.T, s *Sink, chain, id string) {
			withSignatures(t, s, func(b *bolt.Bucket) error {
				return b.Put(rowKey(chain, id), make([]byte, signatureRowSize))
			})
		}},
		{"malformed short row", func(t *testing.T, s *Sink, chain, id string) {
			withSignatures(t, s, func(b *bolt.Bucket) error {
				return b.Put(rowKey(chain, id), []byte("x"))
			})
		}},
		{"row replayed from entry 0 of the same chain", func(t *testing.T, s *Sink, chain, id string) {
			ids := entryIDs(t, s, chain)
			withSignatures(t, s, func(b *bolt.Bucket) error {
				v := b.Get(rowKey(chain, ids[0]))
				return b.Put(rowKey(chain, id), append([]byte(nil), v...))
			})
		}},
		{"signatures file emptied of rows, mode kept", func(t *testing.T, s *Sink, chain, id string) {
			withSignatures(t, s, func(b *bolt.Bucket) error {
				var keys [][]byte
				_ = b.ForEach(func(k, _ []byte) error { keys = append(keys, append([]byte(nil), k...)); return nil })
				for _, k := range keys {
					if err := b.Delete(k); err != nil {
						return err
					}
				}
				return nil
			})
		}},
		{"signatures file deleted", func(t *testing.T, s *Sink, chain, id string) {
			if err := os.Remove(s.signaturesPath()); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			rs := testRecordSigner(t, 7)
			s := openSigning(t, t.TempDir(), rs)
			if _, err := s.Commit(ctx, append(events("u-1", 3), events("u-2", 2)...)); err != nil {
				t.Fatal(err)
			}
			chain := cid(t, s, "u-1")
			if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp+v.name))); err != nil {
				t.Fatal(err)
			}
			forged := forgeErasure(t, s, chain)
			dropIndexRows(t, s, "u-1")
			v.plant(t, s, chain, forged)

			r := verifyWith(t, s, ring)
			cr := chainReport(t, r, chain)
			rt := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs)))
			crt := chainReport(t, rt, chain)
			t.Logf("verify: index=%s unsigned-reported=%v problems=%v", cr.Index, hasProblemWith(cr, "erasure-unsigned"), cr.Problems)
			t.Logf("verify --record-trust: index=%s problems=%v", crt.Index, crt.Problems)
			// Without keys, a row that is absent, malformed, or not by one of
			// the folder's record keys signs nothing. A genuine row replayed
			// from another record, or a signatures file deleted with its mode,
			// takes the record key to see; record trust sees every variant.
			keyless := v.name != "row replayed from entry 0 of the same chain" && v.name != "signatures file deleted"
			if keyless && !hasProblemWith(cr, "erasure-unsigned") {
				t.Errorf("plain verify does not report erasure-unsigned: %v", cr.Problems)
			}
			if len(crt.Problems) == 0 {
				t.Errorf("verify with record trust reports nothing")
			}

			// The gate that matters: does a routine checkpoint sign over it?
			for name, opts := range map[string][]CheckpointOption{
				"plain":        {TrackHeads(FileHeads(hp + v.name))},
				"record-trust": {TrackHeads(FileHeads(hp + v.name)), CheckpointRecordTrust(recordRing(t, rs))},
			} {
				done, err := s.Checkpoint(ctx, signer, nil, opts...)
				if err != nil {
					t.Logf("checkpoint %s: error %v", name, err)
					continue
				}
				p := problemFor(done, chain)
				if p == "" {
					t.Errorf("checkpoint %s SIGNED over the forged erasure", name)
				} else {
					t.Logf("checkpoint %s refused: %s", name, p)
				}
				if _, err := os.Stat(filepath.Join(s.dir, "anchors", chain, "0002.json")); err == nil {
					t.Errorf("checkpoint %s wrote 0002.json over the forged erasure", name)
				}
			}
		})
	}
}

// TestReview050_ErasureUnsigned_KeyRotation — the sink's own erasure signed with
// an OLD record key; record trust given the NEW key only: R6 does not apply
// (unknown key), the chain stays erased-unanchored with a problem, and the
// checkpoint with record trust refuses. With both keys, it passes. The
// erasure-unsigned rule itself does not fire (a row exists).
func TestReview050_ErasureUnsigned_KeyRotation(t *testing.T) {
	ctx := context.Background()
	signer, ring := newSigner(t)
	old := testRecordSigner(t, 7)
	dir := t.TempDir()
	s := openSigning(t, dir, old)
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil { // signed with old
		t.Fatal(err)
	}
	newKey := testRecordSigner(t, 9)
	s2 := openSigning(t, dir, newKey)
	hp := filepath.Join(t.TempDir(), "heads.json")
	done, err := s2.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp)), CheckpointRecordTrust(recordRing(t, newKey)))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("new key only: %q", problemFor(done, chain))
	if problemFor(done, chain) == "" {
		t.Error("checkpointed an erasure signed by an untrusted (old) key")
	}
	done, err = s2.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp)), CheckpointRecordTrust(recordRing(t, old, newKey)))
	if err != nil || problemFor(done, chain) != "" {
		t.Errorf("both keys: %+v %v", done, err)
	}
	r := verifyWith(t, s2, ring, WithRecordTrust(recordRing(t, old, newKey)))
	if cr := chainReport(t, r, chain); cr.Index != IndexErased || len(cr.Problems) != 0 {
		t.Errorf("after rotation+checkpoint: %+v", cr)
	}
}

// TestReview050_Checkpoint_V6InSeries — sink-format §5: a checkpoint is a v7
// anchor. A v6 one, signed by the trusted key, is a problem and is not
// extended.
func TestReview050_Checkpoint_V6InSeries(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	ids := entryIDs(t, s, chain)
	st, _ := s.openStore(true)
	es, err := readChain(ctx, st, chain)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := anchor.ChainHash(anchor.SeedAnchorHash, chain, ids[0], ids[1], es[1].ChainHash)
	v6 := anchor.Anchor{Version: 6, AnchorID: "anchor_01234567-8901-4345-8789-012345678901", Subject: chain, ChainHash: ch,
		Range: anchor.EntryRange{StartEntryID: ids[0], EndEntryID: ids[1]}, EntryCount: 2, VerifiedThrough: 2,
		CreatedAtMs: 1, PreviousAnchorID: anchor.SeedAnchorID}
	v6, err = anchor.SignAnchor(ctx, signer, v6)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(v6, "", "  ")
	if err := os.MkdirAll(filepath.Join(s.dir, "anchors", chain), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "anchors", chain, "0001.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	r := verifyWith(t, s, ring)
	cr := chainReport(t, r, chain)
	if cr.Checkpoints != 0 || !hasProblemWith(cr, "v6 anchor") {
		t.Errorf("a v6 checkpoint in a sink folder: %d verified, problems %v", cr.Checkpoints, cr.Problems)
	}
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	hp := filepath.Join(t.TempDir(), "heads.json")
	done, err := s.Checkpoint(ctx, signer, nil, TrackHeads(NewFileHeads(hp)))
	if err == nil && problemFor(done, chain) == "" {
		t.Errorf("a series holding a v6 checkpoint was extended: %+v", done)
	}
}

// TestReview050_Heads_DeletedAfterStart — a NewFileHeads that started the file
// and wrote it treats a later absence as ErrHeadsFileMissing, as FileHeads
// does: in a long-lived process the refusal is not lost once the file is
// deleted.
func TestReview050_Heads_DeletedAfterStart(t *testing.T) {
	ctx := context.Background()
	hp := filepath.Join(t.TempDir(), "heads.json")
	s, _ := Open(t.TempDir())
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	h := NewFileHeads(hp)
	if err := h.SetHead(ctx, chain, 3, strings.Repeat("a", 128)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hp); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := h.Head(ctx, chain)
	if ok || !errors.Is(err, ErrHeadsFileMissing) {
		t.Errorf("after the started file was deleted: ok=%v err=%v", ok, err)
	}
	// A plain FileHeads refuses.
	if _, _, _, err := FileHeads(hp).Head(ctx, chain); err == nil {
		t.Error("FileHeads accepted a missing file")
	}
}
