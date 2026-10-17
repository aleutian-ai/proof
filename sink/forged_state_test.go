// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/linker"
)

// These tests write state into a folder the way someone with write access to
// its files, and no key, could: through the storage layer, never through the
// sink's own verbs.

// forgeMidChainErasure appends a keyless erasure record to chain, then one
// ordinary event with a valid commitment after it, and deletes the content and
// nonces of everything before the erasure. It touches the evidence file and the
// secrets file only: the subject index still binds the chain.
func forgeMidChainErasure(t *testing.T, s *Sink, chain string) {
	t.Helper()
	ctx := context.Background()
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	_, tail, err := st.ReadTail(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	rec := erasureRecord(tail)
	erasureID, _ := newEntryID()
	fillerID, _ := newEntryID()
	filler := []byte(`{"benign":"filler"}`)
	c, nonce, err := commitment.Salted(filler)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := linker.New(st)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = l.Append(ctx, chain, []linker.Input{
		{EntryID: erasureID, EntryType: EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: erasureHash(rec)},
		{EntryID: fillerID, EntryType: EntryTypeEvent, Timestamp: now.Add(time.Microsecond),
			IngestedAt: now.Add(time.Microsecond), ContentHash: c},
	})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()
	if err := sec.putAll(map[string]map[string]secret{chain: {erasureID: {content: rec}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.eraseChain(chain, map[string][]byte{erasureID: rec}); err != nil {
		t.Fatal(err)
	}
	if err := sec.putAll(map[string]map[string]secret{chain: {fillerID: {content: filler, nonce: nonce}}}); err != nil {
		t.Fatal(err)
	}
}

// TestVerify_EntriesAfterAnErasureAreAProblem: an erasure record in the middle
// of a chain does not make the entries before it lawfully erased. The record is
// keyless, so it can be written into the folder; Verify once counted from the
// last one, reported the destroyed evidence as "Erased: 3" with no problem, and
// the next Checkpoint signed over it.
func TestVerify_EntriesAfterAnErasureAreAProblem(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	forgeMidChainErasure(t, s, chain)

	rep, err := s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	cr := chainReport(t, rep, chain)
	if rep.OK() || len(cr.Problems) == 0 {
		t.Fatalf("a chain with a forged mid-chain erasure verified: %+v", cr)
	}
	if !strings.Contains(strings.Join(cr.Problems, "\n"), "FOLLOW an erasure record") {
		t.Fatalf("the problems do not name the erasure: %v", cr.Problems)
	}
	// The index still binds the chain to its subject, which no erased chain's does.
	if cr.Index != IndexRelinked {
		t.Errorf("index state = %s, want %s", cr.Index, IndexRelinked)
	}

	// And nothing is signed over it.
	done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	if p := problemFor(done, chain); !strings.Contains(p, "was not signed") {
		t.Fatalf("Checkpoint = %+v; want the chain refused", done)
	}
	if _, err := os.Stat(s.anchorDir(chain) + "/0002.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a checkpoint was signed over a chain that does not verify")
	}
}

// TestCheckpoint_SignsNothingThatDoesNotVerify: Checkpoint verifies a chain in
// full before signing it. It once ran the hash walk alone, so content that had
// been modified or deleted since the last checkpoint was signed over, and the
// signature then read as the operator's statement about that state.
func TestCheckpoint_SignsNothingThatDoesNotVerify(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, s *Sink, chain, id string){
		"content modified": func(t *testing.T, s *Sink, chain, id string) {
			if err := writeContent(s, chain, id, []byte("tampered")); err != nil {
				t.Fatal(err)
			}
		},
		"content deleted": func(t *testing.T, s *Sink, chain, id string) {
			if err := withSecrets(s, func(tx *bolt.Tx) error {
				return tx.Bucket(contentBucket).Delete(rowKey(chain, id))
			}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, signer, _ := setup(t)
			chain := cid(t, s, "u-81")
			// A new entry, so the chain has something to checkpoint.
			if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
				t.Fatal(err)
			}
			damage(t, s, chain, entryIDs(t, s, chain)[0])

			done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
			if err != nil {
				t.Fatal(err)
			}
			if p := problemFor(done, chain); !strings.Contains(p, "was not signed") {
				t.Fatalf("Checkpoint = %+v; want the chain refused", done)
			}
			if _, err := os.Stat(s.anchorDir(chain) + "/0002.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a checkpoint was signed over damaged content")
			}
		})
	}
}

// TestExport_RefusesContentThatDoesNotOpenItsCommitment: a disclosed event's
// content is checked against the entry's commitment before it is written.
// Modified content was once exported and counted as disclosed.
func TestExport_RefusesContentThatDoesNotOpenItsCommitment(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-81")
	if err := writeContent(s, chain, entryIDs(t, s, chain)[0], []byte("tampered")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	sum, err := s.Export(context.Background(), ExportSelection{Chains: []string{chain}, Disclose: DiscloseAll}, &buf)
	if !errors.Is(err, ErrExportUnrepresentable) {
		t.Fatalf("err = %v, summary %+v; want ErrExportUnrepresentable", err, sum)
	}
	if sum.Disclosed != 0 {
		t.Fatalf("the summary counts %d events as disclosed", sum.Disclosed)
	}
}

// TestVerify_ASideFileWithoutItsBucketsIsCorrupt: a secrets file or subject
// index replaced by an empty database fails Verify with ErrCorrupt, which the
// CLI reports as a failed verification. It was a plain error, exit 3: a missing
// file, not tampering.
func TestVerify_ASideFileWithoutItsBucketsIsCorrupt(t *testing.T) {
	for _, suffix := range []string{".secrets", ".subjects"} {
		t.Run(suffix, func(t *testing.T) {
			s, _, ring := setup(t)
			path := s.DBPath() + suffix
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			db, err := bolt.Open(path, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			rep, err := s.Verify(context.Background(), ring)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("err = %v (report OK: %v), want ErrCorrupt", err, rep.OK())
			}
		})
	}
}
