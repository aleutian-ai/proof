// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// _74c review fixes.

// #1: checkpoints are still files. A chain's anchors folder that is a symlink,
// to outside the sink or to another chain's folder, is refused: never written
// through, and reported by Verify. So is anchors/ itself as a symlink.
func TestAnchorsSymlinkedFolders(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, s *Sink) (outside string){
		"a chain's folder links outside the sink": func(t *testing.T, s *Sink) string {
			out := t.TempDir()
			dir := s.anchorDir(cid(t, s, "u-81"))
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(out, dir); err != nil {
				t.Fatal(err)
			}
			return out
		},
		"a chain's folder links to another chain's": func(t *testing.T, s *Sink) string {
			dir := s.anchorDir(cid(t, s, "u-81"))
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(s.anchorDir(cid(t, s, "u-82")), dir); err != nil {
				t.Fatal(err)
			}
			return ""
		},
		"anchors/ itself is a symlink": func(t *testing.T, s *Sink) string {
			out := t.TempDir()
			dir := filepath.Join(s.dir, "anchors")
			if err := os.Rename(dir, filepath.Join(out, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(out, "moved"), dir); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(out, "moved")
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			s, signer, ring := setup(t)
			outside := plant(t, s)
			var before []string
			if outside != "" {
				before = listAll(t, outside)
			}
			// A new event, so Checkpoint has something to sign.
			if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
				t.Fatal(err)
			}
			_, _ = s.Checkpoint(ctx, signer, nil)
			if outside != "" && len(listAll(t, outside)) != len(before) {
				t.Fatal("Checkpoint wrote through a symlinked folder")
			}
			// Refused either way: reported on the chain, or (anchors/ itself, which
			// os.Root will not follow) the whole read fails.
			r, err := s.Verify(ctx, ring)
			if err == nil && r.OK() {
				t.Fatalf("Verify passed with a symlinked anchors folder: %+v", r)
			}
		})
	}
}

func listAll(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err == nil {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// #2 (E1): an erasure whose file rewrite failed leaves its chains PENDING, so
// Verify reports them and says to resume; the resume completes the rewrite.
func TestErase_CompactionFailureLeavesChainsPending(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	restore := failCompaction(s, ".secrets")
	if _, err := s.EraseSubject(ctx, "u-1"); err == nil {
		t.Fatal("a failed rewrite was not reported")
	}
	restore()
	cr := chainReport(t, verifyAll(t, s), chains["payments/u-1"])
	if cr.Index != IndexPending || !hasProblem(cr, "erase --resume") {
		t.Fatalf("an erasure whose rewrite failed is not reported pending: %+v", cr)
	}
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	if got := pendingChains(t, s); len(got) != 0 {
		t.Fatalf("still pending after the resume rewrote the files: %v", got)
	}
}

// #3: a failed Commit whose cleanup ALSO failed keeps the new pairs' index rows,
// so erasing the subject still reaches the content left behind.
func TestCommit_CleanupFailureKeepsRowsErasable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	failAppends(s)
	s.wrapSecrets = func(w secretsWriter) secretsWriter { return failingDelete{w} }
	if _, err := s.Commit(ctx, events("u-1", 2)); err == nil {
		t.Fatal("the failure was not reported")
	}
	s.wrapAppender, s.wrapSecrets = nil, nil
	chain := cid(t, s, "u-1") // still bound
	if ids := contentRows(t, s, chain); len(ids) != 2 {
		t.Fatalf("test setup: %d content rows left, want 2", len(ids))
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if ids := contentRows(t, s, chain); len(ids) != 0 {
		t.Fatalf("erasing the subject did not reach the leftover content: %v", ids)
	}
}

type failingDelete struct{ secretsWriter }

func (failingDelete) deleteRows(map[string][]string) error {
	return errors.New("injected: delete failed")
}

func contentRows(t *testing.T, s *Sink, chain string) []string {
	t.Helper()
	sec, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
	if err != nil || sec == nil {
		t.Fatalf("open secrets: %v", err)
	}
	defer sec.Close()
	ids, err := sec.rowIDs(chain)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// #4: the erasure's append reports an error although it committed. The record
// row is kept (not deleted), so the chain verifies.
type appendLandedThenFailed struct{ real *linker.Linker }

func (a appendLandedThenFailed) Append(ctx context.Context, chain string, in []linker.Input) (linker.Result, error) {
	res, err := a.real.Append(ctx, chain, in)
	if err != nil {
		return res, err
	}
	return res, errors.New("injected: error after the commit")
}

func TestEraseChain_AppendThatLandedKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	st, sec, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.eraseChain(ctx, st, sec, appendLandedThenFailed{real: l}, chain)
	sec.Close()
	st.Close()
	if err != nil {
		t.Fatalf("an erasure that landed was reported as failed: %v", err)
	}
	if _, err := readContent(s, chain, res.ErasureEntryID); err != nil {
		t.Fatalf("the landed erasure's record row was deleted: %v", err)
	}
}

// #4, repair: a genuine erasure whose record row is missing gets it back on the
// next erasure of the chain (it is public and fixed).
func TestEraseChain_RestoresAMissingRecord(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	res, err := s.EraseSubjectClass(ctx, "u-1", "auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := removeContent(s, chain, res.Erased[0].ErasureEntryID); err != nil {
		t.Fatal(err)
	}
	markPending(t, s, chain)
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := readContent(s, chain, res.Erased[0].ErasureEntryID); err != nil || !bytes.HasPrefix(got, []byte(`{"erased":`)) {
		t.Fatalf("the missing record was not restored: %q, %v", got, err)
	}
	if cr := chainReport(t, verifyAll(t, s), chain); len(cr.Problems) != 0 {
		t.Fatalf("the chain does not verify after the repair: %+v", cr)
	}
}

func markPending(t *testing.T, s *Sink, chain string) {
	t.Helper()
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).Put([]byte(chain), pendingMarker)
	}); err != nil {
		t.Fatal(err)
	}
}

// #8: a row keyed off the sink's layout (no entry id) is reported, by count;
// a bare-chain key is also removed by erasure; a nonce-only orphan on a live
// chain is reported; a nonce beside an erasure record is flagged.
func TestVerify_RowsOffTheKeyLayout(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["payments/u-2"]
	if err := withSecrets(s, func(tx *bolt.Tx) error {
		if err := tx.Bucket(contentBucket).Put([]byte(chain), []byte(`{"user":"u-2","hidden":1}`)); err != nil {
			return err
		}
		return tx.Bucket(noncesBucket).Put(secretKey(chain, "sink-"+strings.Repeat("9", 32)), make([]byte, 32))
	}); err != nil {
		t.Fatal(err)
	}
	r := verifyAll(t, s)
	if r.OK() {
		t.Fatal("Verify passed with planted rows")
	}
	found := false
	for _, c := range r.Chains {
		if strings.HasPrefix(c.Chain, "<invalid secrets row") && hasProblem(c, "1 rows whose key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the off-layout row was not reported: %+v", r)
	}
	if cr := chainReport(t, r, chain); !hasProblem(cr, "sink-"+strings.Repeat("9", 32)) {
		t.Fatalf("the nonce-only orphan was not reported: %+v", cr)
	}
	if _, err := s.EraseSubject(ctx, "u-2"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(s.secretsPath())
	if bytes.Contains(raw, []byte(`"hidden":1`)) {
		t.Fatal("a row keyed by the bare chain id survived the subject's erasure")
	}
}

func TestVerify_NonceBesideAnErasureRecord(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	res, err := s.EraseSubjectClass(ctx, "u-1", "auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNonce(s, chain, res.Erased[0].ErasureEntryID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if cr := chainReport(t, verifyAll(t, s), chain); !hasProblem(cr, "nonce stored beside it") {
		t.Fatalf("a nonce beside an erasure record was not flagged: %+v", cr)
	}
}

// #9: a row under an entry id this sink never assigns is counted, never shown.
func TestVerify_InvalidEntryIDsAreNotPrinted(t *testing.T) {
	s, chains := multi(t)
	chain := chains["payments/u-2"]
	if err := writeContent(s, chain, "jo@example.com", []byte("x")); err != nil {
		t.Fatal(err)
	}
	cr := chainReport(t, verifyAll(t, s), chain)
	if !hasProblem(cr, "entry id this sink never assigns") {
		t.Fatalf("the row was not reported: %+v", cr)
	}
	for _, p := range cr.Problems {
		if strings.Contains(p, "jo@example.com") {
			t.Fatalf("a crafted entry id was printed: %q", p)
		}
	}
}

// #10: a nonce of the wrong length opens nothing (and is not copied whole).
func TestVerify_WrongLengthNonce(t *testing.T) {
	s, chains := multi(t)
	chain := chains["payments/u-2"]
	id := entryIDs(t, s, chain)[0]
	if err := writeNonce(s, chain, id, make([]byte, 1<<16)); err != nil {
		t.Fatal(err)
	}
	if cr := chainReport(t, verifyAll(t, s), chain); cr.Opened != 0 || len(cr.Problems) == 0 {
		t.Fatalf("a wrong-length nonce opened the event: %+v", cr)
	}
}

// #12: leftover compaction copies are removed even when the file is gone.
func TestCompactFile_LeftoversWithoutTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	left := path + ".compact-123"
	if err := os.WriteFile(left, []byte("a copy of a secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := compactFile(path, DefaultLockTimeout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a leftover copy survived because its file was missing")
	}
}

// #13: a secrets file without its buckets is refused, not read.
func TestVerify_RefusesASecretsFileWithoutBuckets(t *testing.T) {
	s, _, ring := setup(t)
	if err := os.Remove(s.secretsPath()); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(s.secretsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := s.Verify(context.Background(), ring); err == nil || !strings.Contains(err.Error(), "not a secrets file") {
		t.Fatalf("err = %v; want the file refused", err)
	}
}

// #13: a symlinked secrets file is refused by every verb, not only Commit.
func TestSymlinkedSecretsFileIsRefusedEverywhere(t *testing.T) {
	ctx := context.Background()
	verbs := map[string]func(s *Sink) error{
		"commit": func(s *Sink) error { _, err := s.Commit(ctx, events("u-9", 1)); return err },
		"verify": func(s *Sink) error {
			_, ring := newSigner(t)
			_, err := s.Verify(ctx, ring)
			return err
		},
		"erase": func(s *Sink) error { _, err := s.EraseSubject(ctx, "u-81"); return err },
	}
	for name, verb := range verbs {
		t.Run(name, func(t *testing.T) {
			s, _, _ := setup(t)
			elsewhere := filepath.Join(t.TempDir(), "elsewhere.db")
			if err := os.Rename(s.secretsPath(), elsewhere); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, s.secretsPath()); err != nil {
				t.Fatal(err)
			}
			if err := verb(s); err == nil {
				t.Fatalf("%s accepted a symlinked secrets file", name)
			}
		})
	}
}

// #15: every chain with secrets rows is found, not only the first in key order.
// Rows for two chains the evidence file does not hold (sorting after the real
// ones) are both reported as removed.
func TestVerify_FindsEveryChainWithRows(t *testing.T) {
	s, _, _ := setup(t)
	ghosts := []string{"zz." + strings.Repeat("1", 32), "zz." + strings.Repeat("2", 32)}
	for _, g := range ghosts {
		if err := writeContent(s, g, "sink-"+strings.Repeat("3", 32), []byte(`{"user":"gone"}`)); err != nil {
			t.Fatal(err)
		}
	}
	r := verifyAll(t, s)
	for _, g := range ghosts {
		if cr := chainReport(t, r, g); len(cr.Problems) == 0 {
			t.Fatalf("rows of a removed chain %s were not reported: %+v", g, cr)
		}
	}
}

// #10, at the store: a wrong-length nonce comes back empty (present, but opens
// nothing), and oversized content is flagged, not copied.
func TestSecretsGet_SizeChecks(t *testing.T) {
	s, chains := multi(t)
	chain := chains["payments/u-2"]
	id := entryIDs(t, s, chain)[0]
	if err := writeNonce(s, chain, id, make([]byte, 1<<16)); err != nil {
		t.Fatal(err)
	}
	if err := writeContent(s, chain, id, make([]byte, MaxContentBytes+1)); err != nil {
		t.Fatal(err)
	}
	sec, err := openSecretsReadOnly(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()
	content, nonce, tooBig, err := sec.get(chain, id)
	if err != nil {
		t.Fatal(err)
	}
	if nonce == nil || len(nonce) != 0 {
		t.Fatalf("a %d-byte nonce came back as %d bytes (nil: %t); want present and empty", 1<<16, len(nonce), nonce == nil)
	}
	if !tooBig || content != nil {
		t.Fatalf("oversized content: tooBig=%t, %d bytes copied", tooBig, len(content))
	}
}
