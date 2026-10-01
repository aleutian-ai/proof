// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// _75c: record signing in Commit and erase.

// scriptedSigner wraps a real signer. Safe for concurrent use. Call failAt
// (1-based, in call order) fails, or, with other set, is signed by another key
// from then on (a signer rotated mid-call). It tracks how many calls are in
// flight at once.
type scriptedSigner struct {
	real   *MLDSA65RecordSigner
	other  *MLDSA65RecordSigner
	failAt int64
	delay  time.Duration

	calls, inFlight, maxInFlight atomic.Int64
}

func (s *scriptedSigner) Public() crypto.PublicKey { return s.real.Public() }

func (s *scriptedSigner) SignRecord(ctx context.Context, env []byte) ([]byte, error) {
	n := s.calls.Add(1)
	cur := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		m := s.maxInFlight.Load()
		if cur <= m || s.maxInFlight.CompareAndSwap(m, cur) {
			break
		}
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.failAt > 0 && n >= s.failAt {
		if s.other != nil {
			return s.other.SignRecord(ctx, env)
		}
		if n == s.failAt {
			return nil, errors.New("injected: signer failed")
		}
	}
	return s.real.SignRecord(ctx, env)
}

func openSigning(t *testing.T, dir string, rs RecordSigner, opts ...Option) *Sink {
	t.Helper()
	s, err := Open(dir, append([]Option{WithRecordSigner(rs)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// checkRecordSignatures verifies every entry of chain against its signature
// row under pub: the envelope rebuilt from the stored entry, previous_hash the
// previous entry's chain hash. It returns how many entries it checked.
func checkRecordSignatures(t *testing.T, s *Sink, chain string, pub []byte) int {
	t.Helper()
	ctx := context.Background()
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sig, err := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout)
	if err != nil || sig == nil {
		t.Fatalf("no signatures file (%v)", err)
	}
	defer sig.Close()
	rows, err := st.Range(ctx, chain, 0, 1<<62, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range rows {
		row, found, malformed, err := sig.get(chain, e.EntryID)
		if err != nil || !found || malformed {
			t.Fatalf("entry %d: signature found %t malformed %t (%v)", i, found, malformed, err)
		}
		if i > 0 && e.PreviousHash != rows[i-1].ChainHash {
			t.Fatalf("entry %d does not link to %d", i, i-1)
		}
		f := recordFields{chainID: chain, entryID: e.EntryID, entryType: e.EntryType, globalSeq: e.GlobalSeq,
			prevHash: e.PreviousHash, timestamp: e.Timestamp, contentHash: e.ContentHash, keyID: row.keyID}
		if err := verifyRecordSignature(pub, f, row.sig); err != nil {
			t.Fatalf("entry %d (%s): %v", i, e.EntryType, err)
		}
	}
	return len(rows)
}

// sinkUntouched fails unless a sink that had nothing committed still has nothing:
// no entries, no live index rows, no secrets rows, no signing mode or rows.
func sinkUntouched(t *testing.T, s *Sink) {
	t.Helper()
	ctx := context.Background()
	if _, err := os.Stat(s.DBPath()); err == nil {
		st, err := s.openStore(true)
		if err != nil {
			t.Fatal(err)
		}
		chains, _ := st.Chains(ctx)
		st.Close()
		if len(chains) != 0 {
			t.Fatalf("%d chains were written", len(chains))
		}
	}
	if n, err := secretRowCount(s); err != nil || n != 0 {
		t.Fatalf("%d secrets rows remain (%v)", n, err)
	}
	if subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout); err == nil {
		live, _ := subj.liveChains()
		subj.Close()
		if len(live) != 0 {
			t.Fatalf("%d index rows remain", len(live))
		}
	}
	if sig, _ := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout); sig != nil {
		defer sig.Close()
		if on, _ := sig.signing(); on {
			t.Fatal("the sink was switched to signing")
		}
	}
}

// TestCommit_SignsEveryRecord: every entry, on a fresh chain and on one it
// extends, has a signature that verifies over the envelope rebuilt from the
// stored entry, chained through previous_hash.
func TestCommit_SignsEveryRecord(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(ctx, append(events("u-1", 3), events("u-2", 2)...)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, cid(t, s, "u-1"), key.pub); n != 5 {
		t.Fatalf("checked %d entries, want 5", n)
	}
	if n := checkRecordSignatures(t, s, cid(t, s, "u-2"), key.pub); n != 2 {
		t.Fatalf("checked %d entries, want 2", n)
	}
	sig, _ := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout)
	defer sig.Close()
	if has, _ := sig.hasRecordKey(key.id); !has {
		t.Fatal("the record key was not recorded")
	}
}

// TestCommit_SignerFailureLeavesNothing (C5): a signer that fails on any one
// record, that rotates to another key mid-call, or that is cancelled: every
// signature is checked before any write, so nothing remains and the sink is
// not switched to signing.
func TestCommit_SignerFailureLeavesNothing(t *testing.T) {
	cases := map[string]func(t *testing.T) *scriptedSigner{
		"fails on record 3": func(t *testing.T) *scriptedSigner {
			return &scriptedSigner{real: testRecordSigner(t, 7), failAt: 3}
		},
		"rotated from record 2": func(t *testing.T) *scriptedSigner {
			return &scriptedSigner{real: testRecordSigner(t, 7), other: testRecordSigner(t, 8), failAt: 2}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s := openSigning(t, t.TempDir(), mk(t))
			if _, err := s.Commit(context.Background(), append(events("u-1", 3), events("u-2", 2)...)); err == nil {
				t.Fatal("the commit succeeded")
			}
			sinkUntouched(t, s)
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		sg := &scriptedSigner{real: testRecordSigner(t, 7), delay: 50 * time.Millisecond}
		s := openSigning(t, t.TempDir(), sg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err := s.Commit(ctx, events("u-1", 4)); err == nil {
			t.Fatal("a cancelled commit succeeded")
		}
		sinkUntouched(t, s)
	})
}

// TestCommit_RefusedAppendRemovesSignatures: an append that does not land
// leaves no signature rows (and no content).
func TestCommit_RefusedAppendRemovesSignatures(t *testing.T) {
	rs := testRecordSigner(t, 7)
	s := openSigning(t, t.TempDir(), rs)
	failAppends(s)
	if _, err := s.Commit(context.Background(), events("u-1", 3)); err == nil {
		t.Fatal("the commit succeeded")
	}
	sig, err := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout)
	if err != nil || sig == nil {
		t.Fatalf("signatures file: %v", err)
	}
	defer sig.Close()
	if n := sigRowCount(t, sig); n != 0 {
		t.Fatalf("%d signature rows remain", n)
	}
	// F2: the failed first signed commit still made this a signing sink.
	if on, _ := sig.signing(); !on {
		t.Fatal("a failed first signed commit did not set the signing mode")
	}
}

type failingSigDelete struct{ signaturesWriter }

func (failingSigDelete) deleteRows(map[string][]string) error {
	return errors.New("injected: signature delete failed")
}

// TestCommit_SignatureCleanupFailureKeepsRows: if the signature rows cannot be
// removed, the index rows stay bound (errCleanupFailed), as for content.
func TestCommit_SignatureCleanupFailureKeepsRows(t *testing.T) {
	s := openSigning(t, t.TempDir(), testRecordSigner(t, 7))
	failAppends(s)
	s.wrapSignatures = func(w signaturesWriter) signaturesWriter { return failingSigDelete{w} }
	_, err := s.Commit(context.Background(), events("u-1", 2))
	if !errors.Is(err, errCleanupFailed) {
		t.Fatalf("err = %v; want errCleanupFailed", err)
	}
	cid(t, s, "u-1") // still bound: erasing the subject reaches what is left
}

// TestRecordSigning_ModeTable (C4): every cell of the table, for Commit and
// the three erase entry points. A refusal writes nothing.
func TestRecordSigning_ModeTable(t *testing.T) {
	ctx := context.Background()
	verbs := map[string]func(s *Sink) error{
		"commit":     func(s *Sink) error { _, err := s.Commit(ctx, events("u-9", 1)); return err },
		"erase":      func(s *Sink) error { _, err := s.EraseSubject(ctx, "u-1"); return err },
		"eraseClass": func(s *Sink) error { _, err := s.EraseSubjectClass(ctx, "u-1", testClass); return err },
		"resume":     func(s *Sink) error { _, err := s.ResumeErasures(ctx); return err },
	}
	for name, verb := range verbs {
		t.Run("signing sink, no signer/"+name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := openSigning(t, dir, testRecordSigner(t, 7)).Commit(ctx, events("u-1", 1)); err != nil {
				t.Fatal(err)
			}
			plain, _ := Open(dir)
			if err := verb(plain); !errors.Is(err, ErrRecordSignerRequired) {
				t.Fatalf("err = %v; want ErrRecordSignerRequired", err)
			}
			cid(t, plain, "u-1") // nothing was erased or forgotten
		})
		t.Run("unsigned sink with entries, signer/"+name, func(t *testing.T) {
			dir := t.TempDir()
			plain, _ := Open(dir)
			if _, err := plain.Commit(ctx, events("u-1", 1)); err != nil {
				t.Fatal(err)
			}
			signing := openSigning(t, dir, testRecordSigner(t, 7))
			if err := verb(signing); !errors.Is(err, ErrSinkNotSigning) {
				t.Fatalf("err = %v; want ErrSinkNotSigning", err)
			}
			if _, err := os.Stat(signing.signaturesPath()); err == nil {
				t.Fatal("a signatures file was created on an unsigned sink")
			}
			cid(t, plain, "u-1")
		})
	}
	t.Run("new sink, signer: signs", func(t *testing.T) {
		s := openSigning(t, t.TempDir(), testRecordSigner(t, 7))
		if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
			t.Fatal(err)
		}
		sig, _ := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout)
		defer sig.Close()
		if on, _ := sig.signing(); !on {
			t.Fatal("not signing")
		}
	})
	t.Run("unsigned sink, no signer: no signatures file", func(t *testing.T) {
		s, _ := Open(t.TempDir())
		if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(s.signaturesPath()); err == nil {
			t.Fatal("an unsigned sink got a signatures file")
		}
	})
	t.Run("failed first signed commit stays signing", func(t *testing.T) {
		dir := t.TempDir()
		first := openSigning(t, dir, testRecordSigner(t, 7))
		failAppends(first)
		if _, err := first.Commit(ctx, events("u-1", 1)); err == nil {
			t.Fatal("the commit succeeded")
		}
		plain, _ := Open(dir)
		if _, err := plain.Commit(ctx, events("u-1", 1)); !errors.Is(err, ErrRecordSignerRequired) {
			t.Fatalf("err = %v; want ErrRecordSignerRequired", err)
		}
	})
	t.Run("altered mode marker", func(t *testing.T) {
		dir := t.TempDir()
		s := openSigning(t, dir, testRecordSigner(t, 7))
		if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
			t.Fatal(err)
		}
		sig, _ := openSignatures(s.signaturesPath(), DefaultLockTimeout)
		if err := sig.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(metaBucket).Put(metaRecordSigning, []byte("ed25519"))
		}); err != nil {
			t.Fatal(err)
		}
		sig.Close()
		for _, k := range []*Sink{s, mustOpen(t, dir)} {
			if _, err := k.Commit(ctx, events("u-1", 1)); err == nil || errors.Is(err, ErrRecordSignerRequired) {
				t.Fatalf("an altered mode was not reported as such: %v", err)
			}
		}
	})
}

func mustOpen(t *testing.T, dir string) *Sink {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRecordSigningOptions(t *testing.T) {
	if _, err := Open(t.TempDir(), WithRecordSigner(nil)); err == nil {
		t.Fatal("a nil record signer was accepted")
	}
	for _, n := range []int{0, -1} {
		if _, err := Open(t.TempDir(), WithRecordSigningConcurrency(n)); err == nil {
			t.Fatalf("concurrency %d was accepted", n)
		}
	}
}

// TestSignAll (C6): the bound holds, order is kept, the first error stops the
// rest, and no signer call is still running when signAll returns.
func TestSignAll(t *testing.T) {
	ctx := context.Background()
	real := testRecordSigner(t, 7)
	key, _ := recordKeyOf(real)
	jobs := make([]recordFields, 40)
	for i := range jobs {
		f := validRecordFields()
		f.globalSeq = int64(100 + i)
		jobs[i] = f
	}
	sg := &scriptedSigner{real: real, delay: 2 * time.Millisecond}
	sigs, err := signAll(ctx, sg, key, 4, jobs)
	if err != nil {
		t.Fatal(err)
	}
	if got := sg.maxInFlight.Load(); got > 4 || got < 2 {
		t.Fatalf("max in flight %d; want 2..4 (bounded, and parallel)", got)
	}
	for i, f := range jobs {
		f.keyID = key.id
		if err := verifyRecordSignature(key.pub, f, sigs[i]); err != nil {
			t.Fatalf("signature %d is not job %d's: %v", i, i, err)
		}
	}

	failing := &scriptedSigner{real: real, failAt: 3, delay: 5 * time.Millisecond}
	if _, err := signAll(ctx, failing, key, 4, jobs); err == nil {
		t.Fatal("a failure was not reported")
	}
	if n := failing.inFlight.Load(); n != 0 {
		t.Fatalf("%d signer calls still running after signAll returned", n)
	}
	if n := failing.calls.Load(); n >= int64(len(jobs)) {
		t.Fatalf("the first failure did not stop the rest (%d calls)", n)
	}
}

// TestErase_SignsTheErasureEntry: an erasure entry is signed and verifies,
// chained to the entry before it; a chain already ending with its erasure gets
// no second entry or signature.
func TestErase_SignsTheErasureEntry(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(ctx, events("u-1", 3)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, chain, key.pub); n != 4 {
		t.Fatalf("checked %d entries, want 3 events and the erasure", n)
	}
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, chain, key.pub); n != 4 {
		t.Fatalf("a resume added an entry to an erased chain (%d)", n)
	}
}

// TestErase_SignerFailureForgetsNothing (C7): a signer failing at presign
// leaves the subject findable and nothing erased.
func TestErase_SignerFailureForgetsNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := openSigning(t, dir, testRecordSigner(t, 7)).Commit(ctx, append(events("u-1", 2), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	broken := openSigning(t, dir, &scriptedSigner{real: testRecordSigner(t, 7), failAt: 1})
	_, err := broken.EraseSubject(ctx, "u-1")
	if err == nil || !strings.Contains(err.Error(), "not forgotten") {
		t.Fatalf("err = %v; want a refusal that forgot nothing", err)
	}
	chain := cid(t, broken, "u-1")
	if got, _ := readContent(broken, chain, entryIDs(t, broken, chain)[0]); len(got) == 0 {
		t.Fatal("content was erased although the erasure was refused")
	}
	if pend := pendingChains(t, broken); len(pend) != 0 {
		t.Fatalf("chains were marked pending: %v", pend)
	}
}

// TestErase_ResumeSignsPendingChains: a pending erasure completed by a resume
// is signed too.
func TestErase_ResumeSignsPendingChains(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	markPending(t, s, chain)
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, chain, key.pub); n != 3 {
		t.Fatalf("checked %d entries, want 2 events and the erasure", n)
	}
}

// oneInterloper appends a foreign entry before the erasure's own append, so the
// erasure entry was prepared against a tail that moved.
type oneInterloper struct{ real *linker.Linker }

func (i oneInterloper) Append(ctx context.Context, chain string, in []linker.Input) (linker.Result, error) {
	now := in[0].IngestedAt.Add(-1)
	if _, err := i.real.Append(ctx, chain, []linker.Input{{EntryID: "sink-" + strings.Repeat("e", 32),
		EntryType: EntryTypeEvent, Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		return linker.Result{}, err
	}
	return i.real.Append(ctx, chain, in)
}

// TestEraseChain_PinsTheChainHash (C2): the erasure entry is appended with its
// predicted chain hash, on unsigned sinks too, so a moved tail is refused.
func TestEraseChain_PinsTheChainHash(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["auth/u-1"]
	st, sec, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	defer sec.Close()
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	pre := presignOne(t, s, st, chain)
	if _, err := s.eraseChain(ctx, st, sec, oneInterloper{real: l}, chain, pre, nil); !errors.Is(err, linker.ErrUnexpectedChainHash) {
		t.Fatalf("err = %v; want the erasure refused", err)
	}
	if _, err := readContent(s, chain, pre.id); err == nil {
		t.Fatal("the refused erasure's record row was left")
	}
}

// TestErase_CompactsTheSignaturesFile: rows a failed commit's cleanup deleted
// leave the file's bytes at the next erasure call (here a resume); committed
// signatures stay.
func TestErase_CompactsTheSignaturesFile(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	dir := t.TempDir()
	s := openSigning(t, dir, rs)
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	// A failed commit: its signature rows are written, then deleted.
	failing := openSigning(t, dir, rs)
	failAppends(failing)
	var deleted [][]byte
	failing.wrapSignatures = func(w signaturesWriter) signaturesWriter {
		return &capturingSigs{signaturesWriter: w, got: &deleted}
	}
	if _, err := failing.Commit(ctx, events("u-2", 2)); err == nil {
		t.Fatal("the commit succeeded")
	}
	if len(deleted) == 0 {
		t.Fatal("test setup: no signatures were written by the failed commit")
	}
	before, _ := os.ReadFile(s.signaturesPath())
	inFile := 0
	for _, sig := range deleted {
		if bytes.Contains(before, sig) {
			inFile++
		}
	}
	if inFile == 0 {
		t.Fatal("test setup: the deleted signatures are not in the file's free pages, so this proves nothing")
	}
	// A resume with nothing pending: it compacts, but writes no signature that
	// could happen to reuse (and so hide) the freed pages.
	fiBefore, err := os.Stat(s.signaturesPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumeErasures(ctx); err != nil {
		t.Fatal(err)
	}
	// Compaction replaces the file (fresh copy, atomic rename). The bytes check
	// below is the outcome; bbolt may also reuse freed pages on its own, so this
	// is what shows the file was rewritten.
	fiAfter, err := os.Stat(s.signaturesPath())
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(fiBefore, fiAfter) {
		t.Fatal("the erasure call did not rewrite the signatures file")
	}
	raw, err := os.ReadFile(s.signaturesPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range deleted {
		if bytes.Contains(raw, sig) {
			t.Fatal("a deleted signature's bytes are still in the file after the erasure")
		}
	}
	if n := checkRecordSignatures(t, s, chain, key.pub); n != 1 {
		t.Fatalf("a committed signature did not survive the compaction (%d)", n)
	}
}

// capturingSigs records the signatures written through it.
type capturingSigs struct {
	signaturesWriter
	mu  sync.Mutex
	got *[][]byte
}

func (c *capturingSigs) putAll(rows map[string]map[string]signatureRow) error {
	c.mu.Lock()
	for _, byEntry := range rows {
		for _, r := range byEntry {
			*c.got = append(*c.got, append([]byte(nil), r.sig...))
		}
	}
	c.mu.Unlock()
	return c.signaturesWriter.putAll(rows)
}

func sigRowCount(t *testing.T, sig *signaturesStore) int {
	t.Helper()
	n := 0
	if err := sig.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(signaturesBucket).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestEraseChain_SignedRefusalRemovesTheSignature: in a signing sink, an erasure
// whose append is refused leaves neither its record row nor its signature.
func TestEraseChain_SignedRefusalRemovesTheSignature(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(ctx, events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	st, sec, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	defer sec.Close()
	sigs, closeSigs, err := s.openRecordSigning(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSigs()
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := s.presignErasures(ctx, st, sigs, []string{chain})
	if err != nil {
		t.Fatal(err)
	}
	p := pre[chain]
	if p.sig == nil {
		t.Fatal("test setup: the erasure entry was not signed")
	}
	if _, err := s.eraseChain(ctx, st, sec, oneInterloper{real: l}, chain, &p, sigs); !errors.Is(err, linker.ErrUnexpectedChainHash) {
		t.Fatalf("err = %v; want the erasure refused", err)
	}
	if _, found, _, _ := sigs.store.get(chain, p.id); found {
		t.Fatal("the refused erasure's signature was left")
	}
}
