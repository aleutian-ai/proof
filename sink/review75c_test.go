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
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// _75c review fixes.

// landedThenCancelled appends for real, then cancels the call's context and
// reports an error: the append landed, and the read-back that would prove it
// fails (the store honours the cancelled context).
type landedThenCancelled struct {
	real   *linker.Linker
	cancel context.CancelFunc
}

func (a landedThenCancelled) Append(ctx context.Context, chain string, in []linker.Input) (linker.Result, error) {
	res, err := a.real.Append(ctx, chain, in)
	a.cancel()
	if err != nil {
		return res, err
	}
	return res, errors.New("injected: error after the commit")
}

// #1: an erasure whose outcome cannot be checked keeps its record AND its
// signature (the entry may have landed), stays pending, and a resume leaves a
// fully signed chain.
func TestEraseChain_UnknownOutcomeKeepsTheSignature(t *testing.T) {
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(context.Background(), events("u-1", 2)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	ctx, cancel := context.WithCancel(context.Background())
	st, sec, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	sigs, closeSigs, err := s.openRecordSigning(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := linker.New(st)
	pre, err := s.presignErasures(ctx, st, sigs, []string{chain})
	if err != nil {
		t.Fatal(err)
	}
	p := pre[chain]
	_, err = s.eraseChain(ctx, st, sec, landedThenCancelled{real: l, cancel: cancel}, chain, &p, sigs)
	if err == nil || !strings.Contains(err.Error(), "could not be checked") {
		t.Fatalf("err = %v; want an unknown outcome", err)
	}
	if _, found, _, _ := sigs.store.get(chain, p.id); !found {
		t.Fatal("the signature of an erasure that may have landed was deleted")
	}
	closeSigs()
	sec.Close()
	st.Close()
	markPending(t, s, chain)
	if _, err := s.ResumeErasures(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, chain, key.pub); n != 3 {
		t.Fatalf("checked %d entries; want 2 events and the erasure, all signed", n)
	}
}

// corruptTailHash rewrites the stored chain hash of chain's last entry (and its
// head state) to something that is not a hash.
func corruptTailHash(t *testing.T, s *Sink, chain string) {
	t.Helper()
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := st.ReadTail(context.Background(), chain)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"entries", "state"} {
			b := tx.Bucket([]byte(name))
			type kv struct{ k, v []byte }
			var changed []kv
			if err := b.ForEach(func(k, v []byte) error {
				if bytes.HasPrefix(k, []byte(chain)) && bytes.Contains(v, []byte(h)) {
					changed = append(changed, kv{append([]byte(nil), k...),
						bytes.ReplaceAll(v, []byte(h), []byte(strings.Repeat("Z", 128)))})
				}
				return nil
			}); err != nil {
				return err
			}
			for _, c := range changed {
				if err := b.Put(c.k, c.v); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// #2: a pending chain whose tail hash cannot be hashed from fails alone; the
// subject's erasure goes on.
func TestErase_UnhashableTailFailsAlone(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, append(events("u-1", 1), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	bad := cid(t, s, "u-2")
	good := cid(t, s, "u-1")
	markPending(t, s, bad)
	corruptTailHash(t, s, bad)
	_, err = s.EraseSubject(ctx, "u-1")
	ie := incomplete(t, err)
	if len(ie.Pending) != 1 || ie.Pending[0] != bad {
		t.Fatalf("pending %v; want only the corrupt chain", ie.Pending)
	}
	if !endsErased(t, s, good) {
		t.Fatal("the subject's own chain was not erased")
	}
}

func endsErased(t *testing.T, s *Sink, chain string) bool {
	t.Helper()
	st, err := s.openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ok, err := endsWithGenuineErasure(context.Background(), st, chain)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// #3: erasing a subject with chains in two classes, plus a pending chain of
// another subject: every chain's erasure carries ITS OWN signature.
func TestErase_SignaturesGoToTheirChains(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	s := openSigning(t, t.TempDir(), rs)
	recs := append(events("u-1", 2), events("u-2", 1)...)
	recs = append(recs, Record{Class: "auth", Subject: "u-1", Content: []byte(`{"login":1}`)})
	if _, err := s.Commit(ctx, recs); err != nil {
		t.Fatal(err)
	}
	a, b, other := cid(t, s, "u-1"), cidIn(t, s, "auth", "u-1"), cid(t, s, "u-2")
	markPending(t, s, other)
	res, err := s.EraseSubject(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Erased) != 2 || len(res.Resumed) != 1 {
		t.Fatalf("erased %d, resumed %d; want 2 and 1", len(res.Erased), len(res.Resumed))
	}
	for chain, want := range map[string]int{a: 3, b: 2, other: 2} {
		if n := checkRecordSignatures(t, s, chain, key.pub); n != want {
			t.Fatalf("chain checked %d entries, want %d", n, want)
		}
	}
}

// #4 (G1): erase errors name no chain; the ids are in the result.
func TestErase_ErrorsNameNoChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, append(events("u-1", 1), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	stuck := cid(t, s, "u-2")
	markPending(t, s, stuck)
	stick(t, s, stuck)
	for name, call := range map[string]func() error{
		"erase":  func() error { _, err := s.EraseSubject(ctx, "u-1"); return err },
		"resume": func() error { _, err := s.ResumeErasures(ctx); return err },
	} {
		err := call()
		ie := incomplete(t, err)
		if anyChainID.MatchString(err.Error()) {
			t.Fatalf("%s: the error names a chain: %v", name, err)
		}
		if len(ie.Pending) != 1 || ie.Pending[0] != stuck {
			t.Fatalf("%s: the ids must stay in Pending: %v", name, ie.Pending)
		}
	}
}

// #5: an erasure refused at its append whose cleanup fails says so.
func TestEraseChain_UndoFailureIsReported(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	s.wrapSignatures = func(w signaturesWriter) signaturesWriter { return failingSigDelete{w} }
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
	l, _ := linker.New(st)
	pre, _ := s.presignErasures(ctx, st, sigs, []string{chain})
	p := pre[chain]
	_, err = s.eraseChain(ctx, st, sec, oneInterloper{real: l}, chain, &p, sigs)
	if err == nil || !strings.Contains(err.Error(), "remove the erasure signature") {
		t.Fatalf("err = %v; want the failed cleanup reported", err)
	}
}

// reusingSigner returns every signature in ONE buffer it overwrites on the
// next call, as a pooled client might.
type reusingSigner struct {
	real *MLDSA65RecordSigner
	mu   sync.Mutex
	buf  []byte
}

func (r *reusingSigner) Public() crypto.PublicKey { return r.real.Public() }
func (r *reusingSigner) SignRecord(ctx context.Context, env []byte) ([]byte, error) {
	sig, err := r.real.SignRecord(ctx, env)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf[:0], sig...)
	return r.buf, nil
}

// #6: a signer that reuses its buffer cannot change what is stored after it
// was verified.
func TestCommit_SignerBufferReuse(t *testing.T) {
	real := testRecordSigner(t, 7)
	key, _ := recordKeyOf(real)
	s := openSigning(t, t.TempDir(), &reusingSigner{real: real}, WithRecordSigningConcurrency(1))
	if _, err := s.Commit(context.Background(), events("u-1", 3)); err != nil {
		t.Fatal(err)
	}
	if n := checkRecordSignatures(t, s, cid(t, s, "u-1"), key.pub); n != 3 {
		t.Fatalf("checked %d", n)
	}
}

// #18: a typed-nil signer is refused at Open.
func TestWithRecordSigner_TypedNil(t *testing.T) {
	if _, err := Open(t.TempDir(), WithRecordSigner((*MLDSA65RecordSigner)(nil))); err == nil {
		t.Fatal("a nil *MLDSA65RecordSigner was accepted")
	}
}

// cancellingSigner cancels the call's context on its first call: the
// cancellation then provably reaches signing (not some earlier step).
type cancellingSigner struct {
	real   *MLDSA65RecordSigner
	cancel context.CancelFunc
	calls  int64
	mu     sync.Mutex
}

func (c *cancellingSigner) Public() crypto.PublicKey { return c.real.Public() }
func (c *cancellingSigner) SignRecord(ctx context.Context, env []byte) ([]byte, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	c.cancel()
	<-ctx.Done()
	return nil, ctx.Err()
}

// #19: a commit cancelled DURING signing leaves nothing.
func TestCommit_CancelledDuringSigning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs := &cancellingSigner{real: testRecordSigner(t, 7), cancel: cancel}
	s := openSigning(t, t.TempDir(), cs)
	if _, err := s.Commit(ctx, events("u-1", 4)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want cancelled", err)
	}
	if cs.calls == 0 {
		t.Fatal("the signer was never called: the test did not reach signing")
	}
	sinkUntouched(t, s)
}

// #19: a presign failure keeps earlier pending chains pending, and changes no
// byte of the signatures file.
func TestErase_PresignFailureKeepsPendingAndSignatures(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	good := openSigning(t, dir, testRecordSigner(t, 7))
	if _, err := good.Commit(ctx, append(events("u-1", 1), events("u-2", 1)...)); err != nil {
		t.Fatal(err)
	}
	other := cid(t, good, "u-2")
	markPending(t, good, other)
	before, _ := os.ReadFile(good.signaturesPath())
	broken := openSigning(t, dir, &scriptedSigner{real: testRecordSigner(t, 7), failAt: 1})
	if _, err := broken.EraseSubject(ctx, "u-1"); err == nil {
		t.Fatal("the erasure succeeded")
	}
	if pend := pendingChains(t, broken); len(pend) != 1 || pend[0] != other {
		t.Fatalf("pending %v; want the earlier pending chain still pending", pend)
	}
	after, _ := os.ReadFile(good.signaturesPath())
	if !bytes.Equal(before, after) {
		t.Fatal("a refused erasure changed the signatures file")
	}
}

// G2: a failed rewrite of the signatures file is reported, but erased chains
// are not kept pending for it (the file holds no erased values).
func TestErase_SignaturesRewriteFailureDoesNotKeepPending(t *testing.T) {
	ctx := context.Background()
	s := openSigning(t, t.TempDir(), testRecordSigner(t, 7))
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	real := s.compact
	s.compact = func(path string, d time.Duration) error {
		if path == s.signaturesPath() {
			return errors.New("injected: rewrite failed")
		}
		return real(path, d)
	}
	_, err := s.EraseSubject(ctx, "u-1")
	ie := incomplete(t, err)
	if !ie.Compacted || len(ie.Pending) != 0 {
		t.Fatalf("compacted %t, pending %v; want true and none", ie.Compacted, ie.Pending)
	}
	if !strings.Contains(err.Error(), "evidence.db.signatures") {
		t.Fatalf("the failure was not reported: %v", err)
	}
	if pend := pendingChains(t, s); len(pend) != 0 {
		t.Fatalf("chains left pending: %v", pend)
	}
}

type failingSigPut struct{ signaturesWriter }

func (failingSigPut) putAll(map[string]map[string]signatureRow) error {
	return errors.New("injected: signature store failed")
}

// An erasure whose signature cannot be stored is not appended, and leaves no
// record row behind.
func TestEraseChain_SignatureStoreFailure(t *testing.T) {
	ctx := context.Background()
	s := openSigning(t, t.TempDir(), testRecordSigner(t, 7))
	if _, err := s.Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	s.wrapSignatures = func(w signaturesWriter) signaturesWriter { return failingSigPut{w} }
	st, sec, err := s.openFiles()
	if err != nil {
		t.Fatal(err)
	}
	sigs, closeSigs, err := s.openRecordSigning(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := linker.New(st)
	pre, _ := s.presignErasures(ctx, st, sigs, []string{chain})
	p := pre[chain]
	if _, err := s.eraseChain(ctx, st, sec, l, chain, &p, sigs); err == nil {
		t.Fatal("the erasure went on without its signature")
	}
	closeSigs()
	sec.Close()
	st.Close()
	if _, err := readContent(s, chain, p.id); err == nil {
		t.Fatal("the erasure record row was left behind")
	}
	if endsErased(t, s, chain) {
		t.Fatal("the erasure entry was appended without its signature")
	}
}
