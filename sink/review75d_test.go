// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// _75d review fixes.

func readEntries(t *testing.T, s *Sink, chain string, n int) []store.Entry {
	t.Helper()
	es := make([]store.Entry, n)
	for i := range es {
		editEntry(t, s, chain, int64(i), func(e *store.Entry) { es[i] = *e })
	}
	return es
}

// #1 (HIGH), regression: a validly signed record spliced into the MIDDLE of a
// chain, with the keyless chain hashes recomputed and the next entry's signed
// previous_hash left as it was, is caught: the stored previous_hash must be the
// previous entry's chain hash. Found by the _75d review (two PoCs).
func TestVerify_MiddleSpliceIsCaught(t *testing.T) {
	ctx := context.Background()
	s, ring, rs := signedSink(t)
	chain := cid(t, s, "u-1")
	es := readEntries(t, s, chain, 3)
	// The "orphan": entry 1 as a failed commit could have signed it.
	newTs := es[1].Timestamp.Add(1234 * time.Millisecond)
	key, _ := recordKeyOf(rs)
	sig, err := signRecord(ctx, rs, key, recordFields{chainID: chain, entryID: es[1].EntryID,
		entryType: es[1].EntryType, globalSeq: 1, prevHash: es[1].PreviousHash, timestamp: newTs,
		contentHash: es[1].ContentHash})
	if err != nil {
		t.Fatal(err)
	}
	withSignatures(t, s, func(b *bolt.Bucket) error {
		raw, _ := hex.DecodeString(key.id)
		return b.Put(rowKey(chain, es[1].EntryID), append(raw, sig...))
	})
	ch1 := chainformat.ComputeChainHashV3Unchecked(es[0].ChainHash, 1, newTs, es[1].ContentHash)
	ch2 := chainformat.ComputeChainHashV3Unchecked(ch1, 2, es[2].Timestamp, es[2].ContentHash)
	editEntry(t, s, chain, 1, func(e *store.Entry) { e.Timestamp = newTs; e.ChainHash = ch1 })
	editEntry(t, s, chain, 2, func(e *store.Entry) { e.ChainHash = ch2 })
	for _, opts := range [][]VerifyOption{nil, {WithRecordTrust(recordRing(t, rs))}} {
		cr := chainReport(t, verifyWith(t, s, ring, opts...), chain)
		if !hasProblemWith(cr, "previous_hash") {
			t.Fatalf("a splice passed: %+v", cr)
		}
	}
}

// #1 (HIGH), regression: front truncation (entry 0 removed, the keyless hashes
// recomputed) is caught: a sink chain starts at sequence 0 with no previous
// hash.
func TestVerify_FrontTruncationIsCaught(t *testing.T) {
	s, ring, rs := signedSink(t)
	chain := cid(t, s, "u-1")
	es := readEntries(t, s, chain, 3)
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	k0 := append(append([]byte(chain), 0), make([]byte, 8)...)
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("entries")).Delete(k0) }); err != nil {
		t.Fatal(err)
	}
	db.Close()
	withSignatures(t, s, func(b *bolt.Bucket) error { return b.Delete(rowKey(chain, es[0].EntryID)) })
	if err := removeContent(s, chain, es[0].EntryID); err != nil {
		t.Fatal(err)
	}
	if err := removeNonce(s, chain, es[0].EntryID); err != nil {
		t.Fatal(err)
	}
	ch1 := chainformat.ComputeChainHashV3Unchecked("", 1, es[1].Timestamp, es[1].ContentHash)
	ch2 := chainformat.ComputeChainHashV3Unchecked(ch1, 2, es[2].Timestamp, es[2].ContentHash)
	editEntry(t, s, chain, 1, func(e *store.Entry) { e.ChainHash = ch1 })
	editEntry(t, s, chain, 2, func(e *store.Entry) { e.ChainHash = ch2 })
	for _, opts := range [][]VerifyOption{nil, {WithRecordTrust(recordRing(t, rs))}} {
		cr := chainReport(t, verifyWith(t, s, ring, opts...), chain)
		if !hasProblemWith(cr, "sequence 0") {
			t.Fatalf("a front truncation passed: %+v", cr)
		}
	}
}

// #2: a first signed commit that never reached its chain (its cleanup failed,
// as a crash would leave it) leaves signature rows; erasing the subject removes
// them, and the folder then verifies (not REMOVED).
func TestErase_FirstCommitLeftoverSignatures(t *testing.T) {
	ctx := context.Background()
	rs := testRecordSigner(t, 7)
	dir := t.TempDir()
	if _, err := openSigning(t, dir, rs).Commit(ctx, events("u-2", 1)); err != nil {
		t.Fatal(err)
	}
	s := openSigning(t, dir, rs)
	failAppends(s)
	s.wrapSignatures = func(w signaturesWriter) signaturesWriter { return failingSigDelete{w} }
	s.wrapSecrets = func(w secretsWriter) secretsWriter { return failingDelete{w} }
	if _, err := s.Commit(ctx, events("u-1", 2)); err == nil {
		t.Fatal("the commit succeeded")
	}
	s.wrapAppender, s.wrapSignatures, s.wrapSecrets = nil, nil, nil
	chain := cid(t, s, "u-1")
	_, ring := newSigner(t)
	if cr := chainReport(t, verifyWith(t, s, ring), chain); cr.OrphanSignatures != 2 {
		t.Fatalf("test setup: %+v", cr)
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	r := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs)))
	if !r.OK() {
		t.Fatalf("after erasing the subject the folder fails: %+v", r)
	}
	sig, _ := openSignaturesReadOnly(s.signaturesPath(), DefaultLockTimeout)
	defer sig.Close()
	if ids, _ := sig.rowIDs(chain); len(ids) != 0 {
		t.Fatalf("%d signature rows of the never-committed chain survived", len(ids))
	}
}

// #4: a damaged signatures file is a finding in the report, never a reason
// for Verify to report nothing.
func TestVerify_DamagedSignaturesFileIsAFinding(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Sink){
		"altered mode": func(t *testing.T, s *Sink) {
			db, err := bolt.Open(s.signaturesPath(), 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(metaBucket).Put(metaRecordSigning, []byte("ed25519"))
			}); err != nil {
				t.Fatal(err)
			}
		},
		"a bucket missing": func(t *testing.T, s *Sink) {
			db, err := bolt.Open(s.signaturesPath(), 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(metaBucket) }); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			s, ring, rs := signedSink(t)
			damage(t, s)
			for _, opts := range [][]VerifyOption{nil, {WithRecordTrust(recordRing(t, rs))}} {
				r, err := s.Verify(context.Background(), ring, opts...)
				if err != nil {
					t.Fatalf("Verify reported nothing: %v", err)
				}
				if r.OK() || len(chainReport(t, r, "<invalid signatures file>").Problems) == 0 {
					t.Fatalf("the damage was not reported: %+v", r)
				}
				if len(r.Chains) < 3 {
					t.Fatal("the chains' own verdicts are missing")
				}
			}
		})
	}
}

// #7: an entry in another chain format than v3 (all this sink writes) is
// reported: v2 hashes bind a free-form run id no signature covers.
func TestVerify_NonV3EntryIsReported(t *testing.T) {
	s, ring, _ := signedSink(t)
	chain := cid(t, s, "u-1")
	editEntry(t, s, chain, 2, func(e *store.Entry) { e.FormatVersion = 2 })
	if cr := chainReport(t, verifyWith(t, s, ring), chain); !hasProblemWith(cr, "format v3") {
		t.Fatalf("%+v", cr)
	}
}

// #8: an orphan signature on an erased chain keeps it erased-unanchored even
// with record trust (a trailing run of orphans is the erasure-reversal shape).
func TestVerify_SignedErasureWithOrphanWaitsForACheckpoint(t *testing.T) {
	s, ring, rs := signedSink(t)
	chain := cid(t, s, "u-1")
	if _, err := s.EraseSubject(context.Background(), "u-1"); err != nil {
		t.Fatal(err)
	}
	withSignatures(t, s, func(b *bolt.Bucket) error {
		return b.Put(rowKey(chain, "sink-"+strings.Repeat("9", 32)), make([]byte, signatureRowSize))
	})
	cr := chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), chain)
	if cr.Index != IndexErasedUnanchored || cr.OrphanSignatures != 1 {
		t.Fatalf("index %q, orphans %d", cr.Index, cr.OrphanSignatures)
	}
}

// failingSource fails every lookup with something other than "unknown key".
type failingSource struct{}

func (failingSource) PublicKey(string) ([]byte, anchor.Trust, error) {
	return nil, anchor.TrustProvided, errors.New("kms: unavailable")
}

// #19: a key source that fails is an error (verification could not run), not
// a verdict on the signatures.
func TestVerify_KeySourceFailureIsAnError(t *testing.T) {
	s, ring, _ := signedSink(t)
	if _, err := s.Verify(context.Background(), ring, WithRecordTrust(failingSource{})); err == nil ||
		!strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err = %v", err)
	}
}

// #19: signature rows of a pending chain with no entries are a note.
func TestVerify_PendingChainSignatureRowsAreANote(t *testing.T) {
	s, ring, _ := signedSink(t)
	fresh := "events." + strings.Repeat("6", 32)
	markPending(t, s, fresh)
	withSignatures(t, s, func(b *bolt.Bucket) error {
		return b.Put(rowKey(fresh, "sink-"+strings.Repeat("5", 32)), make([]byte, signatureRowSize))
	})
	cr := chainReport(t, verifyWith(t, s, ring), fresh)
	if cr.OrphanSignatures != 1 || cr.Anomaly == "removed" {
		t.Fatalf("%+v", cr)
	}
}

// #13: a crafted row under a valid chain but an invalid entry id is counted
// once (malformed), not also as an orphan.
func TestVerify_CraftedRowCountedOnce(t *testing.T) {
	s, ring, _ := signedSink(t)
	chain := cid(t, s, "u-1")
	withSignatures(t, s, func(b *bolt.Bucket) error {
		return b.Put(rowKey(chain, "jo@example.com"), []byte("x"))
	})
	r := verifyWith(t, s, ring)
	if cr := chainReport(t, r, chain); cr.OrphanSignatures != 0 {
		t.Fatalf("counted as an orphan too: %+v", cr)
	}
	if len(chainReport(t, r, "<invalid signatures row #1>").Problems) == 0 {
		t.Fatal("not counted as malformed")
	}
}

// #1, the variant the start-at-zero check alone catches: entry 0 removed AND
// the new first entry's previous_hash blanked (no record trust, so no
// signature notices). Only "a sink chain starts at sequence 0" sees it.
func TestVerify_FrontTruncationWithBlankedPrevious(t *testing.T) {
	s, ring, _ := signedSink(t)
	chain := cid(t, s, "u-1")
	es := readEntries(t, s, chain, 3)
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	k0 := append(append([]byte(chain), 0), make([]byte, 8)...)
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("entries")).Delete(k0) }); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_ = removeContent(s, chain, es[0].EntryID)
	_ = removeNonce(s, chain, es[0].EntryID)
	ch1 := chainformat.ComputeChainHashV3Unchecked("", 1, es[1].Timestamp, es[1].ContentHash)
	ch2 := chainformat.ComputeChainHashV3Unchecked(ch1, 2, es[2].Timestamp, es[2].ContentHash)
	editEntry(t, s, chain, 1, func(e *store.Entry) { e.ChainHash, e.PreviousHash = ch1, "" })
	editEntry(t, s, chain, 2, func(e *store.Entry) { e.ChainHash, e.PreviousHash = ch2, ch1 })
	if cr := chainReport(t, verifyWith(t, s, ring), chain); !hasProblemWith(cr, "sequence 0") {
		t.Fatalf("a front truncation passed: %+v", cr)
	}
}
