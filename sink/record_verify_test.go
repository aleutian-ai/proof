// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/store"
)

// _75d: Verify checks record signatures.

// recordRing is a record trust source holding the given signers' keys.
func recordRing(t *testing.T, signers ...*MLDSA65RecordSigner) *anchor.KeyRing {
	t.Helper()
	keys := map[string][]byte{}
	for _, s := range signers {
		k, err := recordKeyOf(s)
		if err != nil {
			t.Fatal(err)
		}
		keys[k.id] = k.pub
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, keys)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// signedSink is a signing sink with u-1 (3 events) and u-2 (2 events), plus
// its checkpoint key ring and record signer.
func signedSink(t *testing.T) (*Sink, *anchor.KeyRing, *MLDSA65RecordSigner) {
	t.Helper()
	rs := testRecordSigner(t, 7)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(context.Background(), append(events("u-1", 3), events("u-2", 2)...)); err != nil {
		t.Fatal(err)
	}
	_, ring := newSigner(t)
	return s, ring, rs
}

func verifyWith(t *testing.T, s *Sink, ring anchor.KeySource, opts ...VerifyOption) Report {
	t.Helper()
	r, err := s.Verify(context.Background(), ring, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// editEntry rewrites one stored entry (decoded, changed, re-encoded).
func editEntry(t *testing.T, s *Sink, chain string, seq int64, change func(e *store.Entry)) {
	t.Helper()
	db, err := bolt.Open(s.DBPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := append(append([]byte(chain), 0), make([]byte, 8)...)
	binary.BigEndian.PutUint64(key[len(chain)+1:], uint64(seq))
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		var e store.Entry
		if err := json.Unmarshal(b.Get(key), &e); err != nil {
			return err
		}
		change(&e)
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put(key, raw)
	}); err != nil {
		t.Fatal(err)
	}
}

// withSignatures runs fn in a write transaction on the signatures file.
func withSignatures(t *testing.T, s *Sink, fn func(b *bolt.Bucket) error) {
	t.Helper()
	db, err := bolt.Open(s.signaturesPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error { return fn(tx.Bucket(signaturesBucket)) }); err != nil {
		t.Fatal(err)
	}
}

func hasProblemWith(cr ChainReport, sub string) bool {
	for _, p := range cr.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestVerifyRecords_AllSigned(t *testing.T) {
	s, ring, rs := signedSink(t)
	r := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs)))
	if r.RecordSignatures != RecordSignaturesChecked {
		t.Fatalf("RecordSignatures = %q", r.RecordSignatures)
	}
	for _, cr := range r.Chains {
		if hasProblemWith(cr, "record signature") || cr.Signed != cr.Entries {
			t.Fatalf("%+v", cr)
		}
	}
}

// Each kind of failure, on one chain only, counted in its own field, as ONE
// aggregated problem line.
func TestVerifyRecords_Failures(t *testing.T) {
	cases := map[string]struct {
		tamper func(t *testing.T, s *Sink, chain string, ids []string)
		count  func(cr ChainReport) int
		want   string
	}{
		"unsigned": {func(t *testing.T, s *Sink, chain string, ids []string) {
			withSignatures(t, s, func(b *bolt.Bucket) error { return b.Delete(rowKey(chain, ids[1])) })
		}, func(cr ChainReport) int { return cr.Unsigned }, "no record signature"},
		"malformed": {func(t *testing.T, s *Sink, chain string, ids []string) {
			withSignatures(t, s, func(b *bolt.Bucket) error { return b.Put(rowKey(chain, ids[1]), []byte{1, 2, 3}) })
		}, func(cr ChainReport) int { return cr.MalformedSignatures }, "malformed"},
		"a signature byte flipped": {func(t *testing.T, s *Sink, chain string, ids []string) {
			withSignatures(t, s, func(b *bolt.Bucket) error {
				v := append([]byte(nil), b.Get(rowKey(chain, ids[1]))...)
				v[len(v)-1] ^= 1
				return b.Put(rowKey(chain, ids[1]), v)
			})
		}, func(cr ChainReport) int { return cr.BadSignatures }, "BAD"},
		"two signatures swapped": {func(t *testing.T, s *Sink, chain string, ids []string) {
			withSignatures(t, s, func(b *bolt.Bucket) error {
				a := append([]byte(nil), b.Get(rowKey(chain, ids[0]))...)
				c := append([]byte(nil), b.Get(rowKey(chain, ids[1]))...)
				if err := b.Put(rowKey(chain, ids[0]), c); err != nil {
					return err
				}
				return b.Put(rowKey(chain, ids[1]), a)
			})
		}, func(cr ChainReport) int { return cr.BadSignatures }, "BAD"},
		"entry type relabelled": {func(t *testing.T, s *Sink, chain string, ids []string) {
			editEntry(t, s, chain, 1, func(e *store.Entry) { e.EntryType = EntryTypeErasure })
		}, func(cr ChainReport) int { return cr.BadSignatures }, "BAD"},
		// The envelope is rebuilt from the STORED previous_hash (_75b F1): an
		// edited one fails that entry's signature, even though a verifier taking
		// the previous entry's hash instead would accept it.
		"stored previous_hash edited": {func(t *testing.T, s *Sink, chain string, ids []string) {
			editEntry(t, s, chain, 1, func(e *store.Entry) { e.PreviousHash = strings.Repeat("0", 128) })
		}, func(cr ChainReport) int { return cr.BadSignatures }, "BAD"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, ring, rs := signedSink(t)
			chain := cid(t, s, "u-1")
			c.tamper(t, s, chain, entryIDs(t, s, chain))
			r := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs)))
			for _, cr := range r.Chains {
				if cr.Chain != chain {
					if hasProblemWith(cr, "record signature") {
						t.Fatalf("an untouched chain reports a signature problem: %v", cr.Problems)
					}
					continue
				}
				if c.count(cr) < 1 || !hasProblemWith(cr, c.want) {
					t.Fatalf("%s not reported: %+v", name, cr)
				}
			}
		})
	}
}

func TestVerifyRecords_UnknownKey(t *testing.T) {
	s, ring, _ := signedSink(t)
	r := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, testRecordSigner(t, 8))))
	cr := chainReport(t, r, cid(t, s, "u-1"))
	if cr.UnknownKeySignatures != cr.Entries || !hasProblemWith(cr, "not trusted") {
		t.Fatalf("%+v", cr)
	}
}

// D2: many failures, one line; a crafted entry id is never printed.
func TestVerifyRecords_Aggregated(t *testing.T) {
	s, ring, rs := signedSink(t)
	chain := cid(t, s, "u-1")
	withSignatures(t, s, func(b *bolt.Bucket) error {
		for _, id := range entryIDs(t, s, chain) {
			if err := b.Delete(rowKey(chain, id)); err != nil {
				return err
			}
		}
		return nil
	})
	cr := chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), chain)
	lines := 0
	for _, p := range cr.Problems {
		if strings.Contains(p, "no record signature") {
			lines++
			if !strings.Contains(p, "3 entries") || !strings.Contains(p, "first: sink-") {
				t.Fatalf("line %q lacks the count or the first id", p)
			}
		}
	}
	if lines != 1 || cr.Unsigned != 3 {
		t.Fatalf("%d lines, %d unsigned; want 1 and 3", lines, cr.Unsigned)
	}

	// A crafted, unsigned entry id is counted, never shown.
	other := cid(t, s, "u-2")
	appendRaw(t, s, other, "jo@example.com")
	cr = chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), other)
	for _, p := range cr.Problems {
		if strings.Contains(p, "jo@example.com") {
			t.Fatalf("a crafted id was printed: %q", p)
		}
	}
	if cr.Unsigned != 1 {
		t.Fatalf("unsigned %d, want 1", cr.Unsigned)
	}
}

// D3: an orphan signature row is a note, not a problem.
func TestVerifyRecords_OrphansAreNotes(t *testing.T) {
	s, ring, rs := signedSink(t)
	chain := cid(t, s, "u-1")
	withSignatures(t, s, func(b *bolt.Bucket) error {
		return b.Put(rowKey(chain, "sink-"+strings.Repeat("9", 32)), make([]byte, signatureRowSize))
	})
	for _, opts := range [][]VerifyOption{nil, {WithRecordTrust(recordRing(t, rs))}} {
		r := verifyWith(t, s, ring, opts...)
		cr := chainReport(t, r, chain)
		if cr.OrphanSignatures != 1 || hasProblemWith(cr, "signature") {
			t.Fatalf("orphans %d, problems %v", cr.OrphanSignatures, cr.Problems)
		}
	}
}

// D3: signature rows for a chain the evidence file does not hold: REMOVED
// unless the index explains them; rows keyed off the layout are counted.
func TestVerifyRecords_RowsWithoutAChain(t *testing.T) {
	s, ring, _ := signedSink(t)
	ghost := "zz." + strings.Repeat("1", 32)
	withSignatures(t, s, func(b *bolt.Bucket) error {
		if err := b.Put(rowKey(ghost, "sink-"+strings.Repeat("3", 32)), make([]byte, signatureRowSize)); err != nil {
			return err
		}
		return b.Put([]byte("not a row key"), []byte("x"))
	})
	r := verifyWith(t, s, ring)
	if cr := chainReport(t, r, ghost); cr.Anomaly != "removed" || len(cr.Problems) == 0 {
		t.Fatalf("a chain known only by signature rows was not reported removed: %+v", cr)
	}
	found := false
	for _, cr := range r.Chains {
		if strings.HasPrefix(cr.Chain, "<invalid signatures row") {
			found = true
		}
	}
	if !found {
		t.Fatal("a row keyed off the layout was not reported")
	}

	// Bound but empty (a first commit that stopped before its append): a note.
	bound := cid(t, s, "u-1")
	_ = bound
	idx, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	fresh := "events." + strings.Repeat("4", 32)
	if err := idx.bindAll([]binding{{subject: "u-7", class: testClass, chain: fresh}}); err != nil {
		t.Fatal(err)
	}
	idx.Close()
	withSignatures(t, s, func(b *bolt.Bucket) error {
		return b.Put(rowKey(fresh, "sink-"+strings.Repeat("5", 32)), make([]byte, signatureRowSize))
	})
	if cr := chainReport(t, verifyWith(t, s, ring), fresh); len(cr.Problems) != 0 || cr.OrphanSignatures != 1 {
		t.Fatalf("a bound, empty chain's signature rows are not a note: %+v", cr)
	}
}

// D4: without record trust a signing sink still verifies, and says the
// signatures were NOT checked.
func TestVerifyRecords_NotChecked(t *testing.T) {
	s, ring, _ := signedSink(t)
	r := verifyWith(t, s, ring)
	if !r.OK() || r.RecordSignatures != RecordSignaturesNotChecked {
		t.Fatalf("OK %t, RecordSignatures %q", r.OK(), r.RecordSignatures)
	}
	for _, cr := range r.Chains {
		if cr.Signed != 0 {
			t.Fatal("signatures were counted without record trust")
		}
	}
	plain, _, _ := setup(t)
	if r := verifyWith(t, plain, ring); r.RecordSignatures != RecordSignaturesNone {
		t.Fatalf("an unsigned sink reports %q", r.RecordSignatures)
	}
}

// The verifier's policy, not the folder's: record trust on an unsigned sink
// fails every entry.
func TestVerifyRecords_TrustOnAnUnsignedSink(t *testing.T) {
	s, _, ring := setup(t)
	r := verifyWith(t, s, ring, WithRecordTrust(recordRing(t, testRecordSigner(t, 7))))
	if r.OK() {
		t.Fatal("an unsigned sink passed with record trust")
	}
	for _, cr := range r.Chains {
		if cr.Entries > 0 && cr.Unsigned != cr.Entries {
			t.Fatalf("%+v", cr)
		}
	}
}

// D5 (R6): a signed erasure is `erased` without a checkpoint, only with record
// trust, a verified erasure signature, and no other problem.
func TestVerifyRecords_SignedErasure(t *testing.T) {
	ctx := context.Background()
	setupErased := func(t *testing.T) (*Sink, *anchor.KeyRing, *MLDSA65RecordSigner, string) {
		s, ring, rs := signedSink(t)
		chain := cid(t, s, "u-1")
		if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
			t.Fatal(err)
		}
		return s, ring, rs, chain
	}
	t.Run("trusted: erased", func(t *testing.T) {
		s, ring, rs, chain := setupErased(t)
		if cr := chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), chain); cr.Index != IndexErased {
			t.Fatalf("index %q, problems %v", cr.Index, cr.Problems)
		}
	})
	t.Run("no trust: unanchored", func(t *testing.T) {
		s, ring, _, chain := setupErased(t)
		if cr := chainReport(t, verifyWith(t, s, ring), chain); cr.Index != IndexErasedUnanchored {
			t.Fatalf("index %q", cr.Index)
		}
	})
	t.Run("bad erasure signature: unanchored", func(t *testing.T) {
		s, ring, rs, chain := setupErased(t)
		ids := entryIDs(t, s, chain)
		last := ids[len(ids)-1]
		withSignatures(t, s, func(b *bolt.Bucket) error {
			v := append([]byte(nil), b.Get(rowKey(chain, last))...)
			v[len(v)-1] ^= 1
			return b.Put(rowKey(chain, last), v)
		})
		if cr := chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), chain); cr.Index != IndexErasedUnanchored {
			t.Fatalf("index %q", cr.Index)
		}
	})
	t.Run("another problem: unanchored", func(t *testing.T) {
		s, ring, rs, chain := setupErased(t)
		ids := entryIDs(t, s, chain)
		if err := writeContent(s, chain, ids[0], []byte(`{"back":1}`)); err != nil { // erased content is back
			t.Fatal(err)
		}
		if cr := chainReport(t, verifyWith(t, s, ring, WithRecordTrust(recordRing(t, rs))), chain); cr.Index != IndexErasedUnanchored {
			t.Fatalf("index %q", cr.Index)
		}
	})
}

// countingSource counts PublicKey lookups.
type countingSource struct {
	inner anchor.KeySource
	mu    sync.Mutex
	n     int
}

func (c *countingSource) PublicKey(id string) ([]byte, anchor.Trust, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.inner.PublicKey(id)
}

func TestVerifyRecords_KeyLookedUpOnce(t *testing.T) {
	s, ring, rs := signedSink(t)
	src := &countingSource{inner: recordRing(t, rs)}
	verifyWith(t, s, ring, WithRecordTrust(src))
	if src.n != 1 {
		t.Fatalf("%d key lookups for one record key; want 1", src.n)
	}
}

func TestVerifyRecords_NilTrust(t *testing.T) {
	s, ring, _ := signedSink(t)
	if _, err := s.Verify(context.Background(), ring, WithRecordTrust(nil)); err == nil {
		t.Fatal("WithRecordTrust(nil) was accepted")
	}
}

// R7: UsesRecordKey reports every record key ever used, and nothing else.
func TestUsesRecordKey(t *testing.T) {
	ctx := context.Background()
	a, b := testRecordSigner(t, 7), testRecordSigner(t, 8)
	ka, _ := recordKeyOf(a)
	kb, _ := recordKeyOf(b)
	dir := t.TempDir()
	if _, err := openSigning(t, dir, a).Commit(ctx, events("u-1", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := openSigning(t, dir, b).Commit(ctx, events("u-1", 1)); err != nil { // rotated
		t.Fatal(err)
	}
	s := mustOpen(t, dir)
	for id, want := range map[string]bool{ka.id: true, kb.id: true, strings.Repeat("0", 32): false} {
		if got, err := s.UsesRecordKey(ctx, id); err != nil || got != want {
			t.Fatalf("UsesRecordKey(%s) = %t, %v; want %t", id, got, err, want)
		}
	}
	plain, _, _ := setup(t)
	if got, err := plain.UsesRecordKey(ctx, ka.id); err != nil || got {
		t.Fatalf("an unsigned sink: %t, %v", got, err)
	}
}
