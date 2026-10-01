// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

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
