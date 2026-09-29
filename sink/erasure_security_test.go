// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"crypto/sha512"
	"os"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/internal/noncestore"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// TestErase_ForgedErasureIsRejected is review finding 1.1. entry_type is not in
// the chain hash or the checkpoint, so a writer can relabel event k as an
// erasure. If an erasure record were checked by plain SHA-512, the writer could
// make the "record" the 115-byte commitment preimage of event k, whose plain
// SHA-512 IS k's commitment. Events before k would then verify as ERASED, not
// MISSING, under a valid signed checkpoint.
func TestErase_ForgedErasureIsRejected(t *testing.T) {
	ctx := context.Background()
	s, _, ring := setup(t) // u-81 has 3 events, all checkpointed
	ids := entryIDs(t, s, cid(t, s, "u-81"))
	victim, forged := ids[0], ids[1]

	// The writer knows event k's content and nonce (it wrote them).
	content, err := os.ReadFile(s.contentPath(cid(t, s, "u-81"), forged))
	if err != nil {
		t.Fatal(err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := ns.Get(cid(t, s, "u-81"), forged)
	if err != nil {
		t.Fatal(err)
	}
	inner := sha512.Sum512(content)
	preimage := append(append([]byte("aleutian.commit.v1:"), nonce...), inner[:]...)

	// Relabel k as an erasure (the chain hash does not cover the type).
	st, err := boltstore.Open(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.Range(ctx, cid(t, s, "u-81"), 0, 1<<62, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows[1].EntryType = EntryTypeErasure
	if err := st.WriteBatch(ctx, rows[1:2]); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// k's content becomes the preimage; the victim before it is deleted by hand.
	if err := os.WriteFile(s.contentPath(cid(t, s, "u-81"), forged), preimage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.contentPath(cid(t, s, "u-81"), victim)); err != nil {
		t.Fatal(err)
	}
	if err := ns.Delete(cid(t, s, "u-81"), victim); err != nil {
		t.Fatal(err)
	}
	ns.Close()

	r, err := s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	c := chainReport(t, r, cid(t, s, "u-81"))
	if len(c.Problems) == 0 {
		t.Fatalf("a forged erasure verified: %+v — the deleted event passes as ERASED", c)
	}
	if !strings.Contains(strings.Join(c.Problems, "; "), "erasure record") {
		t.Fatalf("problems do not name the forged erasure record: %q", c.Problems)
	}
}

// TestErase_RemovesNoncesFromTheFile is review finding 1.2. Deleting keys in
// bbolt leaves the bytes in free pages: an erased nonce must not be findable
// anywhere in the live nonce file.
func TestErase_RemovesNoncesFromTheFile(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	nonces := func(chain string) [][]byte {
		ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer ns.Close()
		var out [][]byte
		for _, id := range entryIDs(t, s, chain) {
			n, err := ns.Get(chain, id)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	erased, kept := nonces(cid(t, s, "u-81")), nonces(cid(t, s, "u-82"))

	if _, err := s.Erase(ctx, cid(t, s, "u-81")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(noncestore.PathFor(s.DBPath()))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range erased {
		if bytes.Contains(raw, n) {
			t.Fatalf("an erased nonce is still in the nonce file's bytes")
		}
	}
	for _, n := range kept { // control: the scan does find live nonces
		if !bytes.Contains(raw, n) {
			t.Fatalf("control failed: a live nonce was not found in the raw file")
		}
	}
}

// TestErase_DeletesSourcesAndForgetsThem is review finding 1.3, owner decision
// (a). Erasure deletes the chain's upstream positions from the live sources
// file, so the file no longer maps the erased pseudonym to upstream messages.
// The accepted cost: a redelivery after the erasure is committed again, after
// the erasure entry, where it is visible and can be erased again.
func TestErase_DeletesSourcesAndForgetsThem(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recs := sourced("u-1", 2, 900)
	if _, err := s.Commit(ctx, append(recs, sourced("u-2", 1, 950)...)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Erase(ctx, cid(t, s, "u-1")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.sourcesPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if bytes.Contains(raw, []byte(r.Source)) {
			t.Fatalf("erased chain's source %q is still in the sources file's bytes", r.Source)
		}
	}
	if !bytes.Contains(raw, []byte("EVIDENCE:950")) { // control
		t.Fatal("control failed: a live source was not found in the raw file")
	}

	got, err := s.Commit(ctx, recs)
	if err != nil || got[0].Entries != 2 || got[0].Duplicates != 0 {
		t.Fatalf("redelivery after erasure: %v, %v; want committed again (decision (a))", got, err)
	}
	if n := len(entryIDs(t, s, cid(t, s, "u-1"))); n != 5 { // 2 events + erasure + 2 re-committed
		t.Fatalf("u-1 holds %d entries, want 5", n)
	}
}

// relabel rewrites one stored entry's type, as a writer of the evidence file
// can: entry_type is bound by neither the chain nor the checkpoints.
func relabel(t *testing.T, s *Sink, chain string, index int, entryType string) string {
	t.Helper()
	st, err := boltstore.Open(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.Range(context.Background(), chain, 0, 1<<62, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows[index].EntryType = entryType
	if err := st.WriteBatch(context.Background(), rows[index:index+1]); err != nil {
		t.Fatal(err)
	}
	return rows[index].EntryID
}

// TestErase_ForgedErasureWithTheRightRecord: the forger writes the exact record
// for the position. Only the domain-separated hash catches this: the relabelled
// entry's content_hash is an event commitment, never the hash of a record.
func TestErase_ForgedErasureWithTheRightRecord(t *testing.T) {
	s, _, ring := setup(t)
	ids := entryIDs(t, s, cid(t, s, "u-81"))
	st, err := boltstore.Open(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.Range(context.Background(), cid(t, s, "u-81"), 0, 1<<62, 0)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	relabel(t, s, cid(t, s, "u-81"), 1, EntryTypeErasure)
	if err := os.WriteFile(s.contentPath(cid(t, s, "u-81"), ids[1]), erasureRecord(rows[0].GlobalSeq), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, cid(t, s, "u-81")); !strings.Contains(strings.Join(c.Problems, "; "), "erasure record") {
		t.Fatalf("a relabelled event with the right record verified: %+v", c)
	}
}

// TestErase_ErasureCannotBeFirst: there is nothing before the first entry to
// erase, and no predecessor sequence to rebuild the record from.
func TestErase_ErasureCannotBeFirst(t *testing.T) {
	s, _, ring := setup(t)
	relabel(t, s, cid(t, s, "u-90"), 0, EntryTypeErasure)
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, cid(t, s, "u-90")); !strings.Contains(strings.Join(c.Problems, "; "), "first entry") {
		t.Fatalf("an erasure as the first entry verified: %+v", c)
	}
}

// TestErasureRecordVector pins the exact record bytes and the domain-separated
// hash to values computed independently (Python hashlib), so another language
// has a fixed target (docs/sink-format.md §2, §4).
func TestErasureRecordVector(t *testing.T) {
	const wantRecord = `{"erased":"every earlier event on this chain","through_global_seq":"41"}`
	const wantHash = "d5979bd4d18e94664d1487cfd494a8441569b07db5346dfc95e2c55f43e2bdf916ef3f28d05864f940dc364ac5986ffd1be5822bdd48ae08fda1d80ed6d09296"
	if got := string(erasureRecord(41)); got != wantRecord {
		t.Fatalf("record %s, want %s", got, wantRecord)
	}
	if got := erasureHash([]byte(wantRecord)); got != wantHash {
		t.Fatalf("hash %s, want %s", got, wantHash)
	}
}
