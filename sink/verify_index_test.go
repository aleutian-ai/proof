// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// Verify's cross-check of the evidence file against the subject index
// (ticket _69c, states S1–S7).

func verifyAll(t *testing.T, s *Sink) Report {
	t.Helper()
	_, ring := newSigner(t)
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasProblem(cr ChainReport, substr string) bool {
	for _, p := range cr.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// updateIndex edits the subject index directly, as a crash or an editor would.
func updateIndex(t *testing.T, s *Sink, fn func(tx *bolt.Tx) error) {
	t.Helper()
	db, err := bolt.Open(s.subjectsPath(), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(fn); err != nil {
		t.Fatal(err)
	}
}

// S1 and S3: live chains, and an erased subject's chains, are not problems;
// the report carries class and state, never the subject. An erasure no
// checkpoint covers yet is "erased-unanchored" (E1); a checkpoint over it makes
// it "erased".
func TestVerifyIndex_LiveAndErased(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	signer, ring := newSigner(t)
	if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(ctx, ring)
	if err != nil || !r.OK() {
		t.Fatalf("problems: %+v, %v", r, err)
	}
	if got := chainReport(t, r, chains["auth/u-1"]).Index; got != IndexErasedUnanchored {
		t.Fatalf("an erasure no checkpoint covers: %q, want %q", got, IndexErasedUnanchored)
	}
	if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
		t.Fatal(err)
	}
	if r, err = s.Verify(ctx, ring); err != nil || !r.OK() {
		t.Fatalf("problems: %+v, %v", r, err)
	}
	for key, want := range map[string]IndexState{"payments/u-1": IndexErased, "auth/u-1": IndexErased,
		"payments/u-2": IndexLive} {
		cr := chainReport(t, r, chains[key])
		if cr.Index != want || cr.Class != strings.Split(key, "/")[0] {
			t.Fatalf("%s: index %q class %q; want %q", key, cr.Index, cr.Class, want)
		}
	}
	raw, err := json.Marshal(r)
	if err != nil || bytes.Contains(raw, []byte("u-")) {
		t.Fatalf("the report names a subject: %s", raw)
	}
}

// S2: a chain whose subject was forgotten but not yet erased fails, naming the
// remedy. If a forward row still names the subject (a half-forgotten index),
// that is reported too: the subject survives its erasure.
func TestVerifyIndex_PendingIsAProblem(t *testing.T) {
	s, chains := multi(t)
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subj.forget("u-1", "auth"); err != nil { // a crash right after forget
		t.Fatal(err)
	}
	subj.Close()
	r := verifyAll(t, s)
	cr := chainReport(t, r, chains["auth/u-1"])
	if r.OK() || cr.Index != IndexPending || !hasProblem(cr, "erase --resume") || hasProblem(cr, "inconsistent") {
		t.Fatalf("pending chain: %+v", cr)
	}

	updateIndex(t, s, func(tx *bolt.Tx) error { // the forward row comes back
		return tx.Bucket(forwardBucket).Put(forwardKey("u-1", "auth"), []byte(chains["auth/u-1"]))
	})
	r = verifyAll(t, s)
	cr = chainReport(t, r, chains["auth/u-1"])
	if cr.Index != IndexMalformed || !hasProblem(cr, "inconsistent") || !hasProblem(cr, "erase --resume") {
		t.Fatalf("pending chain whose forward row survived: %+v", cr)
	}
}

// S4: a live chain with no index row is unaccounted for. So is one whose last
// entry is an erasure in name only (relabelled, wrong hash).
func TestVerifyIndex_UnaccountedChain(t *testing.T) {
	cases := map[string]bool{"plain": false, "fake erasure at the end": true}
	for name, fake := range cases {
		t.Run(name, func(t *testing.T) {
			s, chains := multi(t)
			chain := chains["payments/u-2"]
			if fake {
				st, err := s.openStore(false)
				if err != nil {
					t.Fatal(err)
				}
				l, err := linker.New(st)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				if _, err := l.Append(context.Background(), chain, []linker.Input{{EntryID: "sink-" + strings.Repeat("d", 32),
					EntryType: EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("ab", 64)}}); err != nil {
					t.Fatal(err)
				}
				st.Close()
			}
			updateIndex(t, s, func(tx *bolt.Tx) error {
				if err := tx.Bucket(forwardBucket).Delete(forwardKey("u-2", "payments")); err != nil {
					return err
				}
				return tx.Bucket(reverseBucket).Delete([]byte(chain))
			})
			r := verifyAll(t, s)
			cr := chainReport(t, r, chain)
			if r.OK() || cr.Index != IndexUnaccounted || !hasProblem(cr, "not accounted for") {
				t.Fatalf("unaccounted chain: %+v", cr)
			}
		})
	}
}

// S5: an index row with no chain yet (a first commit stopped before its
// append) is reported, and is NOT a problem (owner decision V1).
func TestVerifyIndex_IndexOnlyIsANote(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	chain := bindChain(t, s, "u-1")
	r := verifyAll(t, s)
	cr := chainReport(t, r, chain)
	if !r.OK() || cr.Index != IndexOnly || cr.Class != testClass || len(cr.Problems) != 0 {
		t.Fatalf("index-only: OK=%v %+v", r.OK(), cr)
	}
	// With leftover content beside it, the leftovers are a problem, and the
	// remedy is the subject's erasure.
	if err := writeContent(s, chain, "sink-"+strings.Repeat("6", 32), []byte(`{"user":"u-1"}`)); err != nil {
		t.Fatal(err)
	}
	r = verifyAll(t, s)
	cr = chainReport(t, r, chain)
	if r.OK() || cr.Index != IndexOnly || !hasProblem(cr, "erasing its subject removes them") {
		t.Fatalf("index-only with leftovers: %+v", cr)
	}
	if n := strings.Count(strings.Join(func() []string {
		var ids []string
		for _, c := range r.Chains {
			ids = append(ids, c.Chain)
		}
		return ids
	}(), " "), chain); n != 1 {
		t.Fatalf("chain reported %d times, want once", n)
	}
}

// S6: a pending row whose chain has no entries is a problem.
func TestVerifyIndex_PendingWithoutChain(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	chain := bindChain(t, s, "u-1")
	updateIndex(t, s, func(tx *bolt.Tx) error {
		if err := tx.Bucket(forwardBucket).Delete(forwardKey("u-1", testClass)); err != nil {
			return err
		}
		return tx.Bucket(reverseBucket).Put([]byte(chain), pendingMarker)
	})
	r := verifyAll(t, s)
	cr := chainReport(t, r, chain)
	if r.OK() || cr.Index != IndexPending || !hasProblem(cr, "erase --resume") {
		t.Fatalf("pending, no chain: %+v", cr)
	}
}

// S7: rows that disagree with the index are problems, never read as subjects.
func TestVerifyIndex_MalformedRows(t *testing.T) {
	cases := map[string]func(tx *bolt.Tx, c map[string]string) (string, error){
		"reverse row names another pair": func(tx *bolt.Tx, c map[string]string) (string, error) {
			return c["payments/u-2"], tx.Bucket(reverseBucket).Put([]byte(c["payments/u-2"]), reverseValue("payments", "u-9"))
		},
		"reverse row of another class": func(tx *bolt.Tx, c map[string]string) (string, error) {
			return c["auth/u-1"], tx.Bucket(reverseBucket).Put([]byte(c["auth/u-1"]), reverseValue("payments", "u-1"))
		},
		"consistent rows binding a pair to another class's chain": func(tx *bolt.Tx, c map[string]string) (string, error) {
			chain := c["auth/u-1"]
			if err := tx.Bucket(forwardBucket).Put(forwardKey("u-1", "payments"), []byte(chain)); err != nil {
				return "", err
			}
			return chain, tx.Bucket(reverseBucket).Put([]byte(chain), reverseValue("payments", "u-1"))
		},
		"reverse row naming a pair with no forward row": func(tx *bolt.Tx, c map[string]string) (string, error) {
			chain := c["payments/u-2"]
			if err := tx.Bucket(forwardBucket).Delete(forwardKey("u-2", "payments")); err != nil {
				return "", err
			}
			return chain, tx.Bucket(reverseBucket).Put([]byte(chain), reverseValue("payments", "u-9"))
		},
		"NUL row that is not the marker": func(tx *bolt.Tx, c map[string]string) (string, error) {
			return c["auth/u-1"], tx.Bucket(reverseBucket).Put([]byte(c["auth/u-1"]), []byte("\x00u-1"))
		},
		"row for an id this sink never mints, shown only by number": func(tx *bolt.Tx, _ map[string]string) (string, error) {
			return "<invalid index row #1>", tx.Bucket(reverseBucket).Put([]byte("u-1\x00payments"), reverseValue("events", "u-1"))
		},
		"forward row to a chain bound to another pair": func(tx *bolt.Tx, c map[string]string) (string, error) {
			return c["payments/u-2"], tx.Bucket(forwardBucket).Put(forwardKey("u-7", "payments"), []byte(c["payments/u-2"]))
		},
		"forward row to nothing": func(tx *bolt.Tx, _ map[string]string) (string, error) {
			return "<invalid index row #1>", tx.Bucket(forwardBucket).Put(forwardKey("u-7", "payments"), []byte("payments."+strings.Repeat("0", 32)))
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			s, chains := multi(t)
			var chain string
			updateIndex(t, s, func(tx *bolt.Tx) error {
				var err error
				chain, err = corrupt(tx, chains)
				return err
			})
			r := verifyAll(t, s)
			cr := chainReport(t, r, chain)
			if r.OK() || cr.Index != IndexMalformed || !hasProblem(cr, "inconsistent") {
				t.Fatalf("malformed row: %+v", cr)
			}
			raw, err := json.Marshal(r)
			if err != nil || bytes.Contains(raw, []byte("u-")) {
				t.Fatalf("the report shows index bytes that name a subject: %s", raw)
			}
		})
	}
}

// Verify reads the index read-only: with no index file, every live chain is
// unaccounted, and no index file is created.
func TestVerifyIndex_MissingIndexCreatesNothing(t *testing.T) {
	s, chains := multi(t)
	if err := os.Remove(s.subjectsPath()); err != nil {
		t.Fatal(err)
	}
	r := verifyAll(t, s)
	if r.OK() || chainReport(t, r, chains["payments/u-2"]).Index != IndexUnaccounted {
		t.Fatalf("no index: %+v", r)
	}
	if _, err := os.Stat(s.subjectsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Verify created a subject index")
	}
}

// ChainSubjects is the deliberate call that names subjects: live rows only.
func TestChainSubjects(t *testing.T) {
	s, chains := multi(t)
	if _, err := s.EraseSubjectClass(context.Background(), "u-1", "payments"); err != nil {
		t.Fatal(err)
	}
	updateIndex(t, s, func(tx *bolt.Tx) error { // a pending row: never listed
		if err := tx.Bucket(forwardBucket).Delete(forwardKey("u-2", "payments")); err != nil {
			return err
		}
		return tx.Bucket(reverseBucket).Put([]byte(chains["payments/u-2"]), pendingMarker)
	})
	rows, err := s.ChainSubjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0] != (ChainSubject{Chain: chains["auth/u-1"], Class: "auth", Subject: "u-1"}) {
		t.Fatalf("ChainSubjects = %+v; want only u-1's live auth chain", rows)
	}
}

// An index restored from before an erasure re-links the erased subject (1.1):
// Verify reports it, ChainSubjects never names it, Commit refuses to append to
// the erased history, and resume forgets it again.
func TestVerifyIndex_RestoredIndexRelinks(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	backup, err := os.ReadFile(s.subjectsPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseSubject(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.subjectsPath(), backup, 0o600); err != nil { // "restore from backup"
		t.Fatal(err)
	}

	r := verifyAll(t, s)
	for _, key := range []string{"payments/u-1", "auth/u-1"} {
		if cr := chainReport(t, r, chains[key]); cr.Index != IndexRelinked || !hasProblem(cr, "erase --resume") {
			t.Fatalf("%s after the restore: %+v", key, cr)
		}
	}
	rows, err := s.ChainSubjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Subject == "u-1" {
			t.Fatalf("ChainSubjects named the erased subject: %+v", row)
		}
	}
	if _, err := s.Commit(ctx, []Record{{Class: "auth", Subject: "u-1", Content: []byte(`{"login":1}`)}}); err == nil {
		t.Fatal("a commit was appended to an erased chain through the restored index")
	}

	resumed, err := s.ResumeErasures(ctx)
	if err != nil || len(resumed) != 2 {
		t.Fatalf("resume = %+v, %v; want both relinked chains forgotten again", resumed, err)
	}
	if r := verifyAll(t, s); !r.OK() || chainReport(t, r, chains["auth/u-1"]).Index != IndexErasedUnanchored {
		t.Fatalf("after resume: %+v", r)
	}
	if _, err := s.Commit(ctx, []Record{{Class: "auth", Subject: "u-1", Content: []byte(`{"login":1}`)}}); err != nil {
		t.Fatal(err)
	}
	if c := cidIn(t, s, "auth", "u-1"); c == chains["auth/u-1"] {
		t.Fatal("the returning subject rejoined its erased chain")
	}
}

// ChainSubjects with no index file names nobody, and creates nothing.
func TestChainSubjects_NoIndex(t *testing.T) {
	s, _ := multi(t)
	if err := os.Remove(s.subjectsPath()); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ChainSubjects(context.Background())
	if err != nil || rows != nil {
		t.Fatalf("ChainSubjects = %+v, %v; want nothing", rows, err)
	}
	if _, err := os.Stat(s.subjectsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ChainSubjects created a subject index")
	}
}

// A malformed row is never listed by ChainSubjects.
func TestChainSubjects_SkipsMalformed(t *testing.T) {
	s, chains := multi(t)
	updateIndex(t, s, func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).Put([]byte(chains["payments/u-2"]), reverseValue("payments", "u-9"))
	})
	rows, err := s.ChainSubjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Chain == chains["payments/u-2"] {
			t.Fatalf("a malformed row was listed: %+v", row)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v; want u-1's two live chains", rows)
	}
}

// Checkpoints left for a chain the index binds but the evidence file lacks:
// entries were removed, whatever the index says.
func TestVerifyIndex_AnchorsBesideIndexOnly(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-0", 1)); err != nil {
		t.Fatal(err)
	}
	chain := bindChain(t, s, "u-1")
	if err := os.MkdirAll(s.anchorDir(chain), 0o700); err != nil {
		t.Fatal(err)
	}
	r := verifyAll(t, s)
	cr := chainReport(t, r, chain)
	if r.OK() || cr.Anomaly != "removed" || cr.Index != IndexOnly || !hasProblem(cr, "REMOVED") {
		t.Fatalf("anchors beside an index-only row: %+v", cr)
	}
}

// An event relabelled as an erasure mid-chain erases nothing: the events before
// it whose content is gone are MISSING, not erased (the same rule as erase).
func TestVerify_RelabelledErasureErasesNothing(t *testing.T) {
	ctx := context.Background()
	s, chains := multi(t)
	chain := chains["payments/u-2"]
	first := entryIDs(t, s, chain)[0]
	st, err := s.openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: "sink-" + strings.Repeat("d", 32),
		EntryType: EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// The event's content AND nonce gone: what a real erasure leaves.
	if err := removeContent(s, chain, first); err != nil {
		t.Fatal(err)
	}
	if err := removeNonce(s, chain, first); err != nil {
		t.Fatal(err)
	}
	cr := chainReport(t, verifyAll(t, s), chain)
	if cr.Erased != 0 || !hasProblem(cr, "MISSING") {
		t.Fatalf("a relabelled erasure counted %d events as erased: %+v", cr.Erased, cr)
	}
}
