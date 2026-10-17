// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// Three ways someone who can write the sink folder, and holds no key, once got
// the sink to accept or sign state it never made. Each test makes the attack
// as that writer would, through the files, and shows where it now stops.

// confirm passes erase results back, as a caller that just erased does.
func confirm(results ...EraseResult) CheckpointOption { return ConfirmErasures(results...) }

// forgeErasure appends a well-formed erasure entry to a chain, stores its
// record, and deletes the chain's content and nonces, as the sink's own
// erasure does: everything a writer of the folder can do without a key. It
// returns the forged entry's id.
func forgeErasure(t *testing.T, s *Sink, chain string) string {
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
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	id, err := newEntryID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
		Timestamp: now, IngestedAt: now, ContentHash: erasureHash(rec)}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.putAll(map[string]map[string]secret{chain: {id: {content: rec}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.eraseChain(chain, map[string][]byte{id: rec}); err != nil {
		t.Fatal(err)
	}
	sec.Close()
	return id
}

// dropIndexRows removes a subject's index rows outright, as a forger does: the
// chain is then accounted for only by the erasure at its end.
func dropIndexRows(t *testing.T, s *Sink, subject string) {
	t.Helper()
	subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Close()
	chains, err := subj.forget(subject, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		if err := subj.clear(c); err != nil {
			t.Fatal(err)
		}
	}
}

// TestForgedErasure_IsNotCheckpointed: an erasure record appended to the end
// of a chain by a writer of the folder, with the chain's index row removed,
// verifies as erased-unanchored, exactly as a real erasure does. The operator's
// routine Checkpoint once signed over it, and the chain then read "erased".
func TestForgedErasure_IsNotCheckpointed(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	forged := forgeErasure(t, s, chain)
	dropIndexRows(t, s, "u-81")

	// It still passes Verify: a folder cannot tell it from a real erasure.
	rep, err := s.Verify(ctx, ring)
	if err != nil || !rep.OK() {
		t.Fatalf("verify: %+v, %v", rep, err)
	}
	if got := chainReport(t, rep, chain).Index; got != IndexErasedUnanchored {
		t.Fatalf("index state %q, want %q", got, IndexErasedUnanchored)
	}

	// The routine checkpoint refuses it, and says what to do.
	done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	p := problemFor(done, chain)
	if !strings.Contains(p, "erasure that no checkpoint covers") || !strings.Contains(p, "erase … --key") {
		t.Fatalf("Checkpoint = %+v; want the chain refused, with the way to confirm an erasure", done)
	}
	if _, err := os.Stat(filepath.Join(s.anchorDir(chain), "0002.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a checkpoint was signed over a forged erasure")
	}
	rep, err = s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	if cr := chainReport(t, rep, chain); cr.Index != IndexErasedUnanchored || cr.Checkpoints != 1 {
		t.Fatalf("after the checkpoint run: %+v; want still erased-unanchored under its one checkpoint", cr)
	}

	// Variations.
	t.Run("confirming another erasure does not cover it", func(t *testing.T) {
		res, err := s.EraseSubject(ctx, "u-82")
		if err != nil {
			t.Fatal(err)
		}
		done, err := s.Checkpoint(ctx, signer, nil, confirm(res.Erased...), UntrackedHeads())
		if err != nil {
			t.Fatal(err)
		}
		if problemFor(done, chain) == "" {
			t.Fatalf("the forged erasure was signed alongside a confirmed one: %+v", done)
		}
		if problemFor(done, res.Erased[0].Chain) != "" {
			t.Fatalf("the confirmed erasure was refused: %+v", done)
		}
	})
	t.Run("a forged erasure in place of a confirmed one", func(t *testing.T) {
		// The operator erases u-90; before the checkpoint, the writer cuts that
		// erasure entry off and appends its own. The id confirmed is the
		// operator's, not the entry now at the end.
		res, err := s.EraseSubject(ctx, "u-90")
		if err != nil {
			t.Fatal(err)
		}
		victim := res.Erased[0].Chain
		truncateTail(t, s, victim)
		forgeErasure(t, s, victim)
		done, err := s.Checkpoint(ctx, signer, nil, confirm(res.Erased...), UntrackedHeads())
		if err != nil {
			t.Fatal(err)
		}
		if problemFor(done, victim) == "" {
			t.Fatalf("an erasure entry swapped in after the confirmed one was signed: %+v", done)
		}
	})
	t.Run("a result that is not a chain and an entry id is refused", func(t *testing.T) {
		for _, r := range []EraseResult{{Chain: chain, ErasureEntryID: "../" + forged}, {Chain: "../x", ErasureEntryID: forged}} {
			if _, err := s.Checkpoint(ctx, signer, nil, ConfirmErasures(r), UntrackedHeads()); err == nil {
				t.Fatalf("ConfirmErasures took %+v", r)
			}
		}
	})
}

// truncateTail removes a chain's last entry from the evidence file.
func truncateTail(t *testing.T, s *Sink, chain string) {
	t.Helper()
	db, err := bolt.Open(s.DBPath(), 0o600, &bolt.Options{Timeout: DefaultLockTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte("entries")).Cursor()
		prefix := append([]byte(chain), 0)
		var last []byte
		for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
			last = append(last[:0], k...)
		}
		if last == nil {
			return fmt.Errorf("chain %s has no entries", chain)
		}
		return tx.Bucket([]byte("entries")).Delete(last)
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRealErasure_IsCheckpointedWhenConfirmed: the operator's own erasure is
// signed over, with either kind of evidence, and not without.
func TestRealErasure_IsCheckpointedWhenConfirmed(t *testing.T) {
	ctx := context.Background()
	t.Run("in-process confirmation", func(t *testing.T) {
		s, signer, ring := setup(t)
		chain := cid(t, s, "u-81")
		res, err := s.EraseSubject(ctx, "u-81")
		if err != nil {
			t.Fatal(err)
		}
		// Not without it: a real erasure and a forged one look the same.
		done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
		if err != nil || problemFor(done, chain) == "" {
			t.Fatalf("an unconfirmed erasure was signed: %+v, %v", done, err)
		}
		// Only the chains named, when asked.
		done, err = s.Checkpoint(ctx, signer, nil, confirm(res.Erased...), OnlyChains(chain), UntrackedHeads())
		if err != nil || len(done) != 1 || done[0].Chain != chain || done[0].Problem != "" {
			t.Fatalf("Checkpoint = %+v, %v; want exactly the erased chain signed", done, err)
		}
		if cr := chainReport(t, mustVerify(t, s, ring), chain); cr.Index != IndexErased || cr.Checkpoints != 2 {
			t.Fatalf("after the confirmed checkpoint: %+v", cr)
		}
	})
	t.Run("record signature", func(t *testing.T) {
		rs := testRecordSigner(t, 7)
		s := openSigning(t, t.TempDir(), rs)
		signer, ring := newSigner(t)
		if _, err := s.Commit(ctx, events("u-81", 2)); err != nil {
			t.Fatal(err)
		}
		chain := cid(t, s, "u-81")
		if _, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EraseSubject(ctx, "u-81"); err != nil {
			t.Fatal(err)
		}
		done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
		if err != nil || problemFor(done, chain) == "" {
			t.Fatalf("without record trust the erasure was signed: %+v, %v", done, err)
		}
		done, err = s.Checkpoint(ctx, signer, nil, CheckpointRecordTrust(recordRing(t, rs)), UntrackedHeads())
		if err != nil || len(done) != 1 || done[0].Problem != "" {
			t.Fatalf("Checkpoint with record trust = %+v, %v; want the erased chain signed", done, err)
		}
		if cr := chainReport(t, mustVerify(t, s, ring), chain); cr.Index != IndexErased || cr.Checkpoints != 2 {
			t.Fatalf("after the checkpoint: %+v", cr)
		}
	})
	t.Run("a forged erasure on a signing sink has no signature", func(t *testing.T) {
		rs := testRecordSigner(t, 7)
		s := openSigning(t, t.TempDir(), rs)
		signer, _ := newSigner(t)
		if _, err := s.Commit(ctx, events("u-81", 2)); err != nil {
			t.Fatal(err)
		}
		chain := cid(t, s, "u-81")
		forgeErasure(t, s, chain)
		dropIndexRows(t, s, "u-81")
		done, err := s.Checkpoint(ctx, signer, nil, CheckpointRecordTrust(recordRing(t, rs)), UntrackedHeads())
		if err != nil || problemFor(done, chain) == "" {
			t.Fatalf("an unsigned erasure was signed over under record trust: %+v, %v", done, err)
		}
	})
}

// TestForgedErasure_RelinkedIsNotConfirmedByResume: the smallest forgery is one
// entry: an erasure record appended to a chain whose index row is left alone.
// Verify calls that relinked and says to run resume, which forgets the subject
// again and deletes the content. Resume reports such a chain as Relinked: its
// erasure entry was not made by the erasure the sink knows of, so a caller
// must not confirm it blindly.
func TestForgedErasure_RelinkedIsNotConfirmedByResume(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	forgeErasure(t, s, chain) // the index row stays
	rep, err := s.Verify(ctx, ring)
	if err != nil || chainReport(t, rep, chain).Index != IndexRelinked {
		t.Fatalf("verify: %+v, %v; want the chain relinked", rep, err)
	}
	resumed, err := s.ResumeErasures(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 1 || !resumed[0].Relinked || resumed[0].Chain != chain {
		t.Fatalf("ResumeErasures = %+v; want the one chain, marked Relinked", resumed)
	}
	// A real interrupted erasure is not marked.
	if res, err := s.EraseSubject(ctx, "u-82"); err != nil || res.Erased[0].Relinked {
		t.Fatalf("EraseSubject = %+v, %v; an ordinary erasure is not Relinked", res, err)
	}
	// Left unconfirmed, it is never signed.
	done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
	if err != nil || problemFor(done, chain) == "" {
		t.Fatalf("Checkpoint = %+v, %v; want the relinked chain's erasure refused", done, err)
	}
}

// poisonSources writes rows into the sources file that point future sources at
// an entry the chain already holds: no key needed.
func poisonSources(t *testing.T, s *Sink, chain, entryID string, seq int64, sources ...string) {
	t.Helper()
	src, err := openSources(s.sourcesPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	pos := map[string]position{}
	for _, name := range sources {
		pos[name] = position{entryID: entryID, seq: seq}
	}
	if err := src.putBatch(chain, pos); err != nil {
		t.Fatal(err)
	}
}

// TestSourcePoison_NewRecordsAreNotDropped: rows written into the sources file
// for sources that have not arrived yet once made the records that later
// carried them come back "committed, duplicate" with nothing appended. A queue
// consumer acknowledged them, and they were gone.
func TestSourcePoison_NewRecordsAreNotDropped(t *testing.T) {
	ctx := context.Background()
	s, _, ring := setup(t)
	chain := cid(t, s, "u-81")
	ids := entryIDs(t, s, chain)
	poisonSources(t, s, chain, ids[0], 0, "EVIDENCE:0", "EVIDENCE:1", "EVIDENCE:2")

	recs := events("u-81", 3)
	for i := range recs {
		recs[i].Source = fmt.Sprintf("EVIDENCE:%d", i)
		recs[i].Content = []byte(fmt.Sprintf(`{"new":"event %d"}`, i))
	}
	out, err := s.Commit(ctx, recs)
	if !errors.Is(err, ErrSourceConflict) {
		t.Fatalf("Commit = %s, %v; want ErrSourceConflict", pattern(out), err)
	}
	var re *RecordError
	if !errors.As(err, &re) || re.Index != 0 {
		t.Fatalf("err = %v; want a *RecordError naming record 0", err)
	}
	// All-or-none, and nothing reported committed: a consumer acks nothing.
	if pattern(out) != "---" {
		t.Fatalf("outcomes %s, want none committed", pattern(out))
	}
	if n := len(entryIDs(t, s, chain)); n != 3 {
		t.Fatalf("the chain holds %d entries, want its 3", n)
	}
	// The error names neither the source nor the content nor the chain.
	for _, secret := range []string{"EVIDENCE:", "new", chain} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error repeats %q: %v", secret, err)
		}
	}

	// Verify reports the poisoned file: three positions on one entry.
	rep, err := s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	cr := chainReport(t, rep, chain)
	if rep.OK() || !strings.Contains(strings.Join(cr.Problems, "\n"), "more than one source position") {
		t.Fatalf("verify did not report the entry with several sources: %+v", cr)
	}
	if strings.Contains(fmt.Sprintf("%+v", rep), "EVIDENCE:") {
		t.Fatalf("the report shows a source: %+v", rep)
	}

	t.Run("a row pointing nowhere suppresses nothing, and is reported", func(t *testing.T) {
		s, _, ring := setup(t)
		chain := cid(t, s, "u-81")
		poisonSources(t, s, chain, "sink-"+strings.Repeat("a", 32), 7, "EVIDENCE:9")
		rec := events("u-81", 1)
		rec[0].Source = "EVIDENCE:9"
		rec[0].Content = []byte(`{"new":"x"}`)
		if out, err := s.Commit(ctx, rec); err != nil || pattern(out) != "N" {
			t.Fatalf("Commit = %s, %v; want the record committed", pattern(out), err)
		}
		// The commit replaced the dangling row with the real position.
		mustVerify(t, s, ring)
		// One that stays dangling is a problem.
		poisonSources(t, s, chain, "sink-"+strings.Repeat("b", 32), 9, "EVIDENCE:10")
		rep, err := s.Verify(ctx, ring)
		if err != nil || rep.OK() {
			t.Fatalf("verify: %+v, %v; want the dangling position reported", rep, err)
		}
		if p := strings.Join(chainReport(t, rep, chain).Problems, "\n"); !strings.Contains(p, "matches no entry of this chain") {
			t.Fatalf("problems: %s", p)
		}
	})
	t.Run("the content row is gone", func(t *testing.T) {
		// The entry the row points at has no stored content to compare with:
		// the record cannot be shown to be the same one, so it is refused.
		s, _, _ := setup(t)
		chain := cid(t, s, "u-81")
		ids := entryIDs(t, s, chain)
		poisonSources(t, s, chain, ids[1], 1, "EVIDENCE:5")
		if err := withSecrets(s, func(tx *bolt.Tx) error {
			return tx.Bucket(contentBucket).Delete(rowKey(chain, ids[1]))
		}); err != nil {
			t.Fatal(err)
		}
		rec := events("u-81", 1)
		rec[0].Source = "EVIDENCE:5"
		if out, err := s.Commit(ctx, rec); !errors.Is(err, ErrSourceConflict) || pattern(out) != "-" {
			t.Fatalf("Commit = %s, %v; want ErrSourceConflict", pattern(out), err)
		}
	})
	t.Run("the same source twice in one call with different content", func(t *testing.T) {
		s, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		recs := events("u-1", 2)
		recs[0].Source, recs[1].Source = "EVIDENCE:1", "EVIDENCE:1"
		out, err := s.Commit(ctx, recs)
		var re *RecordError
		if !errors.Is(err, ErrSourceConflict) || !errors.As(err, &re) || re.Index != 1 || pattern(out) != "--" {
			t.Fatalf("Commit = %s, %v; want record 1 refused and nothing committed", pattern(out), err)
		}
	})
}

// TestSource_SameContentIsStillADuplicate: the redelivery case the source
// exists for is unchanged.
func TestSource_SameContentIsStillADuplicate(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recs := sourced("u-1", 3, 1)
	if out, err := s.Commit(ctx, recs); err != nil || pattern(out) != "NNN" {
		t.Fatalf("first: %s, %v", pattern(out), err)
	}
	if out, err := s.Commit(ctx, recs); err != nil || pattern(out) != "DDD" {
		t.Fatalf("redelivery: %s, %v; want every record a duplicate", pattern(out), err)
	}
	// The same position with other content is a conflict, every time.
	changed := sourced("u-1", 1, 1)
	changed[0].Content = []byte(`{"other":"content"}`)
	for i := 0; i < 2; i++ {
		if out, err := s.Commit(ctx, changed); !errors.Is(err, ErrSourceConflict) || pattern(out) != "-" {
			t.Fatalf("delivery %d: %s, %v; want ErrSourceConflict", i, pattern(out), err)
		}
	}
	if n := len(entryIDs(t, s, cid(t, s, "u-1"))); n != 3 {
		t.Fatalf("the chain holds %d entries, want 3", n)
	}
}

// TestCheckpointHeads_ARestartedSeriesIsRefused: with anchors/<chain>/ removed,
// Checkpoint once signed a fresh 0001.json over the chain as it stood, and
// Verify passed. With the heads kept outside the folder, both say the series
// was cut or restarted, and nothing is signed.
func TestCheckpointHeads_ARestartedSeriesIsRefused(t *testing.T) {
	ctx := context.Background()
	// withHeads is setup, plus one more checkpoint per chain, with the heads
	// recorded: u-81's series is 0001, 0002.
	withHeads := func(t *testing.T) (*Sink, *HeadsFile, string, func(...CheckpointOption) []Checkpointed, func() Report) {
		s, signer, ring := setup(t)
		heads := NewFileHeads(filepath.Join(t.TempDir(), "heads.json"))
		chain := cid(t, s, "u-81")
		checkpoint := func(opts ...CheckpointOption) []Checkpointed {
			t.Helper()
			done, err := s.Checkpoint(ctx, signer, nil, append(opts, TrackHeads(heads))...)
			if err != nil {
				t.Fatal(err)
			}
			return done
		}
		verify := func() Report {
			t.Helper()
			rep, err := s.Verify(ctx, ring, WithCheckpointHeads(heads))
			if err != nil {
				t.Fatal(err)
			}
			return rep
		}
		// The first run with heads records the series as it stands: nothing to
		// sign, three heads.
		if done := checkpoint(); len(done) != 0 {
			t.Fatalf("enrolment signed or refused something: %+v", done)
		}
		if n, _, ok, err := heads.Head(ctx, chain); err != nil || !ok || n != 1 {
			t.Fatalf("head after enrolment: %d, %v, %v", n, ok, err)
		}
		if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
			t.Fatal(err)
		}
		if done := checkpoint(); len(done) != 1 || done[0].Problem != "" {
			t.Fatalf("second checkpoint: %+v", done)
		}
		if n, _, ok, err := heads.Head(ctx, chain); err != nil || !ok || n != 2 {
			t.Fatalf("head after the second checkpoint: %d, %v, %v", n, ok, err)
		}
		if !verify().OK() {
			t.Fatal("a sink whose series are their heads does not verify")
		}
		return s, heads, chain, checkpoint, verify
	}
	refused := func(t *testing.T, s *Sink, chain string, checkpoint func(...CheckpointOption) []Checkpointed,
		verify func() Report, files int) {
		t.Helper()
		rep := verify()
		if p := strings.Join(chainReport(t, rep, chain).Problems, "\n"); rep.OK() || !strings.Contains(p, "cut or restarted") {
			t.Fatalf("verify did not report the series: %+v", chainReport(t, rep, chain))
		}
		done := checkpoint()
		if p := problemFor(done, chain); !strings.Contains(p, "cut or restarted") {
			t.Fatalf("Checkpoint = %+v; want the chain refused", done)
		}
		ents, _ := os.ReadDir(s.anchorDir(chain))
		if len(ents) != files {
			t.Fatalf("anchors/ holds %d checkpoints for the chain, want %d: something was signed", len(ents), files)
		}
	}

	t.Run("without heads nothing changed", func(t *testing.T) {
		s, signer, ring := setup(t)
		chain := cid(t, s, "u-81")
		if err := os.RemoveAll(s.anchorDir(chain)); err != nil {
			t.Fatal(err)
		}
		done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
		if err != nil || len(done) != 1 || done[0].Problem != "" {
			t.Fatalf("Checkpoint = %+v, %v", done, err)
		}
		mustVerify(t, s, ring) // the documented limitation, still
	})
	t.Run("series removed", func(t *testing.T) {
		s, _, chain, checkpoint, verify := withHeads(t)
		if err := os.RemoveAll(s.anchorDir(chain)); err != nil {
			t.Fatal(err)
		}
		refused(t, s, chain, checkpoint, verify, 0)
	})
	t.Run("last checkpoint removed", func(t *testing.T) {
		// The chain has nothing new past 0001's entries only if its tail is cut
		// too; here the entries stay, so 0002 would simply be signed again.
		s, _, chain, checkpoint, verify := withHeads(t)
		if err := os.Remove(filepath.Join(s.anchorDir(chain), "0002.json")); err != nil {
			t.Fatal(err)
		}
		refused(t, s, chain, checkpoint, verify, 1)
	})
	t.Run("last checkpoint removed and the chain cut back to match", func(t *testing.T) {
		// The truncation a checkpoint exists to catch: remove the entry 0002
		// covered and 0002 itself. Inside the folder everything agrees again.
		s, _, chain, checkpoint, verify := withHeads(t)
		if err := os.Remove(filepath.Join(s.anchorDir(chain), "0002.json")); err != nil {
			t.Fatal(err)
		}
		truncateTail(t, s, chain)
		refused(t, s, chain, checkpoint, verify, 1)
	})
	t.Run("series restarted by another signer's run", func(t *testing.T) {
		// Removed, then signed again from 0001 without the heads: the series is
		// as long as its head would allow after two runs, but it is not the same.
		s, heads, chain, _, verify := withHeads(t)
		signer2, ring2 := newSigner(t)
		if err := os.RemoveAll(s.anchorDir(chain)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Checkpoint(ctx, signer2, nil, UntrackedHeads()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Checkpoint(ctx, signer2, nil, UntrackedHeads()); err != nil {
			t.Fatal(err)
		}
		_ = verify
		rep, err := s.Verify(ctx, ring2, WithCheckpointHeads(heads))
		if err != nil {
			t.Fatal(err)
		}
		if p := strings.Join(chainReport(t, rep, chain).Problems, "\n"); !strings.Contains(p, "cut or restarted") {
			t.Fatalf("a restarted series of the same length verified: %+v", chainReport(t, rep, chain))
		}
		done, err := s.Checkpoint(ctx, signer2, nil, TrackHeads(heads))
		if err != nil || !strings.Contains(problemFor(done, chain), "cut or restarted") {
			t.Fatalf("Checkpoint = %+v, %v", done, err)
		}
	})
	t.Run("a heads file inside the sink folder is refused", func(t *testing.T) {
		s, signer, ring := setup(t)
		inside := FileHeads(filepath.Join(s.dir, "heads.json"))
		if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(inside)); err == nil || !strings.Contains(err.Error(), "inside the sink folder") {
			t.Fatalf("Checkpoint took a heads file inside the folder: %v", err)
		}
		if _, err := s.Verify(ctx, ring, WithCheckpointHeads(inside)); err == nil || !strings.Contains(err.Error(), "inside the sink folder") {
			t.Fatalf("Verify took a heads file inside the folder: %v", err)
		}
	})
}

// TestFileHeads: the heads file is written whole, never through a symlink, and
// a head only grows.
func TestFileHeads(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.json")
	chain := "events." + strings.Repeat("ab", 16)
	hashA, hashB := strings.Repeat("a", 128), strings.Repeat("b", 128)

	// A missing file is never an empty record: deleting it is what a
	// restarted series looks like (docs/decisions.md D23).
	if _, _, _, err := FileHeads(path).Head(ctx, chain); !errors.Is(err, ErrHeadsFileMissing) {
		t.Fatalf("a missing file through FileHeads: %v, want ErrHeadsFileMissing", err)
	}
	h := NewFileHeads(path)
	if _, _, ok, err := h.Head(ctx, chain); err != nil || ok {
		t.Fatalf("a record not yet started: ok=%v err=%v; want no head and no error", ok, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reading a head created the file")
	}
	if err := h.SetHead(ctx, chain, 1, hashA); err != nil {
		t.Fatal(err)
	}
	// A record is started once.
	if _, _, _, err := NewFileHeads(path).Head(ctx, chain); !errors.Is(err, ErrHeadsFileExists) {
		t.Fatalf("NewFileHeads over an existing file: %v, want ErrHeadsFileExists", err)
	}
	// A second handle reads what the first wrote, and the first sees its update.
	h2 := FileHeads(path)
	if err := h2.SetHead(ctx, chain, 2, hashB); err != nil {
		t.Fatal(err)
	}
	if n, hash, ok, err := h.Head(ctx, chain); err != nil || !ok || n != 2 || hash != hashB {
		t.Fatalf("Head = %d %q %v %v; want checkpoint 2", n, hash, ok, err)
	}
	// Nothing but the file is left in the folder: the temporary file was renamed.
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("the folder holds %d files, want only the heads file", len(ents))
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the heads file's mode is %v, want 0600 (%v)", fi.Mode().Perm(), err)
	}

	for name, set := range map[string]func() error{
		"a lower count":                  func() error { return h.SetHead(ctx, chain, 1, hashA) },
		"another hash at the same count": func() error { return h.SetHead(ctx, chain, 2, hashA) },
		"a count below 1":                func() error { return h.SetHead(ctx, chain, 0, hashA) },
		"a hash that is not one":         func() error { return h.SetHead(ctx, chain, 3, "abc") },
		"a chain id that is not one":     func() error { return h.SetHead(ctx, "../x", 3, hashA) },
	} {
		if err := set(); err == nil {
			t.Errorf("SetHead accepted %s", name)
		}
	}
	if n, hash, _, _ := h.Head(ctx, chain); n != 2 || hash != hashB {
		t.Fatalf("a refused SetHead changed the head: %d %q", n, hash)
	}

	t.Run("a symlink is refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		link := filepath.Join(dir, "heads.json")
		if err := os.WriteFile(target, []byte(`{"format":"`+headsFormat+`","heads":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlinks are not available here")
		}
		h := FileHeads(link)
		if _, _, _, err := h.Head(ctx, chain); err == nil {
			t.Fatal("Head read through a symlink")
		}
		if err := h.SetHead(ctx, chain, 1, hashA); err == nil {
			t.Fatal("SetHead wrote through a symlink")
		}
		if raw, _ := os.ReadFile(target); strings.Contains(string(raw), chain) {
			t.Fatal("the symlink's target was written")
		}
	})
	t.Run("a file that is not a heads file is refused", func(t *testing.T) {
		for name, body := range map[string]string{
			"other JSON":       `{"format":"something else","heads":{}}`,
			"an unknown field": `{"format":"` + headsFormat + `","heads":{},"extra":1}`,
			"a bad head":       `{"format":"` + headsFormat + `","heads":{"` + chain + `":{"checkpoints":0,"anchor_chain_hash":"` + hashA + `"}}}`,
			"not JSON":         `garbage`,
		} {
			path := filepath.Join(t.TempDir(), "heads.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := FileHeads(path).Head(ctx, chain); err == nil {
				t.Errorf("%s was read as a heads file", name)
			}
		}
	})
}

// The tests below PIN what the checks above do not close. Each passes while
// the hole is open, and says so; closing one means changing its test.

// TestNotClosed_APendingMarkerMakesTheSinkEraseAChain: the pending marker is a
// row in the index and takes no key. Written onto a live chain, it makes the
// operator's next erase call (for any subject) erase that chain with a real
// erasure entry, return its id, and so confirm it. With a forged erasure
// already on the chain, the call adopts that one.
func TestNotClosed_APendingMarkerMakesTheSinkEraseAChain(t *testing.T) {
	ctx := context.Background()
	for name, forge := range map[string]bool{"marker alone": false, "marker and a forged erasure": true} {
		t.Run(name, func(t *testing.T) {
			s, signer, ring := setup(t)
			victim := cid(t, s, "u-81")
			if forge {
				forgeErasure(t, s, victim)
			}
			subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := subj.forget("u-81", ""); err != nil { // forward row gone, reverse row pending
				t.Fatal(err)
			}
			subj.Close()
			// The operator erases someone else, and checkpoints what the call returned.
			res, err := s.EraseSubject(ctx, "u-90")
			if err != nil {
				t.Fatal(err)
			}
			all := append(append([]EraseResult(nil), res.Resumed...), res.Erased...)
			if _, err := s.Checkpoint(ctx, signer, nil, confirm(all...), UntrackedHeads()); err != nil {
				t.Fatal(err)
			}
			if cr := chainReport(t, mustVerify(t, s, ring), victim); cr.Index != IndexErased {
				t.Fatalf("the hole is closed, or moved: %+v. Update this test and the documents that describe it", cr)
			}
		})
	}
}

// TestNotClosed_ASourcePointedAtIdenticalContentIsADuplicate: the duplicate
// check compares content, so a source row pointing a future source at an entry
// that already holds the same bytes still suppresses the record. Events that
// repeat byte for byte are exposed; Verify reports it only once an entry has
// two source positions.
func TestNotClosed_ASourcePointedAtIdenticalContentIsADuplicate(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ping := Record{Class: testClass, Subject: "u-1", Content: []byte(`{"ping":true}`)}
	if _, err := s.Commit(ctx, []Record{ping}); err != nil { // committed without a source
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	// The sources file does not exist yet; the forger creates it.
	poisonSources(t, s, chain, entryIDs(t, s, chain)[0], 0, "Q:2")
	ping.Source = "Q:2"
	out, err := s.Commit(ctx, []Record{ping})
	if err != nil || pattern(out) != "D" {
		t.Fatalf("the hole is closed, or moved: %s, %v. Update this test and the documents that describe it", pattern(out), err)
	}
	// And Verify passes: the entry has one source position, as any entry may.
	_, ring := newSigner(t)
	mustVerify(t, s, ring)
}

// forgeErasureWithID is forgeErasure with the entry id chosen by the forger.
func forgeErasureWithID(t *testing.T, s *Sink, chain, id string) {
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
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure,
		Timestamp: now, IngestedAt: now, ContentHash: erasureHash(rec)}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()
	if err := sec.putAll(map[string]map[string]secret{chain: {id: {content: rec}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.eraseChain(chain, map[string][]byte{id: rec}); err != nil {
		t.Fatal(err)
	}
}

// TestForgedErasure_AConfirmedIDCopiedToAnotherChain: an erasure entry's id is
// in the evidence file for anyone to read. The operator erases u-81; the forger
// appends an erasure with that same id to u-82's chain and drops its index row.
// Confirming by id alone signed the victim chain. A confirmation names its
// chain.
func TestForgedErasure_AConfirmedIDCopiedToAnotherChain(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	victim := cid(t, s, "u-82")
	res, err := s.EraseSubject(ctx, "u-81")
	if err != nil {
		t.Fatal(err)
	}
	forgeErasureWithID(t, s, victim, res.Erased[0].ErasureEntryID)
	dropIndexRows(t, s, "u-82")

	done, err := s.Checkpoint(ctx, signer, nil, ConfirmErasures(res.Erased...), UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	if problemFor(done, victim) == "" {
		t.Fatalf("the victim chain was signed on another chain's confirmation: %+v", done)
	}
	if problemFor(done, res.Erased[0].Chain) != "" {
		t.Fatalf("the operator's own erasure was refused: %+v", done)
	}
	rep, err := s.Verify(ctx, ring)
	if err != nil {
		t.Fatal(err)
	}
	if got := chainReport(t, rep, victim).Index; got != IndexErasedUnanchored {
		t.Fatalf("the victim chain reads %q", got)
	}
}

// TestConfirmErasedChains: an honest erasure that missed its same-process
// checkpoint (erased without one, or the process died in between) could never
// be checkpointed afterwards on a sink that does not sign: every later
// Checkpoint refused the chain. The operator can now vouch for the chain by
// name, and only for a chain that is in exactly that state.
func TestConfirmErasedChains(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain, live := cid(t, s, "u-81"), cid(t, s, "u-82")
	if _, err := s.EraseSubject(ctx, "u-81"); err != nil {
		t.Fatal(err)
	}
	// The erase results are gone (another process, later). Nothing confirms it.
	if resumed, err := s.ResumeErasures(ctx); err != nil || len(resumed) != 0 {
		t.Fatalf("ResumeErasures = %+v, %v; want nothing left to return", resumed, err)
	}
	done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	if p := problemFor(done, chain); !strings.Contains(p, "--confirm-erased-chain") {
		t.Fatalf("the refusal does not name the way out: %q", p)
	}
	// Vouching for a chain that is not an unconfirmed erasure confirms nothing,
	// and says so.
	done, err = s.Checkpoint(ctx, signer, nil, ConfirmErasedChains(live), UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	if p := problemFor(done, live); !strings.Contains(p, "does not end with an erasure") {
		t.Fatalf("vouching for a live chain: %+v", done)
	}
	if problemFor(done, chain) == "" {
		t.Fatalf("vouching for one chain confirmed another: %+v", done)
	}
	if _, err := s.Checkpoint(ctx, signer, nil, ConfirmErasedChains("../x"), UntrackedHeads()); err == nil {
		t.Fatal("ConfirmErasedChains took something that is not a chain id")
	}
	// Vouched for: signed, once, and then quiet.
	done, err = s.Checkpoint(ctx, signer, nil, ConfirmErasedChains(chain), UntrackedHeads())
	if err != nil || len(done) != 1 || done[0].Chain != chain || done[0].Problem != "" {
		t.Fatalf("Checkpoint = %+v, %v; want the vouched chain signed", done, err)
	}
	if cr := chainReport(t, mustVerify(t, s, ring), chain); cr.Index != IndexErased {
		t.Fatalf("after vouching: %+v", cr)
	}
	if done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads()); err != nil || len(done) != 0 {
		t.Fatalf("a routine run afterwards = %+v, %v; want nothing to report", done, err)
	}

	t.Run("a vouched chain must still verify", func(t *testing.T) {
		s, signer, _ := setup(t)
		chain := cid(t, s, "u-81")
		ids := entryIDs(t, s, chain)
		if _, err := s.EraseSubject(ctx, "u-81"); err != nil {
			t.Fatal(err)
		}
		// Content put back before the erasure: the erasure is not complete.
		if err := writeContent(s, chain, ids[0], []byte("still here")); err != nil {
			t.Fatal(err)
		}
		done, err := s.Checkpoint(ctx, signer, nil, ConfirmErasedChains(chain), UntrackedHeads())
		if err != nil || !strings.Contains(problemFor(done, chain), "does not verify") {
			t.Fatalf("Checkpoint = %+v, %v; want the chain refused", done, err)
		}
	})
}

// TestForgedErasure_APlainEraseDoesNotVouchForIt: a forged erasure on a chain
// whose index row is left alone, met by an ordinary EraseSubject of that
// subject rather than by resume. The call found an erasure entry already
// there, kept it, and returned its id unmarked; `erase --key` then signed it.
// It is Relinked whichever call meets it, and ConfirmErasures ignores it.
func TestForgedErasure_APlainEraseDoesNotVouchForIt(t *testing.T) {
	ctx := context.Background()
	s, signer, _ := setup(t)
	chain := cid(t, s, "u-81")
	forged := forgeErasure(t, s, chain)
	res, err := s.EraseSubject(ctx, "u-81")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Erased) != 1 || res.Erased[0].ErasureEntryID != forged || !res.Erased[0].Relinked {
		t.Fatalf("EraseSubject = %+v; want the adopted erasure marked Relinked", res.Erased)
	}
	done, err := s.Checkpoint(ctx, signer, nil, ConfirmErasures(res.Erased...), UntrackedHeads())
	if err != nil || problemFor(done, chain) == "" {
		t.Fatalf("Checkpoint = %+v, %v; want the adopted erasure refused", done, err)
	}
	// An erasure the call appended itself is not marked.
	if res, err := s.EraseSubject(ctx, "u-82"); err != nil || res.Erased[0].Relinked {
		t.Fatalf("EraseSubject = %+v, %v", res, err)
	}
}

// TestSourcePoison_ARowThatIsNotAPosition: a crafted row with sequence -1 (a
// range read takes a negative start as "from the first entry") and the first
// entry's id made a record with that entry's content read as a duplicate. Nor
// is an id that is no entry id a position.
func TestSourcePoison_ARowThatIsNotAPosition(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := Record{Class: testClass, Subject: "u-1", Content: []byte(`{"ping":true}`)}
	if _, err := s.Commit(ctx, []Record{first}); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-1")
	poisonSources(t, s, chain, entryIDs(t, s, chain)[0], -1, "Q:1")
	first.Source = "Q:1"
	if out, err := s.Commit(ctx, []Record{first}); err != nil || pattern(out) != "N" {
		t.Fatalf("Commit = %s, %v; want the record committed, not taken as a duplicate", pattern(out), err)
	}
	if n := len(entryIDs(t, s, chain)); n != 2 {
		t.Fatalf("the chain holds %d entries, want 2", n)
	}
}

// TestSourceConflict_SaysWhy: the three refusals are told apart in the message
// (which still names no source, content or chain).
func TestSourceConflict_SaysWhy(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	chain := cid(t, s, "u-81")
	ids := entryIDs(t, s, chain)
	poisonSources(t, s, chain, ids[0], 0, "Q:different")
	poisonSources(t, s, chain, ids[1], 1, "Q:missing")
	poisonSources(t, s, chain, ids[2], 2, "Q:oversized")
	if err := withSecrets(s, func(tx *bolt.Tx) error {
		if err := tx.Bucket(contentBucket).Delete(rowKey(chain, ids[1])); err != nil {
			return err
		}
		return tx.Bucket(contentBucket).Put(rowKey(chain, ids[2]), make([]byte, MaxContentBytes+1))
	}); err != nil {
		t.Fatal(err)
	}
	for source, want := range map[string]string{
		"Q:different": "different content",
		"Q:missing":   "is missing",
		"Q:oversized": "is missing",
	} {
		rec := events("u-81", 1)
		rec[0].Source = source
		rec[0].Content = []byte(`{"new":true}`)
		_, err := s.Commit(ctx, rec)
		if !errors.Is(err, ErrSourceConflict) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want ErrSourceConflict saying %q", source, err, want)
		}
	}
}

// TestForgedErasure_UnsignedInASigningSinkIsAProblem is review round 2's
// TestZZ_ForgedErasureLaundered against a sink that signs its records: the
// sink signs every erasure it makes, so one without a signature is reported
// (erasure-unsigned), with and without record trust, while the sink's own
// signed erasure of another subject is not.
func TestForgedErasure_UnsignedInASigningSinkIsAProblem(t *testing.T) {
	ctx := context.Background()
	s, ring, rs := signedSink(t)
	forged := cid(t, s, "u-1")
	real := cid(t, s, "u-2")
	forgeErasure(t, s, forged)
	dropIndexRows(t, s, "u-1")
	if _, err := s.EraseSubject(ctx, "u-2"); err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string][]VerifyOption{
		"without record trust": nil,
		"with record trust":    {WithRecordTrust(recordRing(t, rs))},
	} {
		r := verifyWith(t, s, ring, opts...)
		if cr := chainReport(t, r, forged); !hasProblemWith(cr, "erasure-unsigned") {
			t.Errorf("%s: the forged erasure is not reported: %+v", name, cr)
		}
		if cr := chainReport(t, r, real); hasProblemWith(cr, "erasure-unsigned") {
			t.Errorf("%s: the sink's own signed erasure was reported: %+v", name, cr)
		}
	}
}
