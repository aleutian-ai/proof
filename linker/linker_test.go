// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/verify"
)

const chainID = "chain-under-test"

// backends runs fn against every store implementation.
//
// The linker must behave identically on both: memory is the fast path used by
// most tests, bolt is the default a real user gets, and a linker bug that only
// appears under a real transaction is exactly the bug worth catching.
func backends(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, memory.New()) })
	t.Run("bolt", func(t *testing.T) {
		s, err := bolt.Open(filepath.Join(t.TempDir(), "chain.db"))
		if err != nil {
			t.Fatalf("open bolt store: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		fn(t, s)
	})
}

// input builds a valid Input whose content hash is distinct per id.
func input(id string, arrivalOffset time.Duration) linker.Input {
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	return linker.Input{
		EntryID:     id,
		EntryType:   "capture.request.v3",
		Timestamp:   base.Add(arrivalOffset),
		ContentHash: strings.Repeat(fmt.Sprintf("%02x", len(id)%256), 64),
		IngestedAt:  base.Add(arrivalOffset),
	}
}

// exported reads the whole chain back in the portable form verify.Chain wants.
func exported(t *testing.T, s store.Store) []verify.Entry {
	t.Helper()
	rows, err := s.Range(context.Background(), chainID, 0, 1<<40, 0)
	if err != nil {
		t.Fatalf("range chain: %v", err)
	}
	out := make([]verify.Entry, len(rows))
	for i, r := range rows {
		out[i] = verify.Entry{
			EntryID:       r.EntryID,
			EntryType:     r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion,
			GlobalSeq:     r.GlobalSeq,
			ContentHash:   r.ContentHash,
			ChainHash:     r.ChainHash,
		}
		// v2 binds these; v3 does not, and a v3 entry carrying them is rejected.
		if chainformat.NormalizeFormatVersion(r.FormatVersion) == chainformat.FormatV2 {
			out[i].RunID = r.RunID
			out[i].SequenceNum = r.SequenceNum
		}
	}
	return out
}

// TestAppendProducesAVerifiableChain is the round-trip acceptance test: entries
// linked by this package must verify intact through the independent verifier.
func TestAppendProducesAVerifiableChain(t *testing.T) {
	backends(t, func(t *testing.T, s store.Store) {
		l, err := linker.New(s)
		if err != nil {
			t.Fatalf("new linker: %v", err)
		}
		var batch []linker.Input
		for i := 0; i < 8; i++ {
			batch = append(batch, input(fmt.Sprintf("e%02d", i), time.Duration(i)*time.Second))
		}
		res, err := l.Append(context.Background(), chainID, batch)
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if res.Appended != 8 {
			t.Errorf("Appended = %d, want 8", res.Appended)
		}
		if res.FirstSeq != 0 || res.LastSeq != 7 {
			t.Errorf("seq range = [%d,%d], want [0,7]", res.FirstSeq, res.LastSeq)
		}

		got, err := verify.Chain(exported(t, s), verify.Options{})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got.Verdict != verify.VerdictIntact {
			t.Fatalf("verdict = %q, first break at %d, breaks %+v",
				got.Verdict, got.FirstBreak, got.Breaks)
		}
		if got.EntriesVerified != 8 {
			t.Errorf("EntriesVerified = %d, want 8", got.EntriesVerified)
		}
	})
}

// TestAppendAssignsContiguousSequenceAndLinkage pins the two things the linker
// exists to do, against the stored rows rather than the returned summary.
func TestAppendAssignsContiguousSequenceAndLinkage(t *testing.T) {
	backends(t, func(t *testing.T, s store.Store) {
		l, _ := linker.New(s)
		var batch []linker.Input
		for i := 0; i < 5; i++ {
			batch = append(batch, input(fmt.Sprintf("e%02d", i), time.Duration(i)*time.Second))
		}
		if _, err := l.Append(context.Background(), chainID, batch); err != nil {
			t.Fatalf("append: %v", err)
		}

		rows, err := s.Range(context.Background(), chainID, 0, 1<<40, 0)
		if err != nil {
			t.Fatalf("range: %v", err)
		}
		if len(rows) != 5 {
			t.Fatalf("stored %d rows, want 5", len(rows))
		}
		for i, r := range rows {
			if r.GlobalSeq != int64(i) {
				t.Errorf("row %d: GlobalSeq = %d, want %d", i, r.GlobalSeq, i)
			}
			// v3 does not have a batch-local sequence number; GlobalSeq above is
			// the position, and it IS bound into the hash.
			if r.SequenceNum != 0 {
				t.Errorf("row %d: SequenceNum = %d, want 0 under v3", i, r.SequenceNum)
			}
			if i == 0 {
				if r.PreviousHash != "" {
					t.Errorf("genesis PreviousHash = %q, want empty", r.PreviousHash)
				}
				continue
			}
			if r.PreviousHash != rows[i-1].ChainHash {
				t.Errorf("row %d: PreviousHash does not link to the prior ChainHash", i)
			}
		}
	})
}

// TestTamperedEntryBreaksAtThatIndex — the property the whole project exists for.
// FirstBreak must name the altered row, not merely report that something is wrong.
func TestTamperedEntryBreaksAtThatIndex(t *testing.T) {
	backends(t, func(t *testing.T, s store.Store) {
		l, _ := linker.New(s)
		var batch []linker.Input
		for i := 0; i < 6; i++ {
			batch = append(batch, input(fmt.Sprintf("e%02d", i), time.Duration(i)*time.Second))
		}
		if _, err := l.Append(context.Background(), chainID, batch); err != nil {
			t.Fatalf("append: %v", err)
		}

		rows := exported(t, s)
		const tamperAt = 3
		rows[tamperAt].ContentHash = strings.Repeat("ab", 64)

		got, err := verify.Chain(rows, verify.Options{})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got.Verdict == verify.VerdictIntact {
			t.Fatal("tampered chain verified as intact")
		}
		if got.FirstBreak != tamperAt {
			t.Errorf("FirstBreak = %d, want %d (breaks: %+v)", got.FirstBreak, tamperAt, got.Breaks)
		}
		if len(got.Breaks) == 0 || got.Breaks[0].Type != verify.BreakHashMismatch {
			t.Errorf("first break type = %+v, want %q", got.Breaks, verify.BreakHashMismatch)
		}
	})
}

// TestRestartContinuesLinkage covers the case a durable store exists for: close
// the process, reopen, append again, and the chain must be continuous across the
// seam.
func TestRestartContinuesLinkage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.db")

	s1, err := bolt.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	l1, _ := linker.New(s1)
	res1, err := l1.Append(context.Background(), chainID,
		[]linker.Input{input("e00", 0), input("e01", time.Second)})
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := bolt.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	l2, _ := linker.New(s2)
	res2, err := l2.Append(context.Background(), chainID,
		[]linker.Input{input("e02", 2*time.Second)})
	if err != nil {
		t.Fatalf("second append: %v", err)
	}

	if res2.FirstSeq != res1.LastSeq+1 {
		t.Errorf("post-restart FirstSeq = %d, want %d", res2.FirstSeq, res1.LastSeq+1)
	}
	// v3 mints no run ids, so there is nothing here to be unique. The v2
	// uniqueness property is asserted by TestV2RunIDsAreUnique.
	if res1.RunID != "" || res2.RunID != "" {
		t.Errorf("a v3 append reported run ids %q and %q", res1.RunID, res2.RunID)
	}

	rows, err := s2.Range(context.Background(), chainID, 0, 1<<40, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("stored %d rows across restart, want 3", len(rows))
	}
	if rows[2].PreviousHash != rows[1].ChainHash {
		t.Error("linkage broken across the restart seam")
	}

	got, err := verify.Chain(exported(t, s2), verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Verdict != verify.VerdictIntact {
		t.Errorf("verdict after restart = %q, breaks %+v", got.Verdict, got.Breaks)
	}
}

// TestBatchingChangesHashes pins the sharp edge documented in the package
// comment. This is not a bug being tolerated — it is a format property, and if it
// ever stops being true the format has changed and every published verifier is
// affected. Asserting it makes that change loud.
func TestBatchingChangesHashes_V2(t *testing.T) {
	a, b := input("e00", 0), input("e01", time.Second)

	one := memory.New()
	lOne, _ := linker.New(one, linker.WithFormatV2())
	if _, err := lOne.Append(context.Background(), chainID, []linker.Input{a, b}); err != nil {
		t.Fatalf("single batch append: %v", err)
	}

	two := memory.New()
	lTwo, _ := linker.New(two, linker.WithFormatV2())
	if _, err := lTwo.Append(context.Background(), chainID, []linker.Input{a}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := lTwo.Append(context.Background(), chainID, []linker.Input{b}); err != nil {
		t.Fatalf("second append: %v", err)
	}

	rowsOne, rowsTwo := exported(t, one), exported(t, two)
	if len(rowsOne) != 2 || len(rowsTwo) != 2 {
		t.Fatalf("row counts %d and %d, want 2 and 2", len(rowsOne), len(rowsTwo))
	}
	if rowsOne[1].ChainHash == rowsTwo[1].ChainHash {
		t.Error("appending [A,B] together and A then B produced the same hash for B; " +
			"run_id and the batch-local sequence number are supposed to be hash inputs")
	}

	// Both chains must nonetheless verify: different is not broken.
	for name, rows := range map[string][]verify.Entry{"one-batch": rowsOne, "two-batch": rowsTwo} {
		got, err := verify.Chain(rows, verify.Options{})
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if got.Verdict != verify.VerdictIntact {
			t.Errorf("%s: verdict = %q, breaks %+v", name, got.Verdict, got.Breaks)
		}
	}
}

// TestBatchingDoesNotChangeHashes_V3 is the property v3 exists for, and the
// exact opposite of the v2 behaviour asserted above.
//
// In v2 a chain depends on how its entries were grouped into Append calls,
// because run_id and a batch-local sequence number are hash inputs. That makes
// a chain impossible to reconstruct from its entries: the batch boundaries are
// part of the artefact and are recorded nowhere. v3 binds global_seq instead,
// so the hashes depend only on WHAT was appended and in WHAT order.
func TestBatchingDoesNotChangeHashes_V3(t *testing.T) {
	a, b := input("e00", 0), input("e01", time.Second)

	one := memory.New()
	lOne, _ := linker.New(one) // v3 is the default
	if _, err := lOne.Append(context.Background(), chainID, []linker.Input{a, b}); err != nil {
		t.Fatalf("single batch append: %v", err)
	}

	two := memory.New()
	lTwo, _ := linker.New(two)
	if _, err := lTwo.Append(context.Background(), chainID, []linker.Input{a}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := lTwo.Append(context.Background(), chainID, []linker.Input{b}); err != nil {
		t.Fatalf("second append: %v", err)
	}

	rowsOne, rowsTwo := exported(t, one), exported(t, two)
	if len(rowsOne) != 2 || len(rowsTwo) != 2 {
		t.Fatalf("row counts %d and %d, want 2 and 2", len(rowsOne), len(rowsTwo))
	}
	for i := range rowsOne {
		if rowsOne[i].ChainHash != rowsTwo[i].ChainHash {
			t.Errorf("entry %d: [A,B] in one batch hashed differently from A then B\n one %s\n two %s",
				i, rowsOne[i].ChainHash, rowsTwo[i].ChainHash)
		}
	}

	for name, rows := range map[string][]verify.Entry{"one-batch": rowsOne, "two-batch": rowsTwo} {
		got, err := verify.Chain(rows, verify.Options{})
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if got.Verdict != verify.VerdictIntact {
			t.Errorf("%s: verdict = %q, breaks %+v", name, got.Verdict, got.Breaks)
		}
	}
}

// TestV3EntriesCarryNoRunID: v3 does not have run ids, and an entry that
// carries one anyway would look as though the value were attested.
func TestV3EntriesCarryNoRunID(t *testing.T) {
	s := memory.New()
	l, _ := linker.New(s)
	res, err := l.Append(context.Background(), chainID, []linker.Input{input("e00", 0), input("e01", time.Second)})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if res.RunID != "" {
		t.Errorf("a v3 append reported run id %q", res.RunID)
	}

	rows, err := s.Range(context.Background(), chainID, 0, 1<<40, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	for i, r := range rows {
		if r.FormatVersion != chainformat.FormatV3 {
			t.Errorf("entry %d: format version %d, want %d", i, r.FormatVersion, chainformat.FormatV3)
		}
		if r.RunID != "" {
			t.Errorf("entry %d carries run id %q", i, r.RunID)
		}
		if r.SequenceNum != 0 {
			t.Errorf("entry %d carries sequence_num %d", i, r.SequenceNum)
		}
		if r.GlobalSeq != int64(i) {
			t.Errorf("entry %d has global_seq %d", i, r.GlobalSeq)
		}
	}
}

// TestV3EntryWithRunIDIsRejected: the fields are not bound into a v3 hash, so a
// verifier must not let one pass as though they were.
func TestV3EntryWithRunIDIsRejected(t *testing.T) {
	s := memory.New()
	l, _ := linker.New(s)
	if _, err := l.Append(context.Background(), chainID, []linker.Input{input("e00", 0)}); err != nil {
		t.Fatalf("append: %v", err)
	}
	rows := exported(t, s)

	for _, tc := range []struct {
		name  string
		mutar func(*verify.Entry)
	}{
		{"run id", func(e *verify.Entry) { e.RunID = "smuggled" }},
		{"sequence num", func(e *verify.Entry) { e.SequenceNum = 7 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]verify.Entry(nil), rows...)
			tc.mutar(&tampered[0])

			got, err := verify.Chain(tampered, verify.Options{})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.Verdict != verify.VerdictBroken {
				t.Fatalf("verdict = %q, want BROKEN", got.Verdict)
			}
			if got.Breaks[0].Type != verify.BreakFormatFieldMisuse {
				t.Errorf("break type = %q, want %q", got.Breaks[0].Type, verify.BreakFormatFieldMisuse)
			}
		})
	}
}

// TestMixedFormatChainVerifies: a store can hold v2 entries followed by v3
// ones, because a chain that was being written before the format changed does
// not stop and restart. Each entry is checked against ITS OWN preimage.
func TestMixedFormatChainVerifies(t *testing.T) {
	s := memory.New()

	lV2, _ := linker.New(s, linker.WithFormatV2())
	if _, err := lV2.Append(context.Background(), chainID, []linker.Input{input("e00", 0), input("e01", time.Second)}); err != nil {
		t.Fatalf("v2 append: %v", err)
	}
	lV3, _ := linker.New(s)
	if _, err := lV3.Append(context.Background(), chainID, []linker.Input{input("e02", 2*time.Second)}); err != nil {
		t.Fatalf("v3 append: %v", err)
	}

	rows := exported(t, s)
	if len(rows) != 3 {
		t.Fatalf("got %d entries, want 3", len(rows))
	}
	if rows[0].RunID == "" {
		t.Error("the v2 entries lost their run id")
	}
	if rows[2].FormatVersion != chainformat.FormatV3 {
		t.Errorf("the third entry is format %d, want v3", rows[2].FormatVersion)
	}

	got, err := verify.Chain(rows, verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Verdict != verify.VerdictIntact {
		t.Errorf("a v2-then-v3 chain did not verify: %q, breaks %+v", got.Verdict, got.Breaks)
	}
	if got.EntriesVerified != 3 {
		t.Errorf("verified %d entries, want 3", got.EntriesVerified)
	}
}

// TestUnknownFormatIsReportedNotGuessed: a build that meets a format it does
// not implement must say so. Guessing a preimage would produce a confident
// wrong answer about whether the chain is intact.
func TestUnknownFormatIsReportedNotGuessed(t *testing.T) {
	s := memory.New()
	l, _ := linker.New(s)
	if _, err := l.Append(context.Background(), chainID, []linker.Input{input("e00", 0)}); err != nil {
		t.Fatalf("append: %v", err)
	}
	rows := exported(t, s)
	rows[0].FormatVersion = 99

	got, err := verify.Chain(rows, verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Verdict != verify.VerdictBroken {
		t.Fatalf("verdict = %q, want BROKEN", got.Verdict)
	}
	if got.Breaks[0].Type != verify.BreakUnknownFormat {
		t.Errorf("break type = %q, want %q", got.Breaks[0].Type, verify.BreakUnknownFormat)
	}
}

// TestConcurrentAppendsDoNotForkTheChain drives real goroutines at one chain.
// Whatever gets through must leave a contiguous, verifiable chain; the lease
// makes a fork impossible rather than unlikely.
func TestConcurrentAppendsDoNotForkTheChain(t *testing.T) {
	backends(t, func(t *testing.T, s store.Store) {
		l, _ := linker.New(s)

		const writers = 8
		var wg sync.WaitGroup
		var mu sync.Mutex
		var succeeded, busy int

		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := l.Append(context.Background(), chainID,
					[]linker.Input{input(fmt.Sprintf("e%02d", i), time.Duration(i)*time.Second)})
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					succeeded++
				case errors.Is(err, linker.ErrChainBusy):
					busy++
				default:
					t.Errorf("writer %d: unexpected error: %v", i, err)
				}
			}(i)
		}
		wg.Wait()

		if succeeded == 0 {
			t.Fatal("every writer lost the lease; no progress was made")
		}
		if succeeded+busy != writers {
			t.Errorf("accounted for %d of %d writers", succeeded+busy, writers)
		}

		rows, err := s.Range(context.Background(), chainID, 0, 1<<40, 0)
		if err != nil {
			t.Fatalf("range: %v", err)
		}
		if len(rows) != succeeded {
			t.Errorf("stored %d rows for %d successful appends", len(rows), succeeded)
		}
		for i, r := range rows {
			if r.GlobalSeq != int64(i) {
				t.Errorf("row %d: GlobalSeq = %d — sequence is not contiguous", i, r.GlobalSeq)
			}
		}
		got, err := verify.Chain(exported(t, s), verify.Options{})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got.Verdict != verify.VerdictIntact {
			t.Errorf("chain forked under concurrency: verdict %q, breaks %+v",
				got.Verdict, got.Breaks)
		}
	})
}

// TestTombstoneEntriesLink covers the rule that three published SDKs got wrong:
// a tombstone is a normal chain member, not a break.
func TestTombstoneEntriesLink(t *testing.T) {
	tombHash, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("generate tombstone content hash: %v", err)
	}
	s := memory.New()
	l, _ := linker.New(s)

	batch := []linker.Input{
		input("e00", 0),
		{
			EntryID:     chainformat.TombstoneEntryIDPrefix + "e01",
			EntryType:   chainformat.TombstoneEntryType,
			Timestamp:   time.Date(2026, 9, 14, 12, 0, 1, 0, time.UTC),
			ContentHash: tombHash,
			IngestedAt:  time.Date(2026, 9, 14, 12, 0, 1, 0, time.UTC),
		},
		input("e02", 2*time.Second),
	}
	if _, err := l.Append(context.Background(), chainID, batch); err != nil {
		t.Fatalf("append with tombstone: %v", err)
	}

	got, err := verify.Chain(exported(t, s), verify.Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Verdict != verify.VerdictIntact {
		t.Fatalf("tombstone reported as a break: verdict %q, breaks %+v", got.Verdict, got.Breaks)
	}
	if got.TombstonesFound != 1 {
		t.Errorf("TombstonesFound = %d, want 1", got.TombstonesFound)
	}
}

// TestArrivalOrderWinsOverEventTime is the regression guard for the defect that
// produced the rule in the first place: a backdated entry must NOT be able to
// place itself earlier in the chain.
//
// The two clocks deliberately disagree here. e00 arrives first but carries a
// LATER event timestamp; e01 arrives second carrying an EARLIER one. Ordering by
// event time would swap them, and a caller that controls its own timestamp could
// then choose its position in the chain.
func TestArrivalOrderWinsOverEventTime(t *testing.T) {
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	first := input("e00", 0)
	first.IngestedAt = base                   // arrived first
	first.Timestamp = base.Add(1 * time.Hour) // claims to be later

	second := input("e01", time.Second)
	second.IngestedAt = base.Add(1 * time.Second) // arrived second
	second.Timestamp = base.Add(-1 * time.Hour)   // claims to be earlier (backdated)

	s := memory.New()
	l, _ := linker.New(s)
	if _, err := l.Append(context.Background(), chainID, []linker.Input{first, second}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rows, err := s.Range(context.Background(), chainID, 0, 1<<40, 0)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("stored %d rows, want 2", len(rows))
	}
	if rows[0].EntryID != "e00" || rows[1].EntryID != "e01" {
		t.Fatalf("order = [%s, %s], want [e00, e01] — sorted by event time, not arrival",
			rows[0].EntryID, rows[1].EntryID)
	}
}

// TestAppendIsOrderStableRegardlessOfCallerOrder: the caller's slice order must
// not influence the chain. Arrival order is the authority, so a shuffled input
// must produce the identical chain.
func TestAppendIsOrderStableRegardlessOfCallerOrder(t *testing.T) {
	mk := func(order []int) []verify.Entry {
		s := memory.New()
		fixedRun := func() (string, error) { return "fixed-run-id-for-comparison", nil }
		l, _ := linker.New(s, linker.WithRunIDFunc(fixedRun))
		var batch []linker.Input
		for _, i := range order {
			batch = append(batch, input(fmt.Sprintf("e%02d", i), time.Duration(i)*time.Second))
		}
		if _, err := l.Append(context.Background(), chainID, batch); err != nil {
			t.Fatalf("append: %v", err)
		}
		return exported(t, s)
	}

	ascending := mk([]int{0, 1, 2, 3})
	shuffled := mk([]int{2, 0, 3, 1})
	if len(ascending) != len(shuffled) {
		t.Fatalf("row counts differ: %d vs %d", len(ascending), len(shuffled))
	}
	for i := range ascending {
		if ascending[i] != shuffled[i] {
			t.Errorf("row %d differs between caller orderings:\n asc = %+v\n shuf= %+v",
				i, ascending[i], shuffled[i])
		}
	}
}

// TestInputSliceIsNotMutated — Append sorts a copy. A caller still holding its
// batch for its own bookkeeping must not find it reordered underneath.
func TestInputSliceIsNotMutated(t *testing.T) {
	batch := []linker.Input{
		input("e02", 2*time.Second),
		input("e00", 0),
		input("e01", time.Second),
	}
	before := []string{batch[0].EntryID, batch[1].EntryID, batch[2].EntryID}

	l, _ := linker.New(memory.New())
	if _, err := l.Append(context.Background(), chainID, batch); err != nil {
		t.Fatalf("append: %v", err)
	}
	for i := range batch {
		if batch[i].EntryID != before[i] {
			t.Errorf("caller slice reordered at %d: %q became %q", i, before[i], batch[i].EntryID)
		}
	}
}

// TestRejectsUnorderableBatches: the invariants that make sequence assignment
// well-defined at all.
func TestRejectsUnorderableBatches(t *testing.T) {
	good := input("e00", 0)
	zeroArrival := input("e01", time.Second)
	zeroArrival.IngestedAt = time.Time{}

	tests := []struct {
		name    string
		batch   []linker.Input
		wantErr string
	}{
		{"empty batch", nil, "must not be empty"},
		{"zero ingested_at", []linker.Input{good, zeroArrival}, "zero ingested_at"},
		{"duplicate entry id", []linker.Input{good, input("e00", time.Second)}, "duplicate entry id"},
		{"empty entry id", []linker.Input{good, input("", time.Second)}, "empty entry id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			l, _ := linker.New(s)
			_, err := l.Append(context.Background(), chainID, tc.batch)
			if err == nil {
				t.Fatalf("append accepted an unorderable batch")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
			rows, rangeErr := s.Range(context.Background(), chainID, 0, 1<<40, 0)
			if rangeErr == nil && len(rows) != 0 {
				t.Errorf("a rejected batch wrote %d rows", len(rows))
			}
		})
	}
}

// TestV2RunIDsAreUnique keeps the v2 property that TestRestartContinuesLinkage
// used to carry: a run id is a v2 hash input, and a repeated one would make two
// different batches hash identically.
func TestV2RunIDsAreUnique(t *testing.T) {
	s := memory.New()
	l, _ := linker.New(s, linker.WithFormatV2())

	first, err := l.Append(context.Background(), chainID, []linker.Input{input("e00", 0)})
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	second, err := l.Append(context.Background(), chainID, []linker.Input{input("e01", time.Second)})
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if first.RunID == "" || second.RunID == "" {
		t.Fatal("a v2 append reported no run id")
	}
	if first.RunID == second.RunID {
		t.Error("two v2 Append calls produced the same run id")
	}
}
