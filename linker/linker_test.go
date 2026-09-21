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
			EntryID:     r.EntryID,
			EntryType:   r.EntryType,
			Timestamp:   r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			RunID:       r.RunID,
			SequenceNum: r.SequenceNum,
			GlobalSeq:   r.GlobalSeq,
			ContentHash: r.ContentHash,
			ChainHash:   r.ChainHash,
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
			if r.SequenceNum != int64(i) {
				t.Errorf("row %d: SequenceNum = %d, want %d", i, r.SequenceNum, i)
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
	if res2.RunID == res1.RunID {
		t.Error("two Append calls produced the same run id")
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
func TestBatchingChangesHashes(t *testing.T) {
	a, b := input("e00", 0), input("e01", time.Second)

	one := memory.New()
	lOne, _ := linker.New(one)
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
