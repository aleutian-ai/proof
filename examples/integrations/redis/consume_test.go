// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/sink"
)

// ---------------------------------------------------------------------------
// An in-memory consumer group with Redis's pending-list semantics:
// ">" delivers new entries and marks them pending on the reader; "0" returns
// the reader's own pending entries; XAUTOCLAIM moves idle ones; XACK removes
// them from the pending list only. Nothing is ever redelivered by itself.
// ---------------------------------------------------------------------------

type pend struct {
	owner string
	since time.Time
}

type fakeGroup struct {
	entries []entry
	next    int // index of the first never-delivered entry
	pending map[string]*pend
	now     time.Time
	events  []string
	ackErr  error
	deleted map[string]bool // XDEL'd from the stream; may still be pending
	onRead  func()          // called on every readGroup, e.g. to cancel or to change state
}

func newGroup(es ...entry) *fakeGroup {
	return &fakeGroup{entries: es, pending: map[string]*pend{}, now: time.Unix(1_000_000, 0),
		deleted: map[string]bool{}}
}

// as is the group seen by one named consumer.
type as struct {
	*fakeGroup
	name string
}

func (g as) readGroup(ctx context.Context, id string, count int, _ time.Duration) ([]entry, error) {
	if g.onRead != nil {
		g.onRead()
	}
	if err := ctx.Err(); err != nil {
		return nil, err // like a blocking read interrupted by Ctrl-C
	}
	var out []entry
	switch id {
	case "0":
		for _, e := range g.entries {
			if p := g.pending[e.id]; p != nil && p.owner == g.name && len(out) < count {
				if g.deleted[e.id] {
					e = entry{id: e.id, gone: true} // as Redis returns it: an id with no fields
				}
				out = append(out, e)
			}
		}
	case ">":
		for g.next < len(g.entries) && len(out) < count {
			e := g.entries[g.next]
			g.next++
			if g.deleted[e.id] {
				continue // ">" skips entries no longer in the stream
			}
			g.pending[e.id] = &pend{owner: g.name, since: g.now}
			out = append(out, e)
		}
	}
	return out, nil
}

// autoClaim pages like Redis: at most count entries per call, from the cursor
// (an index into entries here), returning the next cursor or "0-0" at the end.
// Deleted entries are dropped from the pending list and reported separately.
func (g as) autoClaim(_ context.Context, minIdle time.Duration, start string, count int) ([]entry, string, []string, error) {
	i := 0
	if start != "0-0" {
		fmt.Sscanf(start, "%d", &i)
	}
	var out []entry
	var deleted []string
	for ; i < len(g.entries); i++ {
		if len(out) == count {
			return out, fmt.Sprint(i), deleted, nil
		}
		e := g.entries[i]
		p := g.pending[e.id]
		if p == nil || g.now.Sub(p.since) < minIdle {
			continue
		}
		if g.deleted[e.id] {
			delete(g.pending, e.id)
			deleted = append(deleted, e.id)
			continue
		}
		p.owner, p.since = g.name, g.now
		out = append(out, e)
	}
	return out, "0-0", deleted, nil
}

func (g as) ack(_ context.Context, ids ...string) error {
	if g.ackErr != nil {
		return g.ackErr
	}
	for _, id := range ids {
		delete(g.pending, id)
	}
	g.events = append(g.events, "ack "+strings.Join(ids, ","))
	return nil
}

// loggingSink records each Commit on the group's event log, and can fail one chain.
type loggingSink struct {
	inner *sink.Sink
	g     *fakeGroup
	fail  string
}

func (s *loggingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	s.g.events = append(s.g.events, "commit")
	if s.fail == "" {
		return s.inner.Commit(ctx, recs)
	}
	var ok []sink.Record
	var at []int // at[j] is the index in recs of ok[j]
	for i, r := range recs {
		if r.Subject != s.fail {
			ok = append(ok, r)
			at = append(at, i)
		}
	}
	// One outcome per record, as the real sink returns: the failed subject's
	// records are not committed.
	out := make([]sink.Outcome, len(recs))
	if len(ok) > 0 {
		done, err := s.inner.Commit(ctx, ok)
		for j, o := range done {
			out[at[j]] = o
		}
		if err != nil {
			return out, err
		}
	}
	return out, errors.New("injected failure on " + s.fail)
}

func ev(id, key string) entry {
	return entry{id: id, key: key, data: []byte(fmt.Sprintf(`{"user":%q,"id":%q}`, key, id))}
}

func sixEvents() []entry {
	return []entry{ev("1-0", "u-81"), ev("2-0", "u-82"), ev("3-0", "u-81"),
		ev("4-0", "u-90"), ev("5-0", "u-82"), ev("6-0", "u-81")}
}

func newSink(t *testing.T) *sink.Sink {
	t.Helper()
	s, err := sink.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func opts() options {
	return options{stream: "evidence", class: "events", sourcePrefix: "evidence@t1", batch: 100, claimIdle: time.Minute}
}

// ---------------------------------------------------------------------------

func TestAckAfterCommit(t *testing.T) {
	g := newGroup(sixEvents()...)
	dst := &loggingSink{inner: newSink(t), g: g}
	st, err := consume(context.Background(), as{g, "sink-1"}, dst, opts(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 6 || len(g.pending) != 0 {
		t.Fatalf("stats %+v, pending %d", st, len(g.pending))
	}
	if len(g.events) != 2 || g.events[0] != "commit" || !strings.HasPrefix(g.events[1], "ack ") {
		t.Fatalf("events %v: want the commit, then one ack", g.events)
	}
}

// TestCrashThenRestart is the demo: commit, die before XACK. Redis keeps the
// entries pending; the restart recovers them FIRST, recognises every one, and
// acks without committing twice.
func TestCrashThenRestart(t *testing.T) {
	g := newGroup(sixEvents()...)
	dst := newSink(t)
	o := opts()
	o.afterCommit = func() { panic("crash-after-commit") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the crash hook did not run")
			}
		}()
		_, _ = consume(context.Background(), as{g, "sink-1"}, dst, o, &bytes.Buffer{})
	}()
	if len(g.pending) != 6 {
		t.Fatalf("%d pending after the crash, want 6: nothing may be acked before the commit returns", len(g.pending))
	}

	// New work arrived meanwhile: recovery must still come first.
	g.entries = append(g.entries, ev("7-0", "u-90"))
	st, err := consume(context.Background(), as{g, "sink-1"}, dst, opts(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.recovered != 6 || st.duplicates != 6 || st.committed != 1 || len(g.pending) != 0 {
		t.Fatalf("restart: %+v, pending %d; want 6 recovered as duplicates, 1 new", st, len(g.pending))
	}
}

// TestClaimFromADeadConsumer: a consumer replaced under a new name would never
// read its predecessor's pending entries. XAUTOCLAIM takes the idle ones; a
// consumer that is merely busy (not idle long enough) keeps its own.
func TestClaimFromADeadConsumer(t *testing.T) {
	g := newGroup(sixEvents()...)
	old := as{g, "sink-old"}
	if _, err := old.readGroup(context.Background(), ">", 3, -1); err != nil { // 1-0..3-0, then it died
		t.Fatal(err)
	}
	g.now = g.now.Add(2 * time.Minute)
	busy := as{g, "sink-busy"}
	if _, err := busy.readGroup(context.Background(), ">", 1, -1); err != nil { // 4-0, just now
		t.Fatal(err)
	}

	st, err := consume(context.Background(), as{g, "sink-new"}, newSink(t), opts(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.recovered != 3 || st.committed != 5 {
		t.Fatalf("stats %+v: want the dead consumer's 3 claimed, 5 committed in all", st)
	}
	if p := g.pending["4-0"]; p == nil || p.owner != "sink-busy" {
		t.Fatalf("a busy consumer's recent entry was taken: %+v", p)
	}
}

// TestRefused: acked at once (never left to be re-read forever), logged by
// entry id only, never by key, and still in the stream.
func TestRefused(t *testing.T) {
	es := append(sixEvents(), ev("7-0", "Jo-Smith"), ev("8-0", "jo@example.com"),
		entry{id: "9-0", key: "u-81"}, // no data (e.g. XDEL'd)
		entry{id: "10-0", key: "u-81", data: make([]byte, sink.MaxContentBytes+1)})
	g := newGroup(es...)
	var log bytes.Buffer
	st, err := consume(context.Background(), as{g, "sink-1"}, newSink(t), opts(), &log)
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 6 || st.refused != 4 || len(g.pending) != 0 {
		t.Fatalf("stats %+v, pending %d", st, len(g.pending))
	}
	for _, id := range []string{"evidence:7-0", "evidence:8-0", "evidence:9-0", "evidence:10-0"} {
		if !strings.Contains(log.String(), id) {
			t.Errorf("log does not name %s", id)
		}
	}
	if strings.Contains(log.String(), "Jo-Smith") || strings.Contains(log.String(), "jo@example") {
		t.Fatalf("log names a refused key: %q", log.String())
	}
	if len(g.entries) != len(es) {
		t.Fatal("a refused entry was removed from the stream")
	}
}

// TestCommitFailure: nothing of a failed chain is acked. It stays pending and
// the next run commits it.
func TestCommitFailure(t *testing.T) {
	g := newGroup(sixEvents()...)
	dst := newSink(t)
	_, err := consume(context.Background(), as{g, "sink-1"}, &loggingSink{inner: dst, g: g, fail: "u-82"},
		opts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("the commit failure was swallowed")
	}
	if len(g.pending) != 2 || g.pending["2-0"] == nil || g.pending["5-0"] == nil {
		t.Fatalf("pending %v: want exactly u-82's two entries", g.pending)
	}
	st, err := consume(context.Background(), as{g, "sink-1"}, dst, opts(), &bytes.Buffer{})
	if err != nil || st.recovered != 2 || st.committed != 2 || len(g.pending) != 0 {
		t.Fatalf("next run: %+v, %v", st, err)
	}
}

// TestAckFailure: committed but not acked. The next run recognises them.
func TestAckFailure(t *testing.T) {
	g := newGroup(sixEvents()...)
	dst := newSink(t)
	g.ackErr = errors.New("connection reset")
	if _, err := consume(context.Background(), as{g, "sink-1"}, dst, opts(), &bytes.Buffer{}); err == nil {
		t.Fatal("an ack failure was swallowed")
	}
	g.ackErr = nil
	st, err := consume(context.Background(), as{g, "sink-1"}, dst, opts(), &bytes.Buffer{})
	if err != nil || st.duplicates != 6 || st.committed != 0 || len(g.pending) != 0 {
		t.Fatalf("next run: %+v, %v; want 6 recognised", st, err)
	}
}

// TestClaimPages: more idle entries than one XAUTOCLAIM returns. The cursor
// must be followed to the end, or the rest stay stranded.
func TestClaimPages(t *testing.T) {
	var es []entry
	for i := 1; i <= 250; i++ {
		es = append(es, ev(fmt.Sprintf("%d-0", i), fmt.Sprintf("u-%d", i%3)))
	}
	g := newGroup(es...)
	if _, err := (as{g, "dead"}).readGroup(context.Background(), ">", 250, -1); err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(time.Hour)
	st, err := consume(context.Background(), as{g, "sink-1"}, newSink(t), opts(), &bytes.Buffer{})
	if err != nil || st.recovered != 250 || st.committed != 250 || len(g.pending) != 0 {
		t.Fatalf("stats %+v, err %v, pending %d; want all 250 claimed", st, err, len(g.pending))
	}
}

// TestDeletedWhilePending: an entry deleted from the stream while pending can
// never be committed. It must be reported as lost, not as a bad key, and not
// left pending forever. Both paths: this consumer's own list, and a claim.
func TestDeletedWhilePending(t *testing.T) {
	g := newGroup(sixEvents()...)
	if _, err := (as{g, "sink-1"}).readGroup(context.Background(), ">", 2, -1); err != nil { // 1-0, 2-0: own
		t.Fatal(err)
	}
	if _, err := (as{g, "dead"}).readGroup(context.Background(), ">", 1, -1); err != nil { // 3-0: a dead peer's
		t.Fatal(err)
	}
	g.deleted["1-0"], g.deleted["3-0"] = true, true
	g.now = g.now.Add(time.Hour)
	var log bytes.Buffer
	st, err := consume(context.Background(), as{g, "sink-1"}, newSink(t), opts(), &log)
	if err != nil {
		t.Fatal(err)
	}
	if st.vanished != 2 || st.refused != 0 || st.committed != 4 || len(g.pending) != 0 {
		t.Fatalf("stats %+v, pending %d", st, len(g.pending))
	}
	for _, id := range []string{"lost evidence:1-0", "lost evidence:3-0"} {
		if !strings.Contains(log.String(), id) {
			t.Errorf("log does not report %q: %s", id, log.String())
		}
	}
	if strings.Contains(log.String(), "not a valid chain id") {
		t.Fatalf("a deleted entry was reported as a bad key: %s", log.String())
	}
}

// TestFollowKeepsClaiming: a peer that dies while this consumer is running
// must not strand its entries until the next restart.
func TestFollowKeepsClaiming(t *testing.T) {
	g := newGroup(sixEvents()...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	g.onRead = func() {
		reads++
		switch {
		case reads == 2:
			// After start-up recovery: a peer takes every entry, then dies.
			for g.next < len(g.entries) {
				g.pending[g.entries[g.next].id] = &pend{owner: "peer", since: g.now}
				g.next++
			}
			g.now = g.now.Add(time.Hour)
		case reads > 2 && len(g.pending) == 0, reads > 1_000_000:
			cancel() // claimed (or give up); the next read sees Ctrl-C
		}
	}
	o := opts()
	o.follow, o.claimIdle = true, time.Millisecond
	st, err := consume(ctx, as{g, "sink-1"}, newSink(t), o, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Ctrl-C during -follow must be a clean stop, got %v", err)
	}
	if st.committed != 6 || len(g.pending) != 0 {
		t.Fatalf("stats %+v, pending %d: the dead peer's entries were not claimed while running", st, len(g.pending))
	}
}

// TestRecreatedStreamIsNotADuplicate: a recreated stream restarts its ids. With
// a new incarnation in the Source, the new "1-0" is committed, not dropped.
func TestRecreatedStreamIsNotADuplicate(t *testing.T) {
	dst := newSink(t)
	if _, err := consume(context.Background(), as{newGroup(ev("1-0", "u-81")), "sink-1"}, dst, opts(),
		&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	o := opts()
	o.sourcePrefix = "evidence@t2"
	st, err := consume(context.Background(), as{newGroup(ev("1-0", "u-81")), "sink-1"}, dst, o, &bytes.Buffer{})
	if err != nil || st.committed != 1 || st.duplicates != 0 {
		t.Fatalf("new stream, same id: %+v, %v; want committed", st, err)
	}
}

func TestSourceFits(t *testing.T) {
	if err := sourceFits("evidence@0123456789abcdef"); err != nil {
		t.Fatalf("an ordinary stream name refused: %v", err)
	}
	if err := sourceFits(strings.Repeat("s", 250) + "@0123456789abcdef"); err == nil {
		t.Fatal("a stream name that overflows every position was accepted")
	}
}

// misreportingSink commits, then reports every record as NOT committed, so the
// consumer acks nothing.
type misreportingSink struct{ inner *sink.Sink }

func (m misreportingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	done, err := m.inner.Commit(ctx, recs)
	for i := range done {
		done[i].Committed = false
	}
	return done, err
}

// TestPendingThatNeverAcksStops: if a recovery pass acknowledges nothing, the
// consumer stops with an error instead of re-reading the same entries forever.
func TestPendingThatNeverAcksStops(t *testing.T) {
	g := newGroup(sixEvents()...)
	if _, err := (as{g, "sink-1"}).readGroup(context.Background(), ">", 6, -1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := consume(context.Background(), as{g, "sink-1"}, misreportingSink{newSink(t)}, opts(), &bytes.Buffer{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "without being acknowledged") {
			t.Fatalf("consume = %v; want it to stop and say why", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("consume looped over pending entries it could not acknowledge")
	}
}

// shortSink commits for real, then returns fewer outcomes than records: a
// committer breaking the one-per-record contract.
type shortSink struct{ inner *sink.Sink }

func (s shortSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	out, err := s.inner.Commit(ctx, recs)
	if len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out, err
}

// TestOutcomeCountMismatch: outcomes that cannot be matched one to one are not
// trusted: nothing is acked (everything stays pending), and nothing panics.
func TestOutcomeCountMismatch(t *testing.T) {
	g := newGroup(sixEvents()...)
	if _, err := consume(context.Background(), as{g, "sink-1"}, shortSink{newSink(t)}, opts(), &bytes.Buffer{}); err == nil {
		t.Fatal("a mismatched outcome count was accepted")
	}
	if len(g.pending) != 6 {
		t.Fatalf("pending %d, want all 6: nothing may be acked on a broken contract", len(g.pending))
	}
}
