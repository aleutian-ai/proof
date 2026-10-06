// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/sink"
)

// ---------------------------------------------------------------------------
// An in-memory consumer group with Kafka's semantics: each partition is a log;
// the group keeps one committed offset per partition; a consumer reads from
// the committed offset (the start when there is none) and its read position
// moves on whether or not it commits. A restart reads from the committed
// offsets again.
// ---------------------------------------------------------------------------

type fakeTopic struct {
	id        [16]byte
	logs      map[int32][]message // partition → records, offset = index
	committed map[int32]int64     // the group's committed offsets
	commitErr error
	commits   [][]message // every commit call, for inspection
}

func newTopic(id byte) *fakeTopic {
	return &fakeTopic{id: [16]byte{id}, logs: map[int32][]message{}, committed: map[int32]int64{}}
}

// produce appends a record to a partition.
func (t *fakeTopic) produce(p int32, key string, value string) {
	m := message{topicID: t.id, partition: p, offset: int64(len(t.logs[p])), value: []byte(value)}
	if key != "" {
		m.key = []byte(key)
	}
	t.logs[p] = append(t.logs[p], m)
}

// fakeConsumer is one consumer process: it starts at the committed offsets.
type fakeConsumer struct {
	t         *fakeTopic
	pos       map[int32]int64
	polls     int
	allows    int
	deadlines int           // polls whose ctx had a deadline
	longest   time.Duration // the furthest such deadline
	onPoll    func()
	pollErr   error
	// unassigned: never assigned a partition, so ready waits for ctx.
	unassigned bool
}

func (t *fakeTopic) consumer() *fakeConsumer {
	pos := map[int32]int64{}
	for p, o := range t.committed {
		pos[p] = o
	}
	return &fakeConsumer{t: t, pos: pos}
}

func (c *fakeConsumer) ready(ctx context.Context) error {
	if c.unassigned {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (c *fakeConsumer) poll(ctx context.Context, limit int) ([]message, error) {
	c.polls++
	if d, ok := ctx.Deadline(); ok {
		c.deadlines++
		c.longest = max(c.longest, time.Until(d))
	}
	if c.onPoll != nil {
		c.onPoll()
	}
	if c.pollErr != nil {
		return nil, c.pollErr
	}
	// Round-robin across partitions, so a batch interleaves them; within a
	// partition, offset order.
	var out []message
	for more := true; more && len(out) < limit; {
		more = false
		for p := int32(0); p < 8 && len(out) < limit; p++ {
			if c.pos[p] < int64(len(c.t.logs[p])) {
				out = append(out, c.t.logs[p][c.pos[p]])
				c.pos[p]++
				more = true
			}
		}
	}
	if len(out) == 0 {
		// Nothing new: a real poll waits; this one waits a little, or until ctx ends.
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	return out, nil
}

func (c *fakeConsumer) commit(_ context.Context, last []message) error {
	if c.t.commitErr != nil {
		return c.t.commitErr
	}
	c.t.commits = append(c.t.commits, last)
	for _, m := range last {
		c.t.committed[m.partition] = m.offset + 1
	}
	return nil
}

func (c *fakeConsumer) allowRebalance() { c.allows++ }

func newSink(t *testing.T) *sink.Sink {
	t.Helper()
	s, err := sink.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func opts() options {
	return options{topic: "agent-actions", class: "actions", idle: 50 * time.Millisecond}
}

func entries(t *testing.T, s *sink.Sink) int {
	t.Helper()
	// No checkpoints here, so an empty key ring: only chains and contents are checked.
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("the sink does not verify: %+v", rep)
	}
	n := 0
	for _, c := range rep.Chains {
		n += c.Entries
	}
	return n
}

// The demo's story: commit, crash before the offset commit, restart. The
// redelivered records are recognised, nothing is committed twice, and the
// offsets end at the log end.
func TestConsume_CrashBetweenCommits(t *testing.T) {
	ctx := context.Background()
	tp := newTopic(1)
	tp.produce(0, "u-81", `{"e":1}`)
	tp.produce(1, "u-82", `{"e":2}`)
	tp.produce(0, "u-81", `{"e":3}`)
	tp.produce(2, "u-90", `{"e":4}`)
	s := newSink(t)

	o := opts()
	crashed := errors.New("crash")
	o.afterCommit = func() { panic(crashed) }
	func() {
		defer func() {
			if r := recover(); r != crashed {
				t.Fatalf("recover = %v", r)
			}
		}()
		consume(ctx, tp.consumer(), s, o, &bytes.Buffer{})
	}()
	if len(tp.committed) != 0 {
		t.Fatalf("offsets committed before the crash: %v", tp.committed)
	}

	st, err := consume(ctx, tp.consumer(), s, opts(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 0 || st.duplicates != 4 {
		t.Fatalf("stats = %+v, want 0 committed, 4 already committed", st)
	}
	if tp.committed[0] != 2 || tp.committed[1] != 1 || tp.committed[2] != 1 {
		t.Fatalf("offsets = %v", tp.committed)
	}
	if n := entries(t, s); n != 4 {
		t.Fatalf("entries = %d, want 4", n)
	}
}

// A record with no key, or a key that is a name, is refused, logged by
// position only, and handled: the offset moves past it.
func TestConsume_RefusedAreHandled(t *testing.T) {
	ctx := context.Background()
	tp := newTopic(1)
	tp.produce(0, "", `{"e":"nokey"}`)
	tp.produce(0, "Jo-Smith", `{"e":"name"}`)
	tp.produce(0, "u-81", ``) // empty value
	tp.produce(0, "u-81", `{"e":1}`)
	var log bytes.Buffer
	st, err := consume(ctx, tp.consumer(), newSink(t), opts(), &log)
	if err != nil {
		t.Fatal(err)
	}
	if st.refused != 3 || st.committed != 1 || tp.committed[0] != 4 {
		t.Fatalf("stats = %+v, offsets = %v", st, tp.committed)
	}
	if strings.Contains(log.String(), "Jo-Smith") || strings.Contains(log.String(), "nokey") {
		t.Fatalf("the log names a key or value: %s", log.String())
	}
	for _, pos := range []string{"agent-actions/0@0", "agent-actions/0@1", "agent-actions/0@2"} {
		if !strings.Contains(log.String(), "refused "+pos+":") {
			t.Fatalf("no refusal logged for %s: %s", pos, log.String())
		}
	}
}

// failingSink fails every record of one subject, committing the rest.
type failingSink struct {
	inner *sink.Sink
	fail  string
}

func (f failingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	var ok []sink.Record
	var at []int
	for i, r := range recs {
		if r.Subject != f.fail {
			ok = append(ok, r)
			at = append(at, i)
		}
	}
	out := make([]sink.Outcome, len(recs))
	if len(ok) > 0 {
		got, err := f.inner.Commit(ctx, ok)
		if err != nil {
			return nil, err
		}
		for j, oc := range got {
			out[at[j]] = oc
		}
	}
	return out, errors.New("disk full")
}

// The offset rule: per partition, up to the first record not handled. A
// later committed record (new or Duplicate) on the same partition never lets
// the offset skip over the one that failed; other partitions still advance.
func TestConsume_StopsAtFirstUnhandledPerPartition(t *testing.T) {
	ctx := context.Background()
	tp := newTopic(1)
	s := newSink(t)
	// u-82's record is already on its chain, so it comes back as a Duplicate.
	if _, err := s.Commit(ctx, []sink.Record{{Class: "actions", Subject: "u-82", Content: []byte("x"),
		Source: source("agent-actions", message{topicID: tp.id, partition: 0, offset: 3})}}); err != nil {
		t.Fatal(err)
	}
	tp.produce(0, "u-81", `{"e":1}`) // 0: committed
	tp.produce(0, "Jo-Smith", `{}`)  // 1: refused, handled
	tp.produce(0, "u-99", `{"e":2}`) // 2: FAILS
	tp.produce(0, "u-82", `x`)       // 3: Duplicate: must not move the offset past 2
	tp.produce(1, "u-83", `{"e":3}`) // partition 1: committed
	tp.produce(2, "u-99", `{"e":4}`) // partition 2: fails first: no commit there

	st, err := consume(ctx, tp.consumer(), failingSink{inner: s, fail: "u-99"}, opts(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
	if st.committed != 2 || st.duplicates != 1 || st.refused != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if tp.committed[0] != 2 {
		t.Fatalf("partition 0 offset = %d, want 2 (stop at the failed record)", tp.committed[0])
	}
	if tp.committed[1] != 1 {
		t.Fatalf("partition 1 offset = %d, want 1", tp.committed[1])
	}
	if _, ok := tp.committed[2]; ok {
		t.Fatalf("partition 2 was committed past its failed first record: %v", tp.committed)
	}
}

// contractSink returns the wrong number of outcomes.
type contractSink struct{ n int }

func (c contractSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) {
	out := make([]sink.Outcome, c.n)
	for i := range out {
		out[i].Committed = true
	}
	return out, nil
}

// errSink returns an error and no outcomes.
type errSink struct{ err error }

func (e errSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) { return nil, e.err }

// Nothing at all is committed — not even a refused prefix — on a contract
// error, a configuration error, or a missing topic id.
func TestConsume_CommitsNothing(t *testing.T) {
	cases := []struct {
		name string
		dst  committer
		id   byte
		want string
	}{
		{"contract", contractSink{n: 1}, 1, "1 outcomes for 2 records"},
		{"signer required", errSink{sink.ErrRecordSignerRequired}, 1, ""},
		{"not signing", errSink{sink.ErrSinkNotSigning}, 1, ""},
		{"no topic id", contractSink{n: 2}, 0, "no topic id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopic(tc.id)
			tp.produce(0, "Jo-Smith", `{}`) // refused first: would be committable
			tp.produce(0, "u-81", `{"e":1}`)
			tp.produce(1, "u-82", `{"e":2}`)
			_, err := consume(context.Background(), tp.consumer(), tc.dst, opts(), &bytes.Buffer{})
			if err == nil || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if len(tp.commits) != 0 {
				t.Fatalf("offsets committed: %v", tp.committed)
			}
		})
	}
}

// The configuration error reaches the caller as itself, for the CLI's message.
func TestConsume_ConfigurationErrorIsReturned(t *testing.T) {
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	_, err := consume(context.Background(), tp.consumer(), errSink{sink.ErrSinkNotSigning}, opts(), &bytes.Buffer{})
	if !errors.Is(err, sink.ErrSinkNotSigning) || !strings.Contains(configurationError(err).Error(), "not retried") {
		t.Fatalf("err = %v", err)
	}
}

// A deleted and recreated topic restarts its offsets at 0. Its topic id is
// new, so a record at an old position is committed, not taken for the old one.
// The control: the same position under the SAME id is a duplicate, so the id
// is what tells them apart.
func TestConsume_RecreatedTopic(t *testing.T) {
	ctx := context.Background()
	s := newSink(t)
	old := newTopic(1)
	old.produce(0, "u-81", `{"e":"old"}`)
	if _, err := consume(ctx, old.consumer(), s, opts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	again := newTopic(1) // the control: same id, same position
	again.produce(0, "u-81", `{"e":"new"}`)
	st, err := consume(ctx, again.consumer(), s, opts(), &bytes.Buffer{})
	if err != nil || st.duplicates != 1 {
		t.Fatalf("control: stats = %+v, err = %v; want the reused position taken as a duplicate", st, err)
	}

	recreated := newTopic(2)
	recreated.produce(0, "u-81", `{"e":"new"}`)
	st, err = consume(ctx, recreated.consumer(), s, opts(), &bytes.Buffer{})
	if err != nil || st.committed != 1 || st.duplicates != 0 {
		t.Fatalf("stats = %+v, err = %v; want the new record committed", st, err)
	}
	if n := entries(t, s); n != 2 {
		t.Fatalf("entries = %d, want 2", n)
	}
}

// A failed offset commit stops the run; the records come back next run and
// are recognised.
func TestConsume_OffsetCommitFails(t *testing.T) {
	ctx := context.Background()
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	s := newSink(t)
	tp.commitErr = errors.New("coordinator gone")
	_, err := consume(ctx, tp.consumer(), s, opts(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "coordinator gone") {
		t.Fatalf("err = %v", err)
	}
	tp.commitErr = nil
	st, err := consume(ctx, tp.consumer(), s, opts(), &bytes.Buffer{})
	if err != nil || st.duplicates != 1 || tp.committed[0] != 1 {
		t.Fatalf("stats = %+v, err = %v, offsets = %v", st, err, tp.committed)
	}
}

// Every poll is followed by AllowRebalance, whatever happened.
func TestConsume_AllowsRebalanceAfterEveryPoll(t *testing.T) {
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	c := tp.consumer()
	if _, err := consume(context.Background(), c, newSink(t), opts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if c.polls != 2 || c.allows != 2 { // one batch, then one empty poll
		t.Fatalf("polls %d, allows %d", c.polls, c.allows)
	}
	c = tp.consumer()
	c.pollErr = errors.New("broker down")
	if _, err := consume(context.Background(), c, newSink(t), opts(), &bytes.Buffer{}); err == nil {
		t.Fatal("a poll error was swallowed")
	}
	if c.allows != c.polls {
		t.Fatalf("polls %d, allows %d", c.polls, c.allows)
	}
}

// With follow, an empty poll is not the end; stopping (Ctrl-C) is a clean stop.
func TestConsume_FollowStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	c := tp.consumer()
	c.onPoll = func() {
		if c.polls == 3 {
			tp.produce(0, "u-82", `{}`) // a record arriving while following
		}
		if c.polls == 5 {
			cancel()
		}
	}
	o := opts()
	o.follow = true
	done := make(chan struct{})
	var st stats
	var err error
	go func() {
		st, err = consume(ctx, c, newSink(t), o, &bytes.Buffer{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("follow did not stop")
	}
	// The record produced after empty polls is committed: an empty poll does
	// not end a follow.
	if err != nil || st.committed != 2 {
		t.Fatalf("stats = %+v, err = %v; want both records committed", st, err)
	}
	if c.deadlines != 0 {
		t.Fatalf("%d follow polls had a deadline", c.deadlines)
	}
}

// Without follow, every poll is bounded by -idle: a drained topic ends the run.
func TestConsume_IdleBoundsEachPoll(t *testing.T) {
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	c := tp.consumer()
	if _, err := consume(context.Background(), c, newSink(t), opts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if c.deadlines != c.polls || c.polls == 0 {
		t.Fatalf("%d of %d polls had a deadline", c.deadlines, c.polls)
	}
	if c.longest > opts().idle {
		t.Fatalf("a poll deadline was %v away, over -idle %v", c.longest, opts().idle)
	}
}

func TestSource(t *testing.T) {
	m := message{topicID: [16]byte{0x0d, 0x55, 0xa5, 0x60, 0x95, 0x76, 0x4c, 0x7f, 0xa5, 0xaa, 0xfc, 0xfe,
		0xb9, 0x6e, 0x7b, 0x62}, partition: 2, offset: 17}
	// The id as kafka-topics.sh --describe prints it.
	m.epoch = 4
	if got, want := source("agent-actions", m), "agent-actions@DVWlYJV2TH-lqvz-uW57Yg/2:17#4"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

// The longest topic whose positions fit is accepted; one more byte is refused.
func TestSourceFits(t *testing.T) {
	n := sink.MaxSourceBytes - maxPosition
	if err := sourceFits(strings.Repeat("t", n)); err != nil {
		t.Fatal(err)
	}
	if err := sourceFits(strings.Repeat("t", n+1)); err == nil {
		t.Fatal("a topic too long for the sink was accepted")
	}
	worst := message{topicID: [16]byte{0xff}, partition: 2147483647, offset: 9223372036854775807, epoch: -2147483648}
	if got := len(source(strings.Repeat("t", n), worst)); got != sink.MaxSourceBytes {
		t.Fatalf("worst-case source is %d bytes, want %d", got, sink.MaxSourceBytes)
	}
}

func TestHandledPrefix(t *testing.T) {
	ms := []message{
		{partition: 0, offset: 5}, {partition: 1, offset: 9}, {partition: 0, offset: 6},
		{partition: 0, offset: 7}, {partition: 1, offset: 10},
	}
	got := handledPrefix(ms, []bool{true, false, true, false, true})
	if len(got) != 1 || got[0].partition != 0 || got[0].offset != 6 {
		t.Fatalf("got %+v", got)
	}
	if got := handledPrefix(ms, []bool{false, false, true, true, true}); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

// A sink that does not account for every record (no outcomes and no error, or
// a record left uncommitted without an error) is a contract error: nothing is
// committed, so a later batch can never move an offset past that record.
func TestConsume_SinkMustAccountForEveryRecord(t *testing.T) {
	cases := map[string]committer{
		"no outcomes, no error": errSink{nil},
		"uncommitted, no error": outcomeSink{{Committed: true}, {Committed: false}},
	}
	for name, dst := range cases {
		t.Run(name, func(t *testing.T) {
			tp := newTopic(1)
			tp.produce(0, "u-81", `{}`)
			tp.produce(0, "u-82", `{}`)
			_, err := consume(context.Background(), tp.consumer(), dst, opts(), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "no offset committed") {
				t.Fatalf("err = %v", err)
			}
			if len(tp.commits) != 0 {
				t.Fatalf("offsets committed: %v", tp.committed)
			}
		})
	}
}

// outcomeSink returns fixed outcomes and no error.
type outcomeSink []sink.Outcome

func (o outcomeSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) { return o, nil }

// The crash hook fires after a successful sink commit, before any offset
// commit, also for a batch that is all refusals; never after a failed commit.
func TestConsume_CrashHook(t *testing.T) {
	tp := newTopic(1)
	tp.produce(0, "Jo-Smith", `{}`) // refused only
	o := opts()
	fired := 0
	o.afterCommit = func() {
		fired++
		if len(tp.commits) != 0 {
			t.Fatal("the hook ran after an offset commit")
		}
	}
	if _, err := consume(context.Background(), tp.consumer(), newSink(t), o, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("fired %d times for an all-refused batch", fired)
	}

	fired = 0
	tp2 := newTopic(1)
	tp2.produce(0, "u-81", `{}`)
	if _, err := consume(context.Background(), tp2.consumer(), errSink{errors.New("disk full")}, o, &bytes.Buffer{}); err == nil {
		t.Fatal("a sink error was swallowed")
	}
	if fired != 0 {
		t.Fatal("the hook fired after a failed sink commit")
	}
}

// cancellingSink cancels the run's context, as Ctrl-C does, then commits.
type cancellingSink struct {
	inner  *sink.Sink
	cancel context.CancelFunc
}

func (c cancellingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	c.cancel()
	return c.inner.Commit(ctx, recs)
}

// Ctrl-C during a batch finishes the batch (sink commit and offset commit),
// then stops cleanly.
func TestConsume_CtrlCFinishesTheBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tp := newTopic(1)
	tp.produce(0, "u-81", `{}`)
	o := opts()
	o.follow = true
	st, err := consume(ctx, tp.consumer(), cancellingSink{inner: newSink(t), cancel: cancel}, o, &bytes.Buffer{})
	if err != nil || st.committed != 1 || tp.committed[0] != 1 {
		t.Fatalf("stats = %+v, err = %v, offsets = %v", st, err, tp.committed)
	}
}

// Without follow, a consumer never assigned a partition gives up after
// joinTimeout with a clear error; Ctrl-C while joining is a clean stop.
func TestConsume_Join(t *testing.T) {
	defer func(d time.Duration) { joinTimeout = d }(joinTimeout)
	joinTimeout = 20 * time.Millisecond
	tp := newTopic(1)
	c := tp.consumer()
	c.unassigned = true
	_, err := consume(context.Background(), c, newSink(t), opts(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no partition of agent-actions was assigned") {
		t.Fatalf("err = %v", err)
	}
	if c.polls != 0 {
		t.Fatal("polled before being assigned")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := opts()
	o.follow = true
	if _, err := consume(ctx, c, newSink(t), o, &bytes.Buffer{}); err != nil {
		t.Fatalf("Ctrl-C while joining: %v", err)
	}
}

// After a log truncation (an unclean leader election) Kafka hands out an
// offset again under a new leader epoch. The epoch is in the position, so the
// new record is committed, not taken for the old one.
func TestConsume_TruncationReusesOffset(t *testing.T) {
	ctx := context.Background()
	s := newSink(t)
	tp := newTopic(1)
	tp.produce(0, "u-81", `{"e":"before"}`)
	if _, err := consume(ctx, tp.consumer(), s, opts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after := newTopic(1) // same topic id, same partition and offset
	after.produce(0, "u-81", `{"e":"after"}`)
	after.logs[0][0].epoch = 1
	st, err := consume(ctx, after.consumer(), s, opts(), &bytes.Buffer{})
	if err != nil || st.committed != 1 {
		t.Fatalf("stats = %+v, err = %v; want the record at the reused offset committed", st, err)
	}
}

// messages: records keep their topic id, epoch and order; context errors are
// ignored; data loss is reported and not fatal; any other error stops.
func TestMessages(t *testing.T) {
	id := [16]byte{9}
	rec := func(p int32, off int64) *kgo.Record {
		return &kgo.Record{Topic: "agent-actions", Partition: p, Offset: off, LeaderEpoch: 3, Key: []byte("u-81")}
	}
	fs := kgo.Fetches{{Topics: []kgo.FetchTopic{{Topic: "agent-actions", TopicID: id, Partitions: []kgo.FetchPartition{
		{Partition: 0, Records: []*kgo.Record{rec(0, 5), rec(0, 6)}},
		{Partition: 1, Err: context.DeadlineExceeded},
		{Partition: 2, Err: &kgo.ErrDataLoss{Topic: "agent-actions", Partition: 2, ConsumedTo: 40, ResetTo: 30}},
	}}}}}
	var log bytes.Buffer
	ms, err := messages(fs, &log)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].topicID != id || ms[0].epoch != 3 || ms[0].offset != 5 || ms[1].offset != 6 ||
		ms[1].rec == nil || string(ms[0].key) != "u-81" {
		t.Fatalf("messages = %+v", ms)
	}
	if !strings.Contains(log.String(), "data loss in Kafka: agent-actions/2 was truncated back from offset 40 to 30") {
		t.Fatalf("data loss not reported: %q", log.String())
	}

	fs[0].Topics[0].Partitions[1].Err = errors.New("not leader")
	if ms, err := messages(fs, &log); err == nil || ms != nil {
		t.Fatalf("a fetch error was ignored: %v", err)
	}
}
