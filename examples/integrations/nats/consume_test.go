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

	"github.com/aleutian-ai/proof/sink"
)

// fakeMsg records what the consumer did to it, and when, on a shared log.
type fakeMsg struct {
	subject string
	data    []byte
	pos     string
	posErr  error
	events  *[]string
	state   string // "", "ack", "nak", "term"
}

func (m *fakeMsg) Subject() string { return m.subject }
func (m *fakeMsg) Data() []byte    { return m.data }
func (m *fakeMsg) Position() (string, error) {
	return m.pos, m.posErr
}
func (m *fakeMsg) settle(s string) error {
	m.state = s
	*m.events = append(*m.events, s+" "+m.pos)
	return nil
}
func (m *fakeMsg) Ack() error  { return m.settle("ack") }
func (m *fakeMsg) Nak() error  { return m.settle("nak") }
func (m *fakeMsg) Term() error { return m.settle("term") }

// loggingSink wraps a real Sink and logs each Commit on the same event log, so a
// test can see that acks come after the commit.
type loggingSink struct {
	inner  committer
	events *[]string
	fail   string // a chain whose commit fails
}

func (s *loggingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	*s.events = append(*s.events, "commit")
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

type harness struct {
	events []string
	sink   *sink.Sink
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	s, err := sink.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &harness{sink: s}
}

func (h *harness) msg(subject string, seq int) *fakeMsg {
	return &fakeMsg{subject: subject, data: []byte(fmt.Sprintf(`{"subject":%q,"seq":%d}`, subject, seq)),
		pos: fmt.Sprintf("EVIDENCE:%d", seq), events: &h.events}
}

func asMessages(ms ...*fakeMsg) []message {
	out := make([]message, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

var r = router{prefix: "evidence", class: "events"}

func TestRouter(t *testing.T) {
	cases := map[string]string{
		"evidence.u-81":                        "u-81",
		"evidence.orders_eu":                   "orders_eu",
		"evidence.jo@example.com":              "", // three tokens: never "com"
		"evidence.U-81":                        "", // not a valid chain id
		"evidence.":                            "",
		"evidence":                             "",
		"other.u-81":                           "",
		"evidencex.u-81":                       "",
		"evidence.a.b":                         "",
		"evidence." + strings.Repeat("a", 129): "",
	}
	for subject, want := range cases {
		got, ok := r.subject(subject)
		if want == "" && ok {
			t.Errorf("%q routed to %q; want refused", subject, got)
		}
		if want != "" && (!ok || got != want) {
			t.Errorf("%q → %q, %v; want %q", subject, got, ok, want)
		}
	}
}

// TestAckAfterCommit: every ack comes after the commit, never before.
func TestAckAfterCommit(t *testing.T) {
	h := newHarness(t)
	dst := &loggingSink{inner: h.sink, events: &h.events}
	ms := []*fakeMsg{h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 2), h.msg("evidence.u-81", 3)}
	st, err := processBatch(context.Background(), dst, r, asMessages(ms...), nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 3 || st.duplicates != 0 || st.refused != 0 {
		t.Fatalf("stats %+v", st)
	}
	if h.events[0] != "commit" || len(h.events) != 4 {
		t.Fatalf("events %v: want the commit first, then three acks", h.events)
	}
	for _, m := range ms {
		if m.state != "ack" {
			t.Fatalf("%s: %q, want ack", m.pos, m.state)
		}
	}
}

// TestRedelivery_NotCommittedTwice: the crash between commit and ack. The same
// messages come back; they are acked and nothing is committed twice.
func TestRedelivery_NotCommittedTwice(t *testing.T) {
	h := newHarness(t)
	crash := func() { panic("crash-after-commit") }

	first := []*fakeMsg{h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 2)}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the crash hook did not run")
			}
		}()
		_, _ = processBatch(context.Background(), h.sink, r, asMessages(first...), crash, &bytes.Buffer{})
	}()
	for _, m := range first {
		if m.state != "" {
			t.Fatalf("%s was %s before the crash; nothing may be acked before it", m.pos, m.state)
		}
	}

	// Redelivered, with one new message behind them.
	again := []*fakeMsg{h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 2), h.msg("evidence.u-81", 3)}
	st, err := processBatch(context.Background(), h.sink, r, asMessages(again...), nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 1 || st.duplicates != 2 {
		t.Fatalf("redelivery: %+v; want 1 committed, 2 duplicates", st)
	}
	for _, m := range again {
		if m.state != "ack" {
			t.Fatalf("%s: %q; a redelivered message must be acked", m.pos, m.state)
		}
	}
}

// TestRefused: a bad subject is terminated and logged by position, never by
// subject; the rest of the batch is committed.
func TestRefused(t *testing.T) {
	h := newHarness(t)
	var log bytes.Buffer
	bad := h.msg("evidence.Jo-Smith", 2)
	ms := []*fakeMsg{h.msg("evidence.u-81", 1), bad, h.msg("evidence.u-82", 3)}
	st, err := processBatch(context.Background(), h.sink, r, asMessages(ms...), nil, &log)
	if err != nil {
		t.Fatal(err)
	}
	if st.committed != 2 || st.refused != 1 {
		t.Fatalf("stats %+v", st)
	}
	if bad.state != "term" {
		t.Fatalf("refused message: %q, want term", bad.state)
	}
	if !strings.Contains(log.String(), "EVIDENCE:2") || strings.Contains(log.String(), "Jo-Smith") {
		t.Fatalf("log must name the position and never the subject: %q", log.String())
	}
}

// TestCommitFailure: messages of a chain whose commit failed are NAKed for
// redelivery; those of chains committed before it are acked.
func TestCommitFailure(t *testing.T) {
	h := newHarness(t)
	dst := &loggingSink{inner: h.sink, events: &h.events, fail: "u-82"}
	a, b := h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 2)
	_, err := processBatch(context.Background(), dst, r, asMessages(a, b), nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("the commit failure was swallowed")
	}
	if a.state != "ack" || b.state != "nak" {
		t.Fatalf("u-81 %q (want ack), u-82 %q (want nak)", a.state, b.state)
	}
}

// TestNoPosition: without a stream position the record could not be made
// idempotent, and redelivery will not give it one: terminated, not committed.
func TestNoPosition(t *testing.T) {
	h := newHarness(t)
	m := h.msg("evidence.u-81", 1)
	m.posErr = errors.New("no metadata")
	st, err := processBatch(context.Background(), h.sink, r, asMessages(m), nil, &bytes.Buffer{})
	if err != nil || st.committed != 0 || st.refused != 1 || m.state != "term" {
		t.Fatalf("stats %+v, err %v, state %q", st, err, m.state)
	}
}

// TestBadPayloadDoesNotStallTheStream: an empty or oversized payload would make
// sink refuse the whole batch, every time it came back. It is terminated
// instead, and the rest of the batch is committed and acked.
func TestBadPayloadDoesNotStallTheStream(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     {},
		"oversized": make([]byte, sink.MaxContentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			var log bytes.Buffer
			bad := h.msg("evidence.u-81", 2)
			bad.data = data
			good := []*fakeMsg{h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 3)}
			st, err := processBatch(context.Background(), h.sink, r,
				asMessages(good[0], bad, good[1]), nil, &log)
			if err != nil {
				t.Fatalf("one bad payload failed the batch: %v", err)
			}
			if st.committed != 2 || st.refused != 1 || bad.state != "term" {
				t.Fatalf("stats %+v, bad %q", st, bad.state)
			}
			for _, m := range good {
				if m.state != "ack" {
					t.Fatalf("%s: %q, want ack", m.pos, m.state)
				}
			}
			if strings.Contains(log.String(), "u-81") {
				t.Fatalf("log names the subject: %q", log.String())
			}
		})
	}
}

// TestRecreatedStreamIsNotADuplicate: a recreated stream restarts at sequence
// 1. With its incarnation in the position, the new message 1 is committed, not
// dropped as the old message 1.
func TestRecreatedStreamIsNotADuplicate(t *testing.T) {
	h := newHarness(t)
	old := h.msg("evidence.u-81", 1)
	old.pos = "EVIDENCE@100:1"
	if _, err := processBatch(context.Background(), h.sink, r, asMessages(old), nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	fresh := h.msg("evidence.u-81", 1)
	fresh.pos = "EVIDENCE@200:1"
	st, err := processBatch(context.Background(), h.sink, r, asMessages(fresh), nil, &bytes.Buffer{})
	if err != nil || st.committed != 1 || st.duplicates != 0 {
		t.Fatalf("a new message in a recreated stream: %+v, %v; want committed", st, err)
	}
}

// shortSink commits for real, then returns fewer outcomes than records: a
// committer breaking the one-per-record contract.
type shortSink struct{ inner committer }

func (s shortSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	out, err := s.inner.Commit(ctx, recs)
	if len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out, err
}

// TestOutcomeCountMismatch: outcomes that cannot be matched one to one are not
// trusted: nothing is acked, everything is NAKed, and no index is out of range.
func TestOutcomeCountMismatch(t *testing.T) {
	h := newHarness(t)
	a, b := h.msg("evidence.u-81", 1), h.msg("evidence.u-82", 2)
	_, err := processBatch(context.Background(), shortSink{h.sink}, r, asMessages(a, b), nil, &bytes.Buffer{})
	if err == nil || a.state != "nak" || b.state != "nak" {
		t.Fatalf("err %v, states %q %q; want an error and both NAKed", err, a.state, b.state)
	}
}

// configSink refuses every commit as a signing-mode mismatch.
type configSink struct{ err error }

func (s configSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) {
	return nil, s.err
}

// TestConfigurationErrorDoesNotNak: a signing-mode mismatch stops the batch
// WITHOUT a NAK (an immediate redelivery would only loop); the messages stay
// unacknowledged for a consumer that is configured right.
func TestConfigurationErrorDoesNotNak(t *testing.T) {
	for _, e := range []error{sink.ErrRecordSignerRequired, sink.ErrSinkNotSigning} {
		h := newHarness(t)
		a := h.msg("evidence.u-81", 1)
		_, err := processBatch(context.Background(), configSink{e}, r, asMessages(a), nil, &bytes.Buffer{})
		if !errors.Is(err, e) || a.state != "" {
			t.Fatalf("err %v, state %q; want the error and the message left unsettled", err, a.state)
		}
	}
}
