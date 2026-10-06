// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/sink"
)

// lrec describes one test log record. Empty fields are left unset.
type lrec struct {
	uid, subject, body string
	resSubject         string // enduser.pseudo.id on the resource instead
	uidInt             bool   // a uid that is not a string
}

func logsOf(rs ...lrec) plog.Logs {
	ld := plog.NewLogs()
	for _, r := range rs {
		rl := ld.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", "agent")
		if r.resSubject != "" {
			rl.Resource().Attributes().PutStr("enduser.pseudo.id", r.resSubject)
		}
		sl := rl.ScopeLogs().AppendEmpty()
		sl.Scope().SetName("test")
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(r.body)
		switch {
		case r.uidInt:
			lr.Attributes().PutInt(uidAttr, 7)
		case r.uid != "":
			lr.Attributes().PutStr(uidAttr, r.uid)
		}
		if r.subject != "" {
			lr.Attributes().PutStr("enduser.pseudo.id", r.subject)
		}
	}
	return ld
}

// post sends logs as protobuf (or JSON) and returns the status, the decoded
// answer, and the receiver's log.
func post(t *testing.T, rv *receiver, ld plog.Logs, json bool) (int, plogotlp.ExportResponse, http.Header) {
	t.Helper()
	req := plogotlp.NewExportRequestFromLogs(ld)
	var b []byte
	var err error
	ct := contentProto
	if json {
		b, err = req.MarshalJSON()
		ct = contentJSON
	} else {
		b, err = req.MarshalProto()
	}
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(b))
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	rv.ServeHTTP(w, r)
	resp := plogotlp.NewExportResponse()
	if w.Code == http.StatusOK {
		if json {
			err = resp.UnmarshalJSON(w.Body.Bytes())
		} else {
			err = resp.UnmarshalProto(w.Body.Bytes())
		}
		if err != nil {
			t.Fatalf("answer does not decode: %v", err)
		}
	}
	return w.Code, resp, w.Header()
}

func newSink(t *testing.T) *sink.Sink {
	t.Helper()
	s, err := sink.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func opts() options { return options{class: "app-logs", subjectAttr: "enduser.pseudo.id"} }

func entries(t *testing.T, s *sink.Sink) int {
	t.Helper()
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

// The collector retries a request it got no answer to. Every record comes
// back with the same uid and is recognised: answered 200, not re-committed.
func TestReceive_RetryIsRecognised(t *testing.T) {
	s := newSink(t)
	var log bytes.Buffer
	rv := newReceiver(s, opts(), &log)
	ld := logsOf(lrec{uid: "a1", subject: "u-81", body: "login"}, lrec{uid: "a2", subject: "u-82", body: "login"},
		lrec{uid: "a3", subject: "u-81", body: "export"})
	for _, json := range []bool{false, true} {
		code, resp, _ := post(t, rv, ld, json)
		if code != http.StatusOK || resp.PartialSuccess().RejectedLogRecords() != 0 {
			t.Fatalf("json=%v: %d, rejected %d", json, code, resp.PartialSuccess().RejectedLogRecords())
		}
	}
	if st := rv.totals(); st.committed != 3 || st.duplicates != 3 {
		t.Fatalf("totals = %+v, want 3 committed then 3 already committed", st)
	}
	if n := entries(t, s); n != 3 {
		t.Fatalf("entries = %d", n)
	}
}

// Owner-pinned (2026-10-06): the Source is delivery identity, not content
// equality. The same uid with a different payload is a duplicate, never new
// evidence. Nobody may add payload comparison without changing this test.
func TestReceive_SameUIDDifferentPayloadIsDuplicate(t *testing.T) {
	s := newSink(t)
	rv := newReceiver(s, opts(), io.Discard)
	if code, _, _ := post(t, rv, logsOf(lrec{uid: "abc", subject: "u-81", body: "payload A"}), false); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ := post(t, rv, logsOf(lrec{uid: "abc", subject: "u-81", body: "payload B"}), false); code != 200 {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != 1 || st.duplicates != 1 {
		t.Fatalf("totals = %+v, want 1 committed and 1 already committed", st)
	}
	if n := entries(t, s); n != 1 {
		t.Fatalf("entries = %d, want 1: payload B must not become new evidence", n)
	}
}

// Records that can never be committed are refused, counted in
// partial_success (which the collector does not retry), and logged by request
// and index, never by a value. The rest of the request is committed.
func TestReceive_Refusals(t *testing.T) {
	s := newSink(t)
	var log bytes.Buffer
	rv := newReceiver(s, opts(), &log)
	ld := logsOf(
		lrec{uid: "ok-1", subject: "u-81", body: "fine"},
		lrec{subject: "u-81", body: "no uid"},
		lrec{uidInt: true, subject: "u-81", body: "uid not a string"},
		lrec{uid: "has space", subject: "u-81", body: "bad uid"},
		lrec{uid: "e1", subject: "jo@example.com", body: "email subject"},
		lrec{uid: "e2", body: "no subject"},
		lrec{uid: "e3", subject: "u-81", body: strings.Repeat("x", 70<<10)},
	)
	code, resp, _ := post(t, rv, ld, false)
	ps := resp.PartialSuccess()
	if code != http.StatusOK || ps.RejectedLogRecords() != 6 {
		t.Fatalf("%d, rejected %d", code, ps.RejectedLogRecords())
	}
	if st := rv.totals(); st.committed != 1 || st.refused != 6 {
		t.Fatalf("totals = %+v", st)
	}
	msg := ps.ErrorMessage()
	for _, want := range []string{"proof refused 6 log records (not retried): ", "2: no " + uidAttr,
		"1: sink: invalid record: sink: subject is not valid", "1: no enduser.pseudo.id (a string attribute",
		"1: " + uidAttr + " is not printable",
		"1: sink: invalid record: content is "} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
	for _, secret := range []string{"jo@example.com", "has space", "xxxxxxxx", "no uid", "email subject"} {
		if strings.Contains(msg, secret) || strings.Contains(log.String(), secret) {
			t.Fatalf("a value leaked (%q): message %q, log %q", secret, msg, log.String())
		}
	}
	for i := 2; i <= 7; i++ {
		if !strings.Contains(log.String(), fmt.Sprintf("request 1, record %d: refused: ", i)) {
			t.Fatalf("record %d's refusal is not logged by position: %s", i, log.String())
		}
	}
}

// The subject is read from the log record first, then from its resource.
func TestReceive_SubjectFromResource(t *testing.T) {
	s := newSink(t)
	rv := newReceiver(s, opts(), io.Discard)
	ld := logsOf(lrec{uid: "r1", resSubject: "u-90", body: "from resource"},
		lrec{uid: "r2", subject: "u-91", resSubject: "Not-A-Pseudonym", body: "record wins"})
	if code, resp, _ := post(t, rv, ld, false); code != 200 || resp.PartialSuccess().RejectedLogRecords() != 0 {
		t.Fatalf("%d, rejected %d", code, resp.PartialSuccess().RejectedLogRecords())
	}
	subs, err := s.ChainSubjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, cs := range subs {
		got[cs.Subject] = true
	}
	if !got["u-90"] || !got["u-91"] || len(got) != 2 {
		t.Fatalf("subjects = %v", got)
	}
}

// The committed content is the record with its resource and scope, as OTLP
// JSON that any OTel tool reads back.
func TestContentOf(t *testing.T) {
	ld := logsOf(lrec{uid: "c1", subject: "u-81", body: "hello"})
	rl := ld.ResourceLogs().At(0)
	sl := rl.ScopeLogs().At(0)
	b, err := contentOf(rl, sl, sl.LogRecords().At(0))
	if err != nil {
		t.Fatal(err)
	}
	back, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(b)
	if err != nil || back.LogRecordCount() != 1 {
		t.Fatalf("does not read back: %v", err)
	}
	brl := back.ResourceLogs().At(0)
	if v, _ := brl.Resource().Attributes().Get("service.name"); v.Str() != "agent" {
		t.Fatal("resource lost")
	}
	if brl.ScopeLogs().At(0).Scope().Name() != "test" || brl.ScopeLogs().At(0).LogRecords().At(0).Body().Str() != "hello" {
		t.Fatal("scope or body lost")
	}
}

// failSink fails every record of one subject, committing the rest.
type failSink struct {
	inner *sink.Sink
	fail  string
}

func (f *failSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	if f.fail == "" {
		return f.inner.Commit(ctx, recs)
	}
	var ok []sink.Record
	var at []int
	for i, r := range recs {
		if r.Subject != f.fail {
			ok = append(ok, r)
			at = append(at, i)
		}
	}
	if len(ok) == len(recs) {
		return f.inner.Commit(ctx, recs)
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

// A sink failure answers 503 with Retry-After, so the collector retries the
// whole request. On the retry, what was committed is recognised.
func TestReceive_SinkFailureIsRetried(t *testing.T) {
	s := newSink(t)
	fs := &failSink{inner: s, fail: "u-99"}
	var log bytes.Buffer
	rv := newReceiver(fs, opts(), &log)
	ld := logsOf(lrec{uid: "f1", subject: "u-81", body: "a"}, lrec{uid: "f2", subject: "u-99", body: "b"})
	code, _, h := post(t, rv, ld, false)
	if code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
		t.Fatalf("%d, Retry-After %q", code, h.Get("Retry-After"))
	}
	if !strings.Contains(log.String(), "Answered 503") {
		t.Fatalf("log = %s", log.String())
	}
	fs.fail = ""
	if code, _, _ := post(t, rv, ld, false); code != http.StatusOK {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != 2 || st.duplicates != 1 {
		t.Fatalf("totals = %+v, want f1 then f2 committed once each, f1 recognised on retry", st)
	}
}

type errSink struct{ err error }

func (e errSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) { return nil, e.err }

type outcomeSink []sink.Outcome

func (o outcomeSink) Commit(context.Context, []sink.Record) ([]sink.Outcome, error) { return o, nil }

// Configuration and contract errors answer 503 and stop the receiver: every
// later request would fail the same way, and the collector keeps retrying
// until the operator fixes it. Later requests are answered 503 too.
func TestReceive_FatalErrors(t *testing.T) {
	cases := []struct {
		name string
		dst  committer
		code int
		want string
	}{
		{"signer required", errSink{sink.ErrRecordSignerRequired}, exitUsage, "not retried"},
		{"not signing", errSink{sink.ErrSinkNotSigning}, exitUsage, "unset " + recordKeyEnv},
		{"wrong count", outcomeSink{{Committed: true}}, exitFailed, "1 outcomes for 2 records"},
		{"no outcomes, no error", errSink{nil}, exitFailed, "0 outcomes for 2 records"},
		{"uncommitted, no error", outcomeSink{{Committed: true}, {}}, exitFailed, "uncommitted without an error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv := newReceiver(tc.dst, opts(), io.Discard)
			ld := logsOf(lrec{uid: "x1", subject: "u-81", body: "a"}, lrec{uid: "x2", subject: "u-82", body: "b"})
			if code, _, _ := post(t, rv, ld, false); code != http.StatusServiceUnavailable {
				t.Fatal(code)
			}
			select {
			case f := <-rv.fatal:
				if f.code != tc.code || !strings.Contains(f.err.Error(), tc.want) {
					t.Fatalf("fatal = %d %v", f.code, f.err)
				}
			default:
				t.Fatal("no fatal error raised")
			}
			// Even a request the sink could take is refused now.
			rv.dst = newSink(t)
			if code, _, _ := post(t, rv, ld, false); code != http.StatusServiceUnavailable {
				t.Fatalf("after a fatal error: %d", code)
			}
		})
	}
}

// The crash hook runs after a successful sink commit, before any answer; never
// after a failed one.
func TestReceive_CrashHook(t *testing.T) {
	o := opts()
	fired := 0
	o.afterCommit = func() { fired++ }
	rv := newReceiver(newSink(t), o, io.Discard)
	post(t, rv, logsOf(lrec{uid: "h1", subject: "u-81", body: "a"}), false)
	if fired != 1 {
		t.Fatalf("fired %d times", fired)
	}
	rv = newReceiver(errSink{errors.New("disk full")}, o, io.Discard)
	post(t, rv, logsOf(lrec{uid: "h2", subject: "u-81", body: "a"}), false)
	if fired != 1 {
		t.Fatal("fired after a failed commit")
	}
}

// cancellingSink cancels the request's context (the collector giving up),
// then commits with the context it was given.
type cancellingSink struct {
	inner  *sink.Sink
	cancel context.CancelFunc
}

func (c cancellingSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	c.cancel()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("commit cut off: %w", ctx.Err())
	}
	return c.inner.Commit(ctx, recs)
}

func protoRequest(t *testing.T, ctx context.Context, ld plog.Logs) *http.Request {
	t.Helper()
	b, err := plogotlp.NewExportRequestFromLogs(ld).MarshalProto()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(b)).WithContext(ctx)
	r.Header.Set("Content-Type", contentProto)
	return r
}

// A collector that gives up during the commit does not cut it off.
func TestReceive_ClientGoneDuringCommitStillCommits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rv := newReceiver(cancellingSink{inner: newSink(t), cancel: cancel}, opts(), io.Discard)
	w := httptest.NewRecorder()
	rv.ServeHTTP(w, protoRequest(t, ctx, logsOf(lrec{uid: "g1", subject: "u-81", body: "a"})))
	if w.Code != http.StatusOK || rv.totals().committed != 1 {
		t.Fatalf("%d, totals %+v", w.Code, rv.totals())
	}
}

// A request whose collector gave up while it waited its turn is not
// committed: nobody reads the answer, and the collector sends it again.
func TestReceive_ClientGoneBeforeItsTurnIsSkipped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newSink(t)
	rv := newReceiver(s, opts(), io.Discard)
	w := httptest.NewRecorder()
	rv.ServeHTTP(w, protoRequest(t, ctx, logsOf(lrec{uid: "g2", subject: "u-81", body: "a"})))
	if w.Code != http.StatusServiceUnavailable || rv.totals() != (stats{}) {
		t.Fatalf("%d, totals %+v", w.Code, rv.totals())
	}
	if _, err := os.Stat(s.DBPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the sink was written for a request nobody waits for (stat: %v)", err)
	}
}

// A request larger than sink.MaxBatch is several commits, answered once.
func TestReceive_LargeRequestIsChunked(t *testing.T) {
	s := newSink(t)
	rv := newReceiver(s, opts(), io.Discard)
	rs := make([]lrec, sink.MaxBatch+5)
	for i := range rs {
		rs[i] = lrec{uid: fmt.Sprintf("big-%d", i), subject: fmt.Sprintf("u-%d", i%3), body: "x"}
	}
	if code, _, _ := post(t, rv, logsOf(rs...), false); code != http.StatusOK {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != len(rs) {
		t.Fatalf("totals = %+v", st)
	}
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// What the collector sends by default: gzipped protobuf.
func TestReceive_Gzip(t *testing.T) {
	rv := newReceiver(newSink(t), opts(), io.Discard)
	b, _ := plogotlp.NewExportRequestFromLogs(logsOf(lrec{uid: "z1", subject: "u-81", body: "a"})).MarshalProto()
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(gz(t, b)))
	r.Header.Set("Content-Type", contentProto+"; charset=binary")
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	rv.ServeHTTP(w, r)
	if w.Code != http.StatusOK || rv.totals().committed != 1 {
		t.Fatalf("%d, totals %+v", w.Code, rv.totals())
	}
}

// Requests that are not OTLP logs get a permanent error, before any commit.
func TestReceive_BadRequests(t *testing.T) {
	bomb := gz(t, make([]byte, maxDecoded+1))
	cases := []struct {
		name, method, ct, enc string
		body                  []byte
		want                  int
	}{
		{"GET", http.MethodGet, contentProto, "", nil, http.StatusMethodNotAllowed},
		{"text", http.MethodPost, "text/plain", "", []byte("hi"), http.StatusUnsupportedMediaType},
		{"not protobuf", http.MethodPost, contentProto, "", []byte{0xff, 0xff, 0xff}, http.StatusBadRequest},
		{"not json", http.MethodPost, contentJSON, "", []byte("{"), http.StatusBadRequest},
		{"too large", http.MethodPost, contentProto, "", make([]byte, maxBody+1), http.StatusRequestEntityTooLarge},
		{"zip bomb", http.MethodPost, contentProto, "gzip", bomb, http.StatusRequestEntityTooLarge},
		{"bad gzip", http.MethodPost, contentProto, "gzip", []byte("nope"), http.StatusBadRequest},
		{"brotli", http.MethodPost, contentProto, "br", []byte("x"), http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv := newReceiver(errSink{errors.New("must not be called")}, opts(), io.Discard)
			r := httptest.NewRequest(tc.method, "/v1/logs", bytes.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.ct)
			if tc.enc != "" {
				r.Header.Set("Content-Encoding", tc.enc)
			}
			w := httptest.NewRecorder()
			rv.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("%d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	got := summary(3, map[string]int{"b": 1, "a": 2})
	if got != "proof refused 3 log records (not retried): 2: a; 1: b" {
		t.Fatalf("%q", got)
	}
}

func TestUIDPattern(t *testing.T) {
	ok := strings.Repeat("u", sink.MaxSourceBytes-len("otel:"))
	for _, s := range []string{"a", "01J9Z3K5M7N8P9Q0R1S2T3V4W5", "0f48f3c0-9e8e-4087-a1db-da39876988f2", ok} {
		if !uidPattern.MatchString(s) {
			t.Fatalf("%q refused", s)
		}
	}
	for _, s := range []string{"", "a b", "tab\t", "é", ok + "u", "line\n", "jo@example.com"} {
		if uidPattern.MatchString(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

// A small gzipped body can hold millions of empty records: over maxRecords
// is refused before any of them is built.
func TestReceive_RecordCap(t *testing.T) {
	rv := newReceiver(errSink{errors.New("must not be called")}, opts(), io.Discard)
	ld := plog.NewLogs()
	lrs := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for range maxRecords + 1 {
		lrs.AppendEmpty()
	}
	if code, _, _ := post(t, rv, ld, false); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d", code)
	}
}

// Refusal lines are capped per request; the counts are in the answer.
func TestReceive_RefusalLinesCapped(t *testing.T) {
	var log bytes.Buffer
	rv := newReceiver(newSink(t), opts(), &log)
	rs := make([]lrec, maxRefusalLines+5)
	for i := range rs {
		rs[i] = lrec{subject: "u-81", body: "no uid"}
	}
	code, resp, _ := post(t, rv, logsOf(rs...), false)
	if code != 200 || resp.PartialSuccess().RejectedLogRecords() != int64(len(rs)) {
		t.Fatalf("%d, rejected %d", code, resp.PartialSuccess().RejectedLogRecords())
	}
	if n := strings.Count(log.String(), ": refused: "); n != maxRefusalLines {
		t.Fatalf("%d refusal lines, want %d", n, maxRefusalLines)
	}
	if !strings.Contains(log.String(), "5 more refusals not listed") {
		t.Fatalf("log = %s", log.String())
	}
}

// pairSink fails one subject's records with a *sink.PairError, as the sink
// does for a subject whose stored state is broken (nothing committed), and
// commits otherwise.
type pairSink struct {
	inner *sink.Sink
	stuck string
	calls int
}

func (p *pairSink) Commit(ctx context.Context, recs []sink.Record) ([]sink.Outcome, error) {
	p.calls++
	var idx []int
	for i, r := range recs {
		if r.Subject == p.stuck {
			idx = append(idx, i)
		}
	}
	if len(idx) > 0 {
		return nil, &sink.PairError{Records: idx, Err: errors.New("index re-links an erased chain")}
	}
	return p.inner.Commit(ctx, recs)
}

// One stuck subject does not hold back the rest of the request: the rest is
// committed, and the request answered 503 so the stuck records are retried.
func TestReceive_PairErrorSetsOneSubjectAside(t *testing.T) {
	s := newSink(t)
	ps := &pairSink{inner: s, stuck: "u-99"}
	var log bytes.Buffer
	rv := newReceiver(ps, opts(), &log)
	ld := logsOf(lrec{uid: "p1", subject: "u-81", body: "a"}, lrec{uid: "p2", subject: "u-99", body: "b"},
		lrec{uid: "p3", subject: "u-82", body: "c"}, lrec{uid: "p4", subject: "u-99", body: "d"})
	if code, _, _ := post(t, rv, ld, false); code != http.StatusServiceUnavailable {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != 2 {
		t.Fatalf("totals = %+v, want the two other subjects committed", st)
	}
	if !strings.Contains(log.String(), "2 records could not be committed because of their subject's stored state") {
		t.Fatalf("log = %s", log.String())
	}
	if code, _, _ := post(t, rv, ld, false); code != http.StatusServiceUnavailable {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != 2 || st.duplicates != 2 {
		t.Fatalf("totals = %+v, want the rest recognised on retry", st)
	}
	ps.stuck = "" // repaired
	if code, _, _ := post(t, rv, ld, false); code != http.StatusOK {
		t.Fatal(code)
	}
	if n := entries(t, s); n != 4 {
		t.Fatalf("entries = %d", n)
	}
}

// A failure in a later chunk answers 503; the earlier chunk stays committed and
// is recognised on the retry.
func TestReceive_LaterChunkFails(t *testing.T) {
	s := newSink(t)
	fs := &failSink{inner: s, fail: "u-99"}
	rv := newReceiver(fs, opts(), io.Discard)
	rs := make([]lrec, sink.MaxBatch+2)
	for i := range rs {
		rs[i] = lrec{uid: fmt.Sprintf("c-%d", i), subject: "u-81", body: "x"}
	}
	rs[len(rs)-1].subject = "u-99" // in the second chunk
	if code, _, _ := post(t, rv, logsOf(rs...), false); code != http.StatusServiceUnavailable {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != sink.MaxBatch+1 {
		t.Fatalf("totals = %+v", st)
	}
	fs.fail = ""
	if code, _, _ := post(t, rv, logsOf(rs...), false); code != http.StatusOK {
		t.Fatal(code)
	}
	if st := rv.totals(); st.committed != sink.MaxBatch+2 || st.duplicates != sink.MaxBatch+1 {
		t.Fatalf("totals = %+v", st)
	}
}

// Refusals in a request answered 503 are not counted: the request comes back.
func TestReceive_RefusalsCountedOnce(t *testing.T) {
	fs := &failSink{inner: newSink(t), fail: "u-99"}
	rv := newReceiver(fs, opts(), io.Discard)
	ld := logsOf(lrec{subject: "u-81", body: "no uid"}, lrec{uid: "r1", subject: "u-99", body: "a"})
	post(t, rv, ld, false)
	fs.fail = ""
	post(t, rv, ld, false)
	if st := rv.totals(); st.refused != 1 {
		t.Fatalf("refused = %d, want 1", st.refused)
	}
}

// A JSON request gets a JSON answer, partial_success included.
func TestReceive_JSONPartialSuccess(t *testing.T) {
	rv := newReceiver(newSink(t), opts(), io.Discard)
	code, resp, _ := post(t, rv, logsOf(lrec{uid: "j1", subject: "u-81", body: "a"}, lrec{subject: "u-81", body: "b"}), true)
	if code != 200 || resp.PartialSuccess().RejectedLogRecords() != 1 ||
		!strings.Contains(resp.PartialSuccess().ErrorMessage(), "no "+uidAttr) {
		t.Fatalf("%d, %d %q", code, resp.PartialSuccess().RejectedLogRecords(), resp.PartialSuccess().ErrorMessage())
	}
}

// The subject attribute on the record wins; a non-string one there is a
// refusal, not a fall back to the resource (documented in the README).
func TestReceive_NonStringSubjectOnRecord(t *testing.T) {
	rv := newReceiver(newSink(t), opts(), io.Discard)
	ld := logsOf(lrec{uid: "n1", resSubject: "u-90", body: "a"})
	ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("enduser.pseudo.id", 7)
	code, resp, _ := post(t, rv, ld, false)
	if code != 200 || resp.PartialSuccess().RejectedLogRecords() != 1 {
		t.Fatalf("%d, rejected %d", code, resp.PartialSuccess().RejectedLogRecords())
	}
}

// The committed content carries the resource too, as JSON: a record well under
// 64 KiB on the wire can be over it as content, and is refused.
func TestReceive_ResourceCountsTowardsContentLimit(t *testing.T) {
	rv := newReceiver(newSink(t), opts(), io.Discard)
	ld := logsOf(lrec{uid: "big", subject: "u-81", body: strings.Repeat("b", 40<<10)})
	ld.ResourceLogs().At(0).Resource().Attributes().PutStr("k8s.pod.labels", strings.Repeat("l", 30<<10))
	code, resp, _ := post(t, rv, ld, false)
	if code != 200 || !strings.Contains(resp.PartialSuccess().ErrorMessage(), "content is ") {
		t.Fatalf("%d, %q", code, resp.PartialSuccess().ErrorMessage())
	}
}

// Concurrent requests (the collector's queue sends several at once) are each
// committed once and answered; the totals add up. Run with -race.
func TestReceive_Concurrent(t *testing.T) {
	s := newSink(t)
	rv := newReceiver(s, opts(), io.Discard)
	const n = 8
	done := make(chan int, n)
	for i := range n {
		go func() {
			ld := logsOf(lrec{uid: fmt.Sprintf("k%d-a", i), subject: fmt.Sprintf("u-%d", i), body: "a"},
				lrec{uid: fmt.Sprintf("k%d-b", i), subject: "u-shared", body: "b"})
			b, _ := plogotlp.NewExportRequestFromLogs(ld).MarshalProto()
			r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(b))
			r.Header.Set("Content-Type", contentProto)
			w := httptest.NewRecorder()
			rv.ServeHTTP(w, r)
			done <- w.Code
		}()
	}
	for range n {
		if code := <-done; code != 200 {
			t.Fatal(code)
		}
	}
	if st := rv.totals(); st.committed != 2*n {
		t.Fatalf("totals = %+v", st)
	}
	if e := entries(t, s); e != 2*n {
		t.Fatalf("entries = %d", e)
	}
}
