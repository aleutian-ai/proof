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
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"github.com/aleutian-ai/proof/sink"
)

const (
	// uidAttr is the stable delivery id each record must carry: the record's
	// sink Source. OTel's semantic conventions define it (opt-in); proof
	// requires it, because OTLP itself has no delivery position.
	uidAttr = "log.record.uid"

	maxBody    = 16 << 20 // compressed request body
	maxDecoded = 64 << 20 // after gzip: a zip bomb is refused, not inflated
	// maxRecords caps the log records in one request: a small gzipped body of
	// empty records would otherwise decode into millions of them. The
	// collector config sends at most 500 per request.
	maxRecords = 10 * sink.MaxBatch
	// maxRefusalLines caps the per-record refusal lines logged per request;
	// the counts by reason are in the answer either way.
	maxRefusalLines = 10
	commitTimeout   = 30 * time.Second // the collector's exporter timeout is longer (collector.yaml)
	retryAfterSecs  = "5"

	contentProto = "application/x-protobuf"
	contentJSON  = "application/json"
)

// uidPattern is what a usable uid looks like: printable ASCII, no spaces, no
// "@" (an email is not a delivery id, and the Source is kept until erasure),
// and short enough that "otel:" + uid fits the sink's Source limit.
var uidPattern = regexp.MustCompile(`^[\x21-\x3f\x41-\x7e]{1,` + fmt.Sprint(sink.MaxSourceBytes-len("otel:")) + `}$`)

// committer is the part of sink.Sink the receiver uses.
type committer interface {
	Commit(ctx context.Context, records []sink.Record) ([]sink.Outcome, error)
}

// stats is what the receiver did.
type stats struct {
	committed  int // new entries on a chain
	duplicates int // already committed (a retried request): answered 200, not re-committed
	refused    int // no usable uid, bad subject or content: counted in partial_success, never retried
}

// options configure the receiver.
type options struct {
	class       string // the evidence class every record is committed under
	subjectAttr string // the attribute holding the subject
	afterCommit func() // the demo's crash hook; nil for none
}

// fatalError stops the receiver: every later request would fail the same way.
type fatalError struct {
	err  error
	code int
}

func (f fatalError) Error() string { return f.err.Error() }
func (f fatalError) Unwrap() error { return f.err }

// receiver is the OTLP/HTTP logs endpoint. Safe for concurrent use: requests
// are decoded concurrently and committed one at a time.
type receiver struct {
	dst   committer
	o     options
	log   io.Writer
	fatal chan fatalError // the first fatal error; main stops the server

	mu    sync.Mutex // serialises commits, the log and the totals
	reqs  int
	total stats
	dead  bool // a fatal error happened: answer 503 to everything after it
}

func newReceiver(dst committer, o options, log io.Writer) *receiver {
	return &receiver{dst: dst, o: o, log: log, fatal: make(chan fatalError, 1)}
}

func (rv *receiver) totals() stats {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	return rv.total
}

// ServeHTTP handles POST /v1/logs.
//
// # Description
//
// The answer follows the sink commit, never precedes it:
//
//   - 200: every record committed (new or already) or refused. Refusals are
//     counted in partial_success, which the collector does not retry.
//   - 503 + Retry-After: the sink failed on a record. The collector retries
//     the whole request; what was committed comes back as already committed.
//   - 503, then the receiver stops: a configuration error (the sink's signing
//     mode against this receiver's key) or a sink breaking its contract.
//     Every later request would fail too, and the collector keeps retrying
//     until the operator fixes it.
//   - 400 / 413 / 415: a request that is not OTLP logs, too large, or of an
//     unsupported content type or encoding. The collector drops it.
//
// The request context is not used for the commit: a collector that gives up
// waiting does not cut a commit off half done.
func (rv *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ct := mediaType(r.Header.Get("Content-Type"))
	if ct != contentProto && ct != contentJSON {
		http.Error(w, "Content-Type must be "+contentProto+" or "+contentJSON, http.StatusUnsupportedMediaType)
		return
	}
	body, status, err := readBody(w, r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	req := plogotlp.NewExportRequest()
	if ct == contentJSON {
		err = req.UnmarshalJSON(body)
	} else {
		err = req.UnmarshalProto(body)
	}
	if err != nil {
		http.Error(w, "not an OTLP logs request", http.StatusBadRequest)
		return
	}
	if n := req.Logs().LogRecordCount(); n > maxRecords {
		http.Error(w, fmt.Sprintf("over %d log records in one request", maxRecords), http.StatusRequestEntityTooLarge)
		return
	}

	rv.mu.Lock()
	defer rv.mu.Unlock()
	if rv.dead {
		unavailable(w)
		return
	}
	// The collector gave up while this request waited its turn: nobody reads
	// the answer, and the collector sends it again. Committing it now would
	// only hold its memory and the lock for nothing.
	if r.Context().Err() != nil {
		unavailable(w)
		return
	}
	rv.reqs++
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), commitTimeout)
	defer cancel()
	st, reasons, err := rv.process(ctx, rv.reqs, req.Logs())
	rv.total.committed += st.committed
	rv.total.duplicates += st.duplicates
	var fe fatalError
	switch {
	case errors.As(err, &fe):
		rv.dead = true
		select {
		case rv.fatal <- fe:
		default:
		}
		unavailable(w)
		return
	case err != nil:
		fmt.Fprintf(rv.log, "request %d: %v. Answered 503: the collector retries it.\n", rv.reqs, err)
		unavailable(w)
		return
	}
	// Refusals count once, when answered: a request answered 503 comes back.
	rv.total.refused += st.refused
	fmt.Fprintf(rv.log, "request %d: committed %d · already committed %d · refused %d\n",
		rv.reqs, st.committed, st.duplicates, st.refused)
	rv.answer(w, ct, st.refused, reasons)
}

// process turns one request into records, commits them, and reports.
//
// Refused records are logged by request and index (the first
// maxRefusalLines of them), never by an attribute value. reasons counts
// refusals by reason, for partial_success.
func (rv *receiver) process(ctx context.Context, reqNo int, ld plog.Logs) (stats, map[string]int, error) {
	var st stats
	reasons := map[string]int{}
	var recs []sink.Record
	idx := 0
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			sl := sls.At(j)
			lrs := sl.LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				idx++
				rec, reason := rv.record(rl, sl, lrs.At(k))
				if reason != "" {
					if st.refused < maxRefusalLines {
						fmt.Fprintf(rv.log, "request %d, record %d: refused: %s\n", reqNo, idx, reason)
					}
					reasons[reason]++
					st.refused++
					continue
				}
				recs = append(recs, rec)
			}
		}
	}

	if st.refused > maxRefusalLines {
		fmt.Fprintf(rv.log, "request %d: %d more refusals not listed (counted in the answer)\n",
			reqNo, st.refused-maxRefusalLines)
	}
	for chunk := range slices.Chunk(recs, sink.MaxBatch) {
		cst, err := rv.commitChunk(ctx, chunk)
		st.committed += cst.committed
		st.duplicates += cst.duplicates
		if err != nil {
			return st, nil, err
		}
		if rv.o.afterCommit != nil {
			rv.o.afterCommit()
		}
	}
	return st, reasons, nil
}

// commitChunk commits up to sink.MaxBatch records.
//
// A *sink.PairError means one subject's own stored state failed and nothing
// was committed. Its records are set aside and the rest committed, so one
// stuck subject does not hold every other record of the request back until
// the collector gives up. The request is still answered 503: the collector
// retries it, the rest come back as already committed, and the stuck subject
// keeps failing (loudly) until the operator repairs it.
func (rv *receiver) commitChunk(ctx context.Context, chunk []sink.Record) (stats, error) {
	var st stats
	live := chunk
	var asideErr error
	aside := 0
	for {
		out, err := rv.dst.Commit(ctx, live)
		if errors.Is(err, sink.ErrRecordSignerRequired) || errors.Is(err, sink.ErrSinkNotSigning) {
			return st, fatalError{err: configurationError(err), code: exitUsage}
		}
		if len(out) != len(live) && (out != nil || err == nil) {
			return st, fatalError{code: exitFailed,
				err: fmt.Errorf("the sink returned %d outcomes for %d records: contract error", len(out), len(live))}
		}
		if err == nil && slices.ContainsFunc(out, func(oc sink.Outcome) bool { return !oc.Committed }) {
			return st, fatalError{code: exitFailed,
				err: errors.New("the sink left a record uncommitted without an error: contract error")}
		}
		var pe *sink.PairError
		if errors.As(err, &pe) && len(pe.Records) < len(live) {
			asideErr = err
			aside += len(pe.Records)
			live = without(live, pe.Records)
			continue
		}
		for _, oc := range out {
			switch {
			case oc.Duplicate:
				st.duplicates++
			case oc.Committed:
				st.committed++
			}
		}
		switch {
		case err != nil:
			return st, fmt.Errorf("commit: %w", err)
		case asideErr != nil:
			return st, fmt.Errorf("%d records could not be committed because of their subject's stored "+
				"state (run proof sink verify); the rest were committed: %w", aside, asideErr)
		}
		return st, nil
	}
}

// without returns recs minus the given indexes.
func without(recs []sink.Record, drop []int) []sink.Record {
	skip := make(map[int]bool, len(drop))
	for _, i := range drop {
		skip[i] = true
	}
	out := make([]sink.Record, 0, len(recs))
	for i, r := range recs {
		if !skip[i] {
			out = append(out, r)
		}
	}
	return out
}

// record builds the sink record for one log record, or says why it is refused.
// Reasons never contain a value from the record.
func (rv *receiver) record(rl plog.ResourceLogs, sl plog.ScopeLogs, lr plog.LogRecord) (sink.Record, string) {
	uid, ok := stringAttr(lr, rl, uidAttr, false)
	if !ok {
		return sink.Record{}, "no " + uidAttr + " (a string attribute on the log record)"
	}
	if !uidPattern.MatchString(uid) {
		return sink.Record{}, uidAttr + " is not printable ASCII without spaces, or too long"
	}
	subject, ok := stringAttr(lr, rl, rv.o.subjectAttr, true)
	if !ok {
		return sink.Record{}, "no " + rv.o.subjectAttr + " (a string attribute on the log record or its resource)"
	}
	content, err := contentOf(rl, sl, lr)
	if err != nil {
		return sink.Record{}, "the record could not be encoded"
	}
	rec := sink.Record{Class: rv.o.class, Subject: subject, Content: content, Source: "otel:" + uid}
	if err := rec.Validate(); err != nil {
		return sink.Record{}, err.Error() // never contains the subject or the content
	}
	return rec, ""
}

// stringAttr reads a string attribute from the log record, or else (when
// orResource) from its resource. Anything that is not a string is absent.
func stringAttr(lr plog.LogRecord, rl plog.ResourceLogs, key string, orResource bool) (string, bool) {
	if v, ok := lr.Attributes().Get(key); ok {
		return v.Str(), v.Type() == pcommon.ValueTypeStr
	}
	if orResource {
		if v, ok := rl.Resource().Attributes().Get(key); ok {
			return v.Str(), v.Type() == pcommon.ValueTypeStr
		}
	}
	return "", false
}

// contentOf is the committed bytes: the log record with its resource and
// scope, as a one-record OTLP JSON export request, readable by any OTel tool.
func contentOf(rl plog.ResourceLogs, sl plog.ScopeLogs, lr plog.LogRecord) ([]byte, error) {
	ld := plog.NewLogs()
	nrl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().CopyTo(nrl.Resource())
	nrl.SetSchemaUrl(rl.SchemaUrl())
	nsl := nrl.ScopeLogs().AppendEmpty()
	sl.Scope().CopyTo(nsl.Scope())
	nsl.SetSchemaUrl(sl.SchemaUrl())
	lr.CopyTo(nsl.LogRecords().AppendEmpty())
	return (&plog.JSONMarshaler{}).MarshalLogs(ld)
}

// answer writes 200, in the request's encoding, with partial_success when any
// record was refused.
func (rv *receiver) answer(w http.ResponseWriter, ct string, refused int, reasons map[string]int) {
	resp := plogotlp.NewExportResponse()
	if refused > 0 {
		ps := resp.PartialSuccess()
		ps.SetRejectedLogRecords(int64(refused))
		ps.SetErrorMessage(summary(refused, reasons))
	}
	var b []byte
	var err error
	if ct == contentJSON {
		b, err = resp.MarshalJSON()
	} else {
		b, err = resp.MarshalProto()
	}
	if err != nil { // committed already; an empty 200 is still a success
		b = nil
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// summary is partial_success's message: counts by reason, most common first.
func summary(refused int, reasons map[string]int) string {
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d: %s", reasons[k], k)
	}
	return fmt.Sprintf("proof refused %d log records (not retried): %s", refused, strings.Join(parts, "; "))
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", retryAfterSecs)
	http.Error(w, "the evidence sink did not commit; retry", http.StatusServiceUnavailable)
}

// readBody reads the request body within the size limits, gunzipping it if
// needed. It returns the HTTP status to answer with on error.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, int, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("body over %d bytes", maxBody)
		}
		return nil, http.StatusBadRequest, errors.New("could not read the body")
	}
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		return raw, 0, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("not gzip")
		}
		b, err := io.ReadAll(io.LimitReader(zr, maxDecoded+1))
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("bad gzip")
		}
		if len(b) > maxDecoded {
			return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("body over %d bytes decompressed", maxDecoded)
		}
		return b, 0, nil
	default:
		return nil, http.StatusUnsupportedMediaType, errors.New("Content-Encoding must be gzip or none")
	}
}

// mediaType is a Content-Type without its parameters, lowercased.
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
