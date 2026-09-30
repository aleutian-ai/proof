// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aleutian-ai/proof/sink"
)

// message is the part of a JetStream message the consumer uses. The real one
// wraps jetstream.Msg; tests use a fake, so no server is needed.
type message interface {
	Subject() string
	Data() []byte
	// Position names where the message sits: the stream, which INCARNATION of
	// it (its creation time), and the sequence, e.g. "EVIDENCE@1727550000000000000:42".
	// It is the record's sink Source, which makes redelivery idempotent.
	// The creation time matters: a deleted and recreated stream restarts at
	// sequence 1, and without it a new message would look like an old one and
	// be dropped as a duplicate.
	Position() (string, error)
	Ack() error
	Nak() error
	Term() error
}

// committer is the part of sink.Sink the consumer uses.
type committer interface {
	Commit(ctx context.Context, records []sink.Record) ([]sink.Outcome, error)
}

// router turns a NATS subject into the record's subject (the pseudonym the
// sink files the message under; the sink maps it to an opaque chain).
//
// The NATS subject must be exactly <prefix>.<key>: one token after the prefix,
// no more. NATS splits subjects on '.', so "evidence.jo@example.com" arrives as
// three tokens. Taking the last would file it under "com". Refusing every other
// shape means a key is used whole or not at all.
type router struct {
	prefix string
	class  string // the evidence class every message is committed under
}

func (r router) subject(natsSubject string) (string, bool) {
	key, ok := strings.CutPrefix(natsSubject, r.prefix+".")
	if !ok || key == "" || strings.Contains(key, ".") {
		return "", false
	}
	return key, sink.ValidSubject(key)
}

// stats is what one batch did.
type stats struct {
	committed  int // new entries on a chain
	duplicates int // already committed: a redelivery, acked and not re-committed
	refused    int // bad subject, payload or position: terminated, never redelivered
}

// processBatch commits a batch of messages, then acknowledges them.
//
// # Description
//
// The order is the point of the example:
//
//  1. Route every message. A message whose subject is not <prefix>.<valid key>,
//     whose payload is empty or too large, or that has no stream position, is
//     TERMINATED: redelivering it would loop forever, and acking it would
//     lose it without a trace. It is logged by stream position, NEVER by subject,
//     since a refused key is often the personal data the rule keeps out.
//  2. Commit the rest through sink, one atomic append per chain, each
//     record carrying its stream position as its Source.
//  3. Only then acknowledge them. A crash before this point means redelivery,
//     and redelivered positions are recognised as already committed.
//
// If a chain's commit fails, its messages are NAKed (redelivered later) and
// processBatch returns the error. Messages of chains committed before it are
// acked: their commits stand.
//
// # Inputs
//
//   - ctx: passed to Commit
//   - dst: where records are committed (a *sink.Sink in production)
//   - r: the subject router
//   - msgs: one fetched batch, at most sink.MaxBatch
//   - afterCommit: called between commit and ack; the demo's crash hook. nil
//     for none.
//   - log: operator log; receives stream positions and counts, never subjects
//     or content. (A returned commit error may name a chain id, which is
//     opaque.)
//
// # Outputs
//
//   - stats: what happened
//   - error: a commit failed; the caller should stop
func processBatch(ctx context.Context, dst committer, r router, msgs []message,
	afterCommit func(), log io.Writer) (stats, error) {
	var st stats
	var recs []sink.Record
	var pending []message // pending[i] is the message of recs[i]

	for _, m := range msgs {
		pos, err := m.Position()
		if err != nil {
			// Without a position the record cannot be made idempotent, and a
			// message that has none will not grow one on redelivery. Terminate it.
			fmt.Fprintf(log, "no stream position (%v): terminated\n", err)
			_ = m.Term()
			st.refused++
			continue
		}
		subject, ok := r.subject(m.Subject())
		if !ok {
			fmt.Fprintf(log, "refused %s: the NATS subject is not %s.<key> with a valid key "+
				"(lowercase letters, digits, . _ -, max 128; no dots in NATS). Terminated.\n", pos, r.prefix)
			_ = m.Term()
			st.refused++
			continue
		}
		// Validated here with the sink's own rule, not left to Commit: Commit
		// refuses a whole batch for one bad record, and a message that can never
		// be committed would come back forever and stall every message behind it.
		// (The error never contains the key or the payload.)
		rec := sink.Record{Class: r.class, Subject: subject, Content: m.Data(), Source: pos}
		if err := rec.Validate(); err != nil {
			fmt.Fprintf(log, "refused %s: %v. Terminated.\n", pos, err)
			_ = m.Term()
			st.refused++
			continue
		}
		recs = append(recs, rec)
		pending = append(pending, m)
	}
	if len(recs) == 0 {
		return st, nil
	}

	out, err := dst.Commit(ctx, recs)
	if out != nil && len(out) != len(recs) {
		// Not the one-per-record contract: nothing can be matched to a message,
		// so nothing is acked; everything is redelivered and recognised.
		err = errors.Join(err, fmt.Errorf("the sink returned %d outcomes for %d records", len(out), len(recs)))
		out = nil
	}
	// One outcome per record, in order: message i is acked exactly when record
	// i is on its chain, and NAKed (redelivered later) otherwise. Nothing is
	// matched by subject.
	committed := 0
	for _, o := range out {
		if o.Committed {
			committed++
		}
	}
	if afterCommit != nil && committed > 0 {
		afterCommit()
	}
	for i, m := range pending {
		if out == nil || !out[i].Committed {
			_ = m.Nak()
			continue
		}
		if out[i].Duplicate {
			st.duplicates++
		} else {
			st.committed++
		}
		// An ack that fails is not lost evidence: the message comes back and
		// is recognised as a duplicate.
		if aerr := m.Ack(); aerr != nil {
			fmt.Fprintf(log, "ack failed (%v): it will be redelivered and recognised\n", aerr)
		}
	}
	if err != nil {
		return st, fmt.Errorf("commit: %w", err)
	}
	return st, nil
}
