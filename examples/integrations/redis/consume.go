// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aleutian-ai/proof/sink"
)

// entry is one stream entry, as the consumer needs it.
type entry struct {
	id   string // the stream entry id, e.g. "1727550000000-0"
	key  string // the "key" field; empty if absent
	data []byte // the "data" field; empty if absent
	// gone is set when the entry has no fields at all: Redis returns a pending
	// entry that was deleted from the stream (XDEL, trimming) this way.
	gone bool
}

// streamClient is the part of a Redis (or Valkey) consumer group the consumer
// uses. The real one wraps go-redis; tests use an in-memory fake with the same
// pending-list semantics, so no server is needed.
type streamClient interface {
	// readGroup is XREADGROUP for this consumer: id "0" returns its own
	// pending entries, ">" returns new ones. block < 0 means do not block.
	readGroup(ctx context.Context, id string, count int, block time.Duration) ([]entry, error)
	// autoClaim is XAUTOCLAIM: take over entries pending on ANY consumer for
	// longer than minIdle. It returns the cursor for the next call ("0-0" means
	// done) and the ids of pending entries that no longer exist in the stream,
	// which Redis has just dropped from the pending list.
	autoClaim(ctx context.Context, minIdle time.Duration, start string, count int) ([]entry, string, []string, error)
	// ack is XACK. It removes entries from the pending list, NOT from the stream.
	ack(ctx context.Context, ids ...string) error
}

// committer is the part of sink.Sink the consumer uses.
type committer interface {
	Commit(ctx context.Context, records []sink.Record) ([]sink.Outcome, error)
}

// stats is what the consumer did.
type stats struct {
	committed  int // new entries on a chain
	duplicates int // already committed (a pending entry from before a crash): acked, not re-committed
	refused    int // bad key or data: acked and logged, left in the stream, not committed
	recovered  int // entries read from a pending list: this consumer's own, or claimed
	vanished   int // pending entries deleted from the stream before anyone committed them
}

func (s *stats) add(o stats) {
	s.committed += o.committed
	s.duplicates += o.duplicates
	s.refused += o.refused
	s.recovered += o.recovered
	s.vanished += o.vanished
}

// options configure consume.
type options struct {
	stream string
	class  string // the evidence class every entry is committed under
	// sourcePrefix begins every record's sink Source: "<stream>@<incarnation>".
	// The incarnation changes whenever the consumer group is created afresh,
	// which is also when a deleted stream comes back. Entry ids restart then,
	// and without it a new entry could be taken for an old one and dropped.
	sourcePrefix string
	batch        int
	claimIdle    time.Duration
	follow       bool
	afterCommit  func() // the demo's crash hook; nil for none
}

// consume recovers pending entries, then reads new ones, committing each batch
// before acknowledging it.
//
// # Description
//
// Redis does not redeliver. An entry read but never acknowledged stays in the
// group's pending list until a consumer asks for it, however long that takes.
// So, before anything new:
//
//  1. This consumer's own pending entries (XREADGROUP … 0): what it had read
//     when it last stopped.
//  2. Entries pending on ANY consumer for longer than claimIdle (XAUTOCLAIM).
//     Their consumer is probably gone, and nobody else will ever read them.
//
// Then new entries (XREADGROUP … >) until the stream is drained, or until the
// context ends with follow.
//
// Recovered entries were possibly committed already (a crash between commit
// and ack). Each record's Source is "<stream>@<incarnation>:<entry id>", so sink
// recognises those and they are acked without being committed twice.
//
// # Outputs
//
//   - stats: totals, also when an error stops the run
//   - error: a read, commit or ack failed. Unacked entries stay pending and are
//     recovered on the next run.
func consume(ctx context.Context, c streamClient, dst committer, o options, log io.Writer) (stats, error) {
	var total stats

	// 1. Own pending entries. Each pass acks what it read, so the list shrinks.
	// If it does not (a pass acked nothing), stop: re-reading the same entries
	// forever would spin without end.
	lastFirst := ""
	for {
		es, err := c.readGroup(ctx, "0", o.batch, -1)
		if err != nil {
			return total, stopped(ctx, fmt.Errorf("read pending: %w", err))
		}
		if len(es) == 0 {
			break
		}
		if es[0].id == lastFirst {
			return total, fmt.Errorf("pending entry %s:%s was read again without being "+
				"acknowledged; stopping rather than looping", o.stream, lastFirst)
		}
		lastFirst = es[0].id
		st, err := processBatch(ctx, c, dst, o, es, log)
		st.recovered = len(es)
		total.add(st)
		if err != nil {
			return total, err
		}
	}

	// 2. Entries a dead consumer left behind.
	st, err := claim(ctx, c, dst, o, log)
	total.add(st)
	if err != nil {
		return total, err
	}
	lastClaim := time.Now()

	// 3. New entries. With follow, keep claiming too: a peer can die at any
	// time, not only before this consumer started.
	block := time.Duration(-1)
	if o.follow {
		block = time.Second
	}
	for ctx.Err() == nil {
		if o.follow && time.Since(lastClaim) >= o.claimIdle {
			st, err := claim(ctx, c, dst, o, log)
			total.add(st)
			if err != nil {
				return total, err
			}
			lastClaim = time.Now()
		}
		es, err := c.readGroup(ctx, ">", o.batch, block)
		if err != nil {
			return total, stopped(ctx, fmt.Errorf("read: %w", err))
		}
		if len(es) == 0 {
			if o.follow {
				continue
			}
			break
		}
		st, err := processBatch(ctx, c, dst, o, es, log)
		total.add(st)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// claim runs XAUTOCLAIM to the end of the pending list, committing what it
// takes over. Pending entries that were deleted from the stream are reported:
// Redis drops them from the pending list, so this is their last trace.
func claim(ctx context.Context, c streamClient, dst committer, o options, log io.Writer) (stats, error) {
	var total stats
	for cursor := "0-0"; ; {
		es, next, deleted, err := c.autoClaim(ctx, o.claimIdle, cursor, o.batch)
		if err != nil {
			return total, stopped(ctx, fmt.Errorf("claim: %w", err))
		}
		for _, id := range deleted {
			fmt.Fprintf(log, "lost %s:%s: it was deleted from the stream while pending, before any "+
				"consumer acknowledged it. If it was not committed before, it never will be.\n", o.stream, id)
		}
		total.vanished += len(deleted)
		if len(es) > 0 {
			st, err := processBatch(ctx, c, dst, o, es, log)
			st.recovered = len(es)
			total.add(st)
			if err != nil {
				return total, err
			}
		}
		if next == "0-0" || next == "" {
			return total, nil
		}
		cursor = next
	}
}

// stopped turns an error caused by the caller stopping us (Ctrl-C with
// -follow) into a clean stop.
func stopped(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// processBatch commits one batch of entries, then acknowledges them.
//
// # Description
//
//  1. Refuse what can never be committed (a key that is not a valid subject;
//     empty or oversized data) and ack it at once, logged by entry id, never by
//     key. Acking does not delete: the entry stays in the stream, just not on
//     a chain. Leaving it pending would re-read it on every recovery forever.
//  2. Commit the rest through sink, each with Source "<stream>@<incarnation>:<id>".
//  3. Then ack them. For a chain whose commit failed, nothing is acked: those
//     entries stay pending and are recovered next run.
//
// A commit failure stops the run, deliberately. It usually means the sink
// folder itself is broken, and committing other chains past it would only hide
// that. The failed entries stay pending, so nothing is lost; the next run
// retries them first.
func processBatch(ctx context.Context, c streamClient, dst committer, o options, es []entry,
	log io.Writer) (stats, error) {
	var st stats
	var refused []string
	var recs []sink.Record
	var ids []string // ids[i] is the stream entry of recs[i]

	for _, e := range es {
		pos := o.stream + ":" + e.id // for the operator's log
		if e.gone {
			fmt.Fprintf(log, "lost %s: it was deleted from the stream while pending. If it was "+
				"not committed before, it never will be. Acked.\n", pos)
			st.vanished++
			refused = append(refused, e.id)
			continue
		}
		// The sink's own rule, applied here so one bad entry never fails (and
		// stalls) its whole batch. The error never contains the key or the data.
		rec := sink.Record{Class: o.class, Subject: e.key, Content: e.data, Source: o.sourcePrefix + ":" + e.id}
		if err := rec.Validate(); err != nil {
			fmt.Fprintf(log, "refused %s: %v. Acked; it stays in the stream.\n", pos, err)
			refused = append(refused, e.id)
			continue
		}
		recs = append(recs, rec)
		ids = append(ids, e.id)
	}
	if len(refused) > 0 {
		if err := c.ack(ctx, refused...); err != nil {
			return st, fmt.Errorf("ack refused entries: %w", err)
		}
		st.refused = len(refused) - st.vanished
	}
	if len(recs) == 0 {
		return st, nil
	}

	out, err := dst.Commit(ctx, recs)
	if out != nil && len(out) != len(recs) {
		// Not the one-per-record contract: nothing can be matched to an entry,
		// so nothing is acked; the entries stay pending and are recovered.
		err = errors.Join(err, fmt.Errorf("the sink returned %d outcomes for %d records", len(out), len(recs)))
		out = nil
	}
	// One outcome per record, in order: entry i is acked exactly when record i
	// is on its chain. Nothing is matched by subject.
	var ack []string
	for i, oc := range out {
		if !oc.Committed {
			continue
		}
		if oc.Duplicate {
			st.duplicates++
		} else {
			st.committed++
		}
		ack = append(ack, ids[i])
	}
	if o.afterCommit != nil && len(ack) > 0 {
		o.afterCommit()
	}
	if len(ack) > 0 {
		if aerr := c.ack(ctx, ack...); aerr != nil {
			// Committed but not acked: they stay pending, and the next run
			// recovers them and recognises them as committed.
			return st, fmt.Errorf("committed, but ack failed (they will be recovered and "+
				"recognised next run): %w", aerr)
		}
	}
	if err != nil {
		return st, fmt.Errorf("commit: %w", err)
	}
	return st, nil
}

// maxEntryID is the longest Redis stream entry id: two uint64s and a dash.
const maxEntryID = len("18446744073709551615-18446744073709551615")

// sourceFits refuses a configuration in which some positions would be longer
// than the sink accepts. Checked at start-up: otherwise EVERY entry would be
// refused one by one, which is silent loss by misconfiguration.
func sourceFits(sourcePrefix string) error {
	if n := len(sourcePrefix) + 1 + maxEntryID; n > sink.MaxSourceBytes {
		return fmt.Errorf("the stream name is too long: positions would be up to %d bytes, "+
			"over the sink's %d byte limit", n, sink.MaxSourceBytes)
	}
	return nil
}
