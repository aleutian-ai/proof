// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aleutian-ai/proof/examples/integrations/topicsink"
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

// committer is the part of topicsink.Sink the consumer uses.
type committer interface {
	Commit(ctx context.Context, records []topicsink.Record) ([]topicsink.Committed, error)
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
	// sourcePrefix begins every record's topicsink Source: "<stream>@<incarnation>".
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
// and ack). Each record's Source is "<stream>:<entry id>", so topicsink
// recognises those and they are acked without being committed twice.
//
// # Outputs
//
//   - stats: totals, also when an error stops the run
//   - error: a read, commit or ack failed. Unacked entries stay pending and are
//     recovered on the next run.
func consume(ctx context.Context, c streamClient, sink committer, o options, log io.Writer) (stats, error) {
	var total stats

	// 1. Own pending entries. Each pass acks what it read, so the list shrinks.
	for {
		es, err := c.readGroup(ctx, "0", o.batch, -1)
		if err != nil {
			return total, stopped(ctx, fmt.Errorf("read pending: %w", err))
		}
		if len(es) == 0 {
			break
		}
		st, err := processBatch(ctx, c, sink, o, es, log)
		st.recovered = len(es)
		total.add(st)
		if err != nil {
			return total, err
		}
	}

	// 2. Entries a dead consumer left behind.
	st, err := claim(ctx, c, sink, o, log)
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
			st, err := claim(ctx, c, sink, o, log)
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
		st, err := processBatch(ctx, c, sink, o, es, log)
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
func claim(ctx context.Context, c streamClient, sink committer, o options, log io.Writer) (stats, error) {
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
			st, err := processBatch(ctx, c, sink, o, es, log)
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
//  1. Refuse what can never be committed (a key that is not a valid chain id;
//     empty or oversized data) and ack it at once, logged by entry id, never by
//     key. Acking does not delete: the entry stays in the stream, just not on
//     a chain. Leaving it pending would re-read it on every recovery forever.
//  2. Commit the rest through topicsink, each with Source "<stream>:<id>".
//  3. Then ack them. For a chain whose commit failed, nothing is acked: those
//     entries stay pending and are recovered next run.
//
// A commit failure stops the run, deliberately. It usually means the sink
// folder itself is broken, and committing other chains past it would only hide
// that. The failed entries stay pending, so nothing is lost; the next run
// retries them first.
func processBatch(ctx context.Context, c streamClient, sink committer, o options, es []entry,
	log io.Writer) (stats, error) {
	var st stats
	var refused []string
	var recs []topicsink.Record
	idsByChain := map[string][]string{}

	for _, e := range es {
		pos := o.stream + ":" + e.id // for the operator's log
		chain, err := topicsink.ChainFor(e.key)
		switch {
		case e.gone:
			fmt.Fprintf(log, "lost %s: it was deleted from the stream while pending. If it was "+
				"not committed before, it never will be. Acked.\n", pos)
			st.vanished++
			refused = append(refused, e.id)
			continue
		case err != nil:
			fmt.Fprintf(log, "refused %s: its key is not a valid chain id (lowercase letters, "+
				"digits, . _ -, max 64). Acked; it stays in the stream.\n", pos)
		case len(e.data) == 0 || len(e.data) > topicsink.MaxContentBytes:
			fmt.Fprintf(log, "refused %s: its data is %d bytes; it must be 1 to %d. Acked; it "+
				"stays in the stream.\n", pos, len(e.data), topicsink.MaxContentBytes)
		default:
			recs = append(recs, topicsink.Record{Key: chain, Content: e.data, Source: o.sourcePrefix + ":" + e.id})
			idsByChain[chain] = append(idsByChain[chain], e.id)
			continue
		}
		refused = append(refused, e.id)
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

	done, err := sink.Commit(ctx, recs)
	if o.afterCommit != nil && len(done) > 0 {
		o.afterCommit()
	}
	var ack []string
	for _, d := range done {
		st.committed += d.Entries
		st.duplicates += d.Duplicates
		ack = append(ack, idsByChain[d.Chain]...)
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
