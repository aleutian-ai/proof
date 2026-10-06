// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/aleutian-ai/proof/sink"
)

// message is one Kafka record, as the consumer needs it.
type message struct {
	topicID   [16]byte // from the same fetch response as the record; zero if the broker sent none
	partition int32
	offset    int64
	epoch     int32  // the leader epoch the record was written in; stored with it, so stable
	key       []byte // nil for a record with no key
	value     []byte
	rec       *kgo.Record // the original, for the offset commit; nil in tests
}

// groupClient is the part of a Kafka consumer group the consumer uses. The
// real one wraps franz-go; tests use an in-memory fake, so no broker is needed.
type groupClient interface {
	// ready waits until the group has assigned this consumer its partitions.
	ready(ctx context.Context) error
	// poll returns the next records, in offset order within each partition,
	// or none when ctx ends first.
	poll(ctx context.Context, max int) ([]message, error)
	// commit commits, for each partition, the offset after the given message:
	// the next record the group will read there.
	commit(ctx context.Context, last []message) error
	// allowRebalance ends the window, opened by poll, in which no rebalance
	// can take this consumer's partitions away.
	allowRebalance()
}

// joinTimeout bounds the wait for a partition assignment without follow, so
// an unreachable broker ends the run instead of hanging it. A variable only so
// tests can shorten it.
var joinTimeout = 30 * time.Second

const (
	// batchTimeout bounds finishing a batch after Ctrl-C: its sink commit and
	// offset commit run to the end rather than being cut off half done.
	batchTimeout = 30 * time.Second
)

// committer is the part of sink.Sink the consumer uses.
type committer interface {
	Commit(ctx context.Context, records []sink.Record) ([]sink.Outcome, error)
}

// stats is what the consumer did.
type stats struct {
	committed  int // new entries on a chain
	duplicates int // already committed (redelivered after a crash): offsets moved past them, not re-committed
	refused    int // bad key or value: logged by position, offsets moved past them, not committed
}

func (s *stats) add(o stats) {
	s.committed += o.committed
	s.duplicates += o.duplicates
	s.refused += o.refused
}

// options configure consume.
type options struct {
	topic       string
	class       string        // the evidence class every record is committed under
	idle        time.Duration // without follow: stop after this long with no records
	follow      bool
	afterCommit func() // the demo's crash hook; nil for none
}

// consume reads the topic, committing each batch to the sink before
// committing its offsets.
//
// # Description
//
// Kafka redelivers from the group's committed offsets after a restart, so a
// crash between the sink commit and the offset commit hands the same records
// out again. Each record's Source is its position (see source), so the sink
// recognises them, and they are not committed twice.
//
// It first waits for the group to assign it partitions (at most joinTimeout
// without follow), so the idle clock never runs during the join. Without
// follow it then stops after idle with no records (the topic is drained); with
// follow it runs until ctx ends. Ctrl-C between batches is a clean stop; a
// batch in progress is finished first.
//
// # Outputs
//
//   - stats: totals, also when an error stops the run
//   - error: a poll, sink commit or offset commit failed. Records whose offsets
//     were not committed are read again on the next run.
func consume(ctx context.Context, c groupClient, dst committer, o options, log io.Writer) (stats, error) {
	var total stats
	jctx, cancel := ctx, context.CancelFunc(func() {})
	if !o.follow {
		jctx, cancel = context.WithTimeout(ctx, joinTimeout)
	}
	err := c.ready(jctx)
	cancel()
	if err != nil {
		if ctx.Err() == nil && jctx.Err() != nil {
			return total, fmt.Errorf("no partition of %s was assigned within %v: is the broker reachable, "+
				"and does the topic exist?", o.topic, joinTimeout)
		}
		return total, stopped(ctx, fmt.Errorf("join the group: %w", err))
	}
	for ctx.Err() == nil {
		pctx, cancel := ctx, context.CancelFunc(func() {})
		if !o.follow {
			pctx, cancel = context.WithTimeout(ctx, o.idle)
		}
		ms, err := c.poll(pctx, batch)
		cancel()
		if err != nil {
			c.allowRebalance()
			return total, stopped(ctx, fmt.Errorf("poll: %w", err))
		}
		if len(ms) == 0 {
			c.allowRebalance()
			if !o.follow {
				break
			}
			continue
		}
		st, err := processBatch(ctx, c, dst, o, ms, log)
		c.allowRebalance()
		total.add(st)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// stopped turns an error caused by the caller stopping us (Ctrl-C) into a
// clean stop.
func stopped(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// isConfiguration reports a sink error that every batch would hit the same way.
func isConfiguration(err error) bool {
	return errors.Is(err, sink.ErrRecordSignerRequired) || errors.Is(err, sink.ErrSinkNotSigning)
}

// processBatch commits one poll's records to the sink, then commits offsets.
//
// # Description
//
//  1. Refuse what can never be committed (a key that is not a valid subject,
//     including no key; an empty or oversized value). Refused records are
//     logged by topic/partition@offset, never by key, and count as handled:
//     Kafka has no per-record ack, so leaving them would stall the partition
//     forever. They stay in the topic, just not on a chain.
//  2. Commit the rest through the sink, each with its Source.
//  3. For each partition, walk its records in offset order and commit the
//     offset after the last handled one before the first that is not. A
//     record is handled when it was refused, or its outcome is Committed
//     (which a Duplicate also is: already on its chain).
//
// Nothing at all is committed when the sink breaks its one-outcome-per-record
// contract (nothing can be matched to a record), when it reports a
// configuration error (the operator must fix it first), or when the broker
// sent no topic id (positions could then collide across a recreated topic).
//
// The sink must account for every record: an error, or an outcome per record,
// all Committed. Anything else (no outcomes and no error, or a record left
// uncommitted without an error) is treated as a contract error, since carrying
// on would let a later batch commit an offset past that record.
//
// A sink failure stops the run after committing the handled prefix: the next
// run reads from the first record not committed. The sink commit and the
// offset commit are not cut off by Ctrl-C (ctx), only by batchTimeout.
func processBatch(ctx context.Context, c groupClient, dst committer, o options, ms []message,
	log io.Writer) (stats, error) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), batchTimeout)
	defer cancel()
	var st stats
	var recs []sink.Record
	var at []int // at[j] is the index in ms of recs[j]
	handled := make([]bool, len(ms))

	for i, m := range ms {
		if m.topicID == ([16]byte{}) {
			return st, fmt.Errorf("the broker sent no topic id for %s (Kafka 3.1 or later is needed); "+
				"no offset committed", o.topic)
		}
		rec := sink.Record{Class: o.class, Subject: string(m.key), Content: m.value, Source: source(o.topic, m)}
		if err := rec.Validate(); err != nil {
			// The error never contains the key or the value.
			fmt.Fprintf(log, "refused %s/%d@%d: %v. Handled: offsets move past it; it stays in the topic.\n",
				o.topic, m.partition, m.offset, err)
			handled[i] = true
			st.refused++
			continue
		}
		recs = append(recs, rec)
		at = append(at, i)
	}

	var err error
	if len(recs) > 0 {
		var out []sink.Outcome
		out, err = dst.Commit(wctx, recs)
		if isConfiguration(err) {
			return stats{}, err
		}
		if (out != nil || err == nil) && len(out) != len(recs) {
			return stats{}, errors.Join(err, fmt.Errorf("the sink returned %d outcomes for %d records; "+
				"no offset committed", len(out), len(recs)))
		}
		if err == nil && slices.ContainsFunc(out, func(oc sink.Outcome) bool { return !oc.Committed }) {
			return stats{}, errors.New("the sink left a record uncommitted without an error; no offset committed")
		}
		for j, oc := range out {
			if !oc.Committed {
				continue
			}
			if oc.Duplicate {
				st.duplicates++
			} else {
				st.committed++
			}
			handled[at[j]] = true
		}
	}
	if o.afterCommit != nil && err == nil {
		o.afterCommit()
	}

	if last := handledPrefix(ms, handled); len(last) > 0 {
		if cerr := c.commit(wctx, last); cerr != nil {
			// Committed to the sink but not in Kafka: these records are read
			// again next run and recognised as committed.
			return st, errors.Join(err, fmt.Errorf("offset commit failed (the records will be read "+
				"again and recognised next run): %w", cerr))
		}
	}
	if err != nil {
		return st, fmt.Errorf("commit: %w", err)
	}
	return st, nil
}

// handledPrefix returns, for each partition, the last message of its handled
// prefix: the messages in offset order up to (not including) the first one not
// handled. A partition whose first message is not handled is left out.
func handledPrefix(ms []message, handled []bool) []message {
	blocked := map[int32]bool{}
	last := map[int32]int{}
	var order []int32
	for i, m := range ms {
		if blocked[m.partition] {
			continue
		}
		if !handled[i] {
			blocked[m.partition] = true
			continue
		}
		if _, seen := last[m.partition]; !seen {
			order = append(order, m.partition)
		}
		last[m.partition] = i
	}
	out := make([]message, 0, len(order))
	for _, p := range order {
		out = append(out, ms[last[p]])
	}
	return out
}

// source is a record's position: "<topic>@<topic id>/<partition>:<offset>#<leader epoch>".
//
// The topic id tells a recreated topic from the old one (offsets restart at
// 0). The leader epoch tells apart records at the same offset after a log
// truncation (an unclean leader election hands out offsets again, under a new
// epoch). Both are stored with the record, so a redelivered record has the
// same position. The topic id is printed as Kafka prints it (unpadded
// base64url), so it matches `kafka-topics.sh --describe`.
func source(topic string, m message) string {
	return topic + "@" + base64.RawURLEncoding.EncodeToString(m.topicID[:]) + "/" +
		strconv.FormatInt(int64(m.partition), 10) + ":" + strconv.FormatInt(m.offset, 10) +
		"#" + strconv.FormatInt(int64(m.epoch), 10)
}

// maxPosition is the longest "@<topic id>/<partition>:<offset>#<leader epoch>" suffix.
var maxPosition = len("@" + base64.RawURLEncoding.EncodeToString(make([]byte, 16)) +
	"/2147483647:9223372036854775807#-2147483648")

// sourceFits refuses a topic whose positions could be longer than the sink
// accepts. Checked at startup: otherwise EVERY record would be refused one by
// one, which is silent loss by misconfiguration.
func sourceFits(topic string) error {
	if n := len(topic) + maxPosition; n > sink.MaxSourceBytes {
		return fmt.Errorf("the topic name is too long: positions would be up to %d bytes, "+
			"over the sink's %d byte limit", n, sink.MaxSourceBytes)
	}
	return nil
}

// kafkaClient adapts franz-go to groupClient.
type kafkaClient struct {
	cl       *kgo.Client
	assigned <-chan struct{} // closed on the first partition assignment
	log      io.Writer
}

func (k kafkaClient) ready(ctx context.Context) error {
	select {
	case <-k.assigned:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (k kafkaClient) poll(ctx context.Context, max int) ([]message, error) {
	fs := k.cl.PollRecords(ctx, max)
	if fs.IsClientClosed() {
		return nil, errors.New("client closed")
	}
	return messages(fs, k.log)
}

// messages converts one poll's fetches.
//
// Context errors (the poll's deadline, Ctrl-C) are not failures. Data loss is
// reported, not fatal: Kafka itself truncated the log and the client has
// already reset to its end, so stopping would only stop again on every
// restart. Any other error stops the run with nothing
// processed: the records are fetched again next run.
func messages(fs kgo.Fetches, log io.Writer) ([]message, error) {
	var errs []error
	fs.EachError(func(t string, p int32, err error) {
		var loss *kgo.ErrDataLoss
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		case errors.As(err, &loss):
			fmt.Fprintf(log, "data loss in Kafka: %s/%d was truncated back from offset %d to %d (e.g. an "+
				"unclean leader election). Records read from there before are gone from Kafka; new records "+
				"reuse those offsets under a new leader epoch, which their positions include. Continuing.\n",
				loss.Topic, loss.Partition, loss.ConsumedTo, loss.ResetTo)
		default:
			errs = append(errs, fmt.Errorf("%s/%d: %w", t, p, err))
		}
	})
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var out []message
	for _, f := range fs {
		for _, t := range f.Topics {
			for _, p := range t.Partitions {
				for _, r := range p.Records {
					out = append(out, message{topicID: t.TopicID, partition: r.Partition, offset: r.Offset,
						epoch: r.LeaderEpoch, key: r.Key, value: r.Value, rec: r})
				}
			}
		}
	}
	return out, nil
}

func (k kafkaClient) commit(ctx context.Context, last []message) error {
	rs := make([]*kgo.Record, len(last))
	for i, m := range last {
		rs[i] = m.rec
	}
	return k.cl.CommitRecords(ctx, rs...)
}

func (k kafkaClient) allowRebalance() { k.cl.AllowRebalance() }
