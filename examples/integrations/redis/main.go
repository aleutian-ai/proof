// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command redis-sink commits a Redis (or Valkey) stream to one proof chain per key.
//
//	redis-sink add -key user < events.jsonl   XADD each line: key=<user>, data=<line>
//	redis-sink consume                        recover pending, then commit → XACK
//	redis-sink pending                        how many entries are read but unacked
//
// Entries on the stream (-stream, default "evidence") carry a "key" field that
// names the chain and a "data" field that is committed. Checkpoint, verify and
// erase the folder (-dir) with topic-sink.
//
// An entry is acknowledged only after its commit succeeds. Redis never
// redelivers, so consume first recovers entries left pending: its own, then any
// idle past -claim-idle. Each record carries "<stream>:<entry id>" as its
// topicsink Source, so an entry committed just before a crash is recognised and
// acked, never committed twice. -crash-after-commit exits between the two.
//
// Works unchanged with Valkey, the Linux Foundation's BSD-licensed fork.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aleutian-ai/proof/examples/integrations/topicsink"
)

const (
	group   = "proof"
	batch   = 100 // well under topicsink.MaxBatch
	maxLine = 1 << 20

	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
	exitCrash  = 3 // -crash-after-commit
)

// crash is the demo's crash: a variable only so tests can observe it.
var crash = func() { os.Exit(exitCrash) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "usage: redis-sink add|consume|pending [-addr host:port] [-stream evidence] [flags]\n" +
		"  add -key FIELD                          JSONL on stdin → XADD key=<FIELD value> data=<line>\n" +
		"  consume -dir D [-consumer NAME] [-claim-idle 60s] [-follow] [-crash-after-commit]"
	if len(args) < 1 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cmd := args[0]
	if cmd != "add" && cmd != "consume" && cmd != "pending" {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:6379", "Redis or Valkey server")
	stream := fs.String("stream", "evidence", "stream name")
	key := fs.String("key", "", "add: the JSON field whose value becomes the entry's key")
	dir := fs.String("dir", "sink-data", "consume: the topicsink folder")
	consumer := fs.String("consumer", "sink-1", "consume: this consumer's name in the group; reuse it across restarts")
	claimIdle := fs.Duration("claim-idle", 60*time.Second, "consume: claim entries another consumer left pending this long")
	follow := fs.Bool("follow", false, "consume: keep running instead of exiting when drained")
	crashAfter := fs.Bool("crash-after-commit", false, "consume: DEMO — exit after the first commit, before any ack")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if cmd == "add" && *key == "" {
		fmt.Fprintln(stderr, "redis-sink add: -key is required")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rdb := redis.NewClient(&redis.Options{Addr: *addr})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Fprintf(stderr, "redis-sink: connect %s: %v\n", *addr, err)
		return exitFailed
	}
	// The group reads from the stream's start, and MKSTREAM creates the stream
	// if needed. BUSYGROUP means it already exists, which is the usual case.
	created := true
	if err := rdb.XGroupCreateMkStream(ctx, *stream, group, "0").Err(); err != nil {
		if !strings.HasPrefix(err.Error(), "BUSYGROUP") {
			fmt.Fprintf(stderr, "redis-sink: create group: %v\n", err)
			return exitFailed
		}
		created = false
	}
	incarnation, err := streamIncarnation(ctx, rdb, *stream, created, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "redis-sink: %v\n", err)
		return exitFailed
	}

	switch cmd {
	case "add":
		err = add(ctx, rdb, *stream, *key, stdin, stdout)
	case "pending":
		var p *redis.XPending
		if p, err = rdb.XPending(ctx, *stream, group).Result(); err == nil {
			fmt.Fprintf(stdout, "%d entries pending (read, not acknowledged) in group %s\n", p.Count, group)
		}
	case "consume":
		var sink *topicsink.Sink
		if sink, err = topicsink.Open(*dir); err != nil {
			break
		}
		o := options{stream: *stream, sourcePrefix: *stream + "@" + incarnation, batch: batch,
			claimIdle: *claimIdle, follow: *follow}
		if *crashAfter {
			o.afterCommit = func() {
				fmt.Fprintln(stderr, "redis-sink: -crash-after-commit: exiting after the commit, before any ack")
				crash()
			}
		}
		c := redisClient{rdb: rdb, stream: *stream, consumer: *consumer}
		var st stats
		st, err = consume(ctx, c, sink, o, stderr)
		fmt.Fprintf(stdout, "recovered from pending %d · committed %d · already committed %d · refused %d\n",
			st.recovered, st.committed, st.duplicates, st.refused)
		if st.vanished > 0 {
			fmt.Fprintf(stdout, "LOST %d: deleted from the stream while pending (see the log)\n", st.vanished)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "redis-sink %s: %v\n", cmd, err)
		return exitFailed
	}
	return exitOK
}

// streamIncarnation returns a token that names this life of the stream.
//
// Entry ids restart when a stream is deleted and recreated, and a reused id
// would make a new entry look already committed. Redis records no creation
// time for a stream, so the example keeps its own token beside it, and makes a
// new one exactly when the consumer group had to be created: the group dies
// with its stream, so that is when the stream is new.
//
// If the group exists but the token does not (it was deleted, or a crash came
// between creating the group and writing the token), a new token is set and a
// warning printed: an entry pending from before would then be committed again.
//
// Not covered: a failover to a replica whose clock is behind can reuse ids
// within one life of the stream. Nothing here can see that.
func streamIncarnation(ctx context.Context, rdb *redis.Client, stream string, created bool,
	log io.Writer) (string, error) {
	key := stream + ":proof-incarnation"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	fresh := hex.EncodeToString(b)
	if created {
		if err := rdb.Set(ctx, key, fresh, 0).Err(); err != nil {
			return "", fmt.Errorf("record the stream's incarnation: %w", err)
		}
		return fresh, nil
	}
	tok, err := rdb.Get(ctx, key).Result()
	if err == nil {
		return tok, nil
	}
	if !errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("read the stream's incarnation: %w", err)
	}
	ok, err := rdb.SetNX(ctx, key, fresh, 0).Result()
	if err != nil {
		return "", fmt.Errorf("record the stream's incarnation: %w", err)
	}
	if !ok { // another consumer set it first
		return rdb.Get(ctx, key).Result()
	}
	fmt.Fprintf(log, "redis-sink: WARNING: %s was missing; a new one was made. An entry still "+
		"pending from before may be committed a second time.\n", key)
	return fresh, nil
}

// add XADDs each JSONL line with its key and the line itself as data.
//
// It stands in for any producer, so it does NOT pre-validate keys against the
// chain-id rule: enforcing that is the consumer's job.
func add(ctx context.Context, rdb *redis.Client, stream, field string, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	n, line := 0, 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		r, err := topicsink.RecordFromJSON(raw, field)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		// Auto ids ("*"): time-based and increasing. The consumer's idempotency
		// relies on an id never being reused; never set ids by hand here.
		if err := rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: stream, ID: "*", Values: []string{"key", r.Key, "data", string(r.Content)},
		}).Err(); err != nil {
			return fmt.Errorf("line %d: XADD: %w", line, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("after line %d: %w", line, err)
	}
	fmt.Fprintf(out, "added %d entries to stream %s\n", n, stream)
	return nil
}

// redisClient adapts go-redis to streamClient.
type redisClient struct {
	rdb      *redis.Client
	stream   string
	consumer string
}

func (c redisClient) readGroup(ctx context.Context, id string, count int, block time.Duration) ([]entry, error) {
	res, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: group, Consumer: c.consumer, Streams: []string{c.stream, id}, Count: int64(count), Block: block,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil // a blocking read that timed out
	}
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, s := range res {
		for _, m := range s.Messages {
			out = append(out, toEntry(m))
		}
	}
	return out, nil
}

func (c redisClient) autoClaim(ctx context.Context, minIdle time.Duration, start string,
	count int) ([]entry, string, []string, error) {
	msgs, next, deleted, err := c.rdb.XAutoClaimWithDeleted(ctx, &redis.XAutoClaimArgs{
		Stream: c.stream, Group: group, Consumer: c.consumer, MinIdle: minIdle, Start: start, Count: int64(count),
	}).Result()
	if err != nil {
		return nil, "", nil, err
	}
	out := make([]entry, len(msgs))
	for i, m := range msgs {
		out[i] = toEntry(m)
	}
	return out, next, deleted, nil
}

func (c redisClient) ack(ctx context.Context, ids ...string) error {
	return c.rdb.XAck(ctx, c.stream, group, ids...).Err()
}

// toEntry reads the two fields this example uses. A field that is absent, or
// not a string, is left empty and the entry is refused downstream.
func toEntry(m redis.XMessage) entry {
	e := entry{id: m.ID, gone: len(m.Values) == 0}
	if k, ok := m.Values["key"].(string); ok {
		e.key = k
	}
	if d, ok := m.Values["data"].(string); ok {
		e.data = []byte(d)
	}
	return e
}
