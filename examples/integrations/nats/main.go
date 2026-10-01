// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command nats-sink commits a NATS JetStream stream to proof chains, one per (class, subject).
//
//	nats-sink publish -key user < events.jsonl   publish each line to evidence.<user>
//	nats-sink consume                            commit, THEN ack; exit when drained
//
// Messages on evidence.<key> are committed to the chain <key> in a sink
// folder (-dir). Checkpoint, verify and erase that folder with `proof sink`.
//
// A message is acknowledged only after its commit succeeds. Each record carries
// its stream position as its sink Source, so a message redelivered after a
// crash is recognised and acked, never committed twice. -crash-after-commit
// exits between the commit and the ack, to show exactly that.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/aleutian-ai/proof/sink"
)

const (
	streamName = "EVIDENCE"
	durable    = "proof-sink"
	fetchBatch = 100 // well under sink.MaxBatch

	// idleWait is how long -follow waits for new messages when the stream is
	// drained. minAckWait keeps the ack deadline well above it: a message held
	// past its deadline is redelivered while still being committed (recognised
	// as a duplicate, but wasted work).
	idleWait   = time.Second
	minAckWait = 5 * time.Second
	maxLine    = 1 << 20

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
	if len(args) < 1 || (args[0] != "publish" && args[0] != "consume") {
		fmt.Fprintln(stderr, "usage: nats-sink publish|consume [-url U] [-prefix evidence] [flags]\n"+
			"  publish -key FIELD                 JSONL on stdin → <prefix>.<FIELD value>\n"+
			"  consume -dir D [-follow] [-ack-wait 30s] [-crash-after-commit]")
		return exitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", nats.DefaultURL, "NATS server")
	prefix := fs.String("prefix", "evidence", "subject prefix: messages are <prefix>.<key>")
	key := fs.String("key", "", "publish: the JSON field whose value becomes the subject's key")
	class := fs.String("class", "events", "consume: the evidence class every message is committed under")
	dir := fs.String("dir", "sink-data", "consume: the sink folder")
	follow := fs.Bool("follow", false, "consume: keep running instead of exiting when drained")
	ackWait := fs.Duration("ack-wait", 30*time.Second, "consume: how long JetStream waits for an ack before redelivering")
	crashAfter := fs.Bool("crash-after-commit", false, "consume: DEMO — exit after the first commit, before acking")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if *ackWait < minAckWait {
		fmt.Fprintf(stderr, "nats-sink: -ack-wait must be at least %s\n", minAckWait)
		return exitUsage
	}
	// A class the sink refuses would make it refuse EVERY message: checked here,
	// at startup, not discovered as silent drops.
	if cmd == "consume" && !sink.ValidClass(*class) {
		fmt.Fprintf(stderr, "nats-sink consume: -class must match [a-z0-9][a-z0-9_-]{0,30}\n")
		return exitUsage
	}
	if cmd == "publish" && *key == "" {
		fmt.Fprintln(stderr, "nats-sink publish: -key is required")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	nc, err := nats.Connect(*url, nats.Name("proof nats-sink"))
	if err != nil {
		fmt.Fprintf(stderr, "nats-sink: connect %s: %v\n", *url, err)
		return exitFailed
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		fmt.Fprintf(stderr, "nats-sink: %v\n", err)
		return exitFailed
	}
	// evidence.* — ONE token after the prefix. A subject with a dotted key is
	// then not accepted by the stream at all. See router.
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: streamName, Subjects: []string{*prefix + ".*"}, Storage: jetstream.FileStorage,
	})
	if err != nil {
		fmt.Fprintf(stderr, "nats-sink: stream %s: %v\n", streamName, err)
		return exitFailed
	}

	switch cmd {
	case "publish":
		err = publish(ctx, js, *prefix, *key, stdin, stdout)
	case "consume":
		var afterCommit func()
		if *crashAfter {
			afterCommit = func() {
				fmt.Fprintln(stderr, "nats-sink: -crash-after-commit: exiting after the commit, before any ack")
				crash()
			}
		}
		err = consume(ctx, js, stream, router{prefix: *prefix, class: *class}, *dir, *ackWait, *follow, afterCommit, stdout, stderr)
	}
	if err != nil {
		fmt.Fprintf(stderr, "nats-sink %s: %v\n", cmd, err)
		return exitFailed
	}
	return exitOK
}

// publish sends each JSONL line to <prefix>.<value of field>.
//
// It stands in for any upstream tool, so it does NOT pre-validate keys against
// the chain-id rule: enforcing that is the consumer's job. Each message gets a
// Nats-Msg-Id, so a publish retried within JetStream's duplicate window is
// stored once.
func publish(ctx context.Context, js jetstream.JetStream, prefix, field string, in io.Reader, out io.Writer) error {
	run := make([]byte, 8)
	if _, err := rand.Read(run); err != nil {
		return err
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	n, line := 0, 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		key, err := keyOf(raw, field)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		msgID := hex.EncodeToString(run) + "-" + strconv.Itoa(line)
		if _, err := js.Publish(ctx, prefix+"."+key, append([]byte(nil), raw...), jetstream.WithMsgID(msgID)); err != nil {
			// Never echo the subject: it holds the key.
			if errors.Is(err, jetstream.ErrNoStreamResponse) || errors.Is(err, nats.ErrNoResponders) {
				return fmt.Errorf("line %d: no stream accepts that subject (the key must be one "+
					"subject token: no dots)", line)
			}
			return fmt.Errorf("line %d: publish: %w", line, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("after line %d: %w", line, err)
	}
	fmt.Fprintf(out, "published %d messages to %s\n", n, streamName)
	return nil
}

// consume fetches, commits and acks until the stream is drained (or, with
// follow, until interrupted).
func consume(ctx context.Context, js jetstream.JetStream, stream jetstream.Stream, r router, dir string,
	ackWait time.Duration, follow bool, afterCommit func(), out, log io.Writer) error {
	dst, closeKey, err := openSink(dir)
	if err != nil {
		return err
	}
	defer closeKey()
	// The stream's creation time names this incarnation of it. See message.Position.
	info, err := stream.Info(ctx)
	if err != nil {
		return fmt.Errorf("stream info: %w", err)
	}
	incarnation := strconv.FormatInt(info.Created.UnixNano(), 10)
	take := func(b jetstream.MessageBatch, err error) ([]message, error) { return fetch(b, err, incarnation) }
	cons, err := js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:   durable,
		AckPolicy: jetstream.AckExplicitPolicy,
		AckWait:   ackWait,
	})
	if err != nil {
		return fmt.Errorf("consumer %s: %w", durable, err)
	}

	var total stats
	defer func() {
		fmt.Fprintf(out, "committed %d · already committed (redelivered) %d · refused %d\n",
			total.committed, total.duplicates, total.refused)
	}()
	for ctx.Err() == nil {
		// Only what is already waiting: a Fetch that waits to fill its batch
		// holds the first messages until it returns, and a message held past its
		// ack deadline is redelivered while it is still being committed.
		msgs, err := take(cons.FetchNoWait(fetchBatch))
		if err != nil {
			return err
		}
		if len(msgs) == 0 {
			if !follow {
				return nil // drained
			}
			if msgs, err = take(cons.Fetch(fetchBatch, jetstream.FetchMaxWait(idleWait))); err != nil {
				return err
			}
			if len(msgs) == 0 {
				continue
			}
		}
		st, err := processBatch(ctx, dst, r, msgs, afterCommit, log)
		total.committed += st.committed
		total.duplicates += st.duplicates
		total.refused += st.refused
		if err != nil {
			return configurationError(err)
		}
	}
	return nil
}

// fetch drains one MessageBatch.
func fetch(batch jetstream.MessageBatch, err error, incarnation string) ([]message, error) {
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	var msgs []message
	for m := range batch.Messages() {
		msgs = append(msgs, jsMessage{Msg: m, incarnation: incarnation})
	}
	if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	return msgs, nil
}

// jsMessage adapts a jetstream.Msg to message.
type jsMessage struct {
	jetstream.Msg
	incarnation string
}

func (m jsMessage) Position() (string, error) {
	md, err := m.Metadata()
	if err != nil {
		return "", err
	}
	return md.Stream + "@" + m.incarnation + ":" + strconv.FormatUint(md.Sequence.Stream, 10), nil
}

// keyOf reads the top-level field that holds a line's key, which must be a JSON
// string. Errors name the field, never a value. The publisher needs a key, not
// a sink.Record, so it does not use sink.RecordFromJSON; each example module
// carries its own copy on purpose (they are separate modules).
func keyOf(line []byte, field string) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return "", fmt.Errorf("not a JSON object: %w", err)
	}
	raw, ok := obj[field]
	var key string
	// Checked explicitly: null decodes into a string without error, as "".
	if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &key) != nil {
		return "", fmt.Errorf("field %q is missing or not a string", field)
	}
	return key, nil
}
