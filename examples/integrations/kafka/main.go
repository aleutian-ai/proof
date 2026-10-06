// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command kafka-sink commits a Kafka topic to proof chains, one per (class, subject).
//
//	kafka-sink produce -key user < events.jsonl   one record per line: key=<user>, value=<line>
//	kafka-sink consume -class actions             commit to the sink, THEN commit offsets
//
// The topic (-topic, default "agent-actions") is the evidence class, fixed by
// the operator (-class), never read from the data. A record's key is its
// subject (a pseudonym) and its value is committed. Checkpoint, verify and
// erase the folder (-dir) with `proof sink`.
//
// Offsets are committed only after the sink commit, per partition, and only up
// to the first record that was not committed. Each record carries
// "<topic>@<topic id>/<partition>:<offset>#<leader epoch>" as its sink Source.
// The topic id is Kafka's own: a deleted and recreated topic gets a new one, so
// offsets restarting at 0 are never mistaken for records already committed.
// -crash-after-commit exits between the sink commit and the offset commit.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/aleutian-ai/proof/sink"
)

const (
	batch   = 500 // records per poll, under sink.MaxBatch
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
	usage := "usage: kafka-sink produce|consume [-brokers host:port] [-topic agent-actions] [flags]\n" +
		"  produce -key FIELD [-every 0s]   JSONL on stdin → one record each: key=<FIELD value>, value=<line>\n" +
		"  consume -class C -dir D [-group proof] [-consumer NAME] [-idle 5s] [-follow] [-crash-after-commit]"
	if len(args) < 1 || (args[0] != "produce" && args[0] != "consume") {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	brokers := fs.String("brokers", "127.0.0.1:9092", "comma-separated Kafka brokers")
	topic := fs.String("topic", "agent-actions", "the topic")
	key := fs.String("key", "", "produce: the JSON field whose value becomes the record key")
	every := fs.Duration("every", 0, "produce: pause between records (for a live demo)")
	class := fs.String("class", "", "consume: the evidence class this topic's records are committed under")
	dir := fs.String("dir", "sink-data", "consume: the sink folder")
	grp := fs.String("group", "proof", "consume: the consumer group")
	consumer := fs.String("consumer", "sink-1", "consume: this consumer's static member id; reuse it across restarts")
	idle := fs.Duration("idle", 5*time.Second, "consume: without -follow, stop after this long with no records")
	follow := fs.Bool("follow", false, "consume: keep running until interrupted")
	crashAfter := fs.Bool("crash-after-commit", false, "consume: DEMO — exit after the first sink commit, before any offset commit")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	// A class the sink refuses would make it refuse EVERY record: checked here,
	// at startup, not discovered as a stream of refusals.
	if cmd == "consume" && !sink.ValidClass(*class) {
		fmt.Fprintf(stderr, "kafka-sink consume: -class must match [a-z0-9][a-z0-9_-]{0,30}\n")
		return exitUsage
	}
	if cmd == "consume" && *idle <= 0 {
		fmt.Fprintln(stderr, "kafka-sink consume: -idle must be positive")
		return exitUsage
	}
	if cmd == "consume" {
		if err := sourceFits(*topic); err != nil {
			fmt.Fprintf(stderr, "kafka-sink consume: %v\n", err)
			return exitUsage
		}
	}
	if cmd == "produce" && *key == "" {
		fmt.Fprintln(stderr, "kafka-sink produce: -key is required")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	seeds := strings.Split(*brokers, ",")

	var err error
	switch cmd {
	case "produce":
		err = produce(ctx, seeds, *topic, *key, *every, stdin, stdout)
	case "consume":
		var dst *sink.Sink
		var closeKey func()
		if dst, closeKey, err = openSink(*dir); err != nil {
			break
		}
		defer closeKey()
		assigned := make(chan struct{})
		var once sync.Once
		var cl *kgo.Client
		cl, err = kgo.NewClient(
			kgo.SeedBrokers(seeds...),
			kgo.ConsumeTopics(*topic),
			kgo.ConsumerGroup(*grp),
			// Static membership: a restart with the same id takes its old place
			// at once, instead of waiting out the dead member's session.
			kgo.InstanceID(*consumer),
			kgo.DisableAutoCommit(),
			// No rebalance between a poll and its offset commit, so an offset is
			// never committed for a partition this consumer no longer owns.
			kgo.BlockRebalanceOnPoll(),
			kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
			kgo.OnPartitionsAssigned(func(context.Context, *kgo.Client, map[string][]int32) {
				once.Do(func() { close(assigned) })
			}),
		)
		if err != nil {
			break
		}
		defer cl.Close()
		o := options{topic: *topic, class: *class, idle: *idle, follow: *follow}
		if *crashAfter {
			o.afterCommit = func() {
				fmt.Fprintln(stderr, "kafka-sink: -crash-after-commit: exiting after the sink commit, before any offset commit")
				crash()
			}
		}
		var st stats
		st, err = consume(ctx, kafkaClient{cl: cl, assigned: assigned, log: stderr}, dst, o, stderr)
		err = configurationError(err)
		fmt.Fprintf(stdout, "committed %d · already committed %d · refused %d\n", st.committed, st.duplicates, st.refused)
	}
	if err != nil {
		fmt.Fprintf(stderr, "kafka-sink %s: %v\n", cmd, err)
		return exitFailed
	}
	return exitOK
}

// produce sends each JSONL line as one record, keyed by the line's field.
//
// It stands in for any producer, so it does NOT pre-validate keys: a line
// without the field is sent with no key (Kafka allows that), and refusing it
// is the consumer's job. The default partitioner sends every record with the
// same key to the same partition.
func produce(ctx context.Context, seeds []string, topic, field string, every time.Duration,
	in io.Reader, out io.Writer) error {
	cl, err := kgo.NewClient(kgo.SeedBrokers(seeds...), kgo.DefaultProduceTopic(topic))
	if err != nil {
		return err
	}
	defer cl.Close()
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
		if n > 0 && every > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(every):
			}
		}
		rec := &kgo.Record{Key: key, Value: bytes.Clone(raw)}
		if err := cl.ProduceSync(ctx, rec).FirstErr(); err != nil {
			return fmt.Errorf("line %d: produce: %w", line, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("after line %d: %w", line, err)
	}
	fmt.Fprintf(out, "produced %d records to topic %s\n", n, topic)
	return nil
}

// keyOf reads the top-level field that holds a line's key. A missing or null
// field gives no key (nil); any other value must be a JSON string. Errors name
// the field, never a value. Each example module carries its own copy on
// purpose (they are separate modules).
func keyOf(line []byte, field string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	raw, ok := obj[field]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var key string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &key) != nil {
		return nil, fmt.Errorf("field %q is not a string", field)
	}
	return []byte(key), nil
}
