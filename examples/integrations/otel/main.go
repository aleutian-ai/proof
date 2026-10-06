// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command otel-sink receives OpenTelemetry logs (OTLP/HTTP) and commits each
// log record to a proof chain, one per (class, subject).
//
//	otel-sink -class app-logs -dir sink-data      listen on 127.0.0.1:4320, POST /v1/logs
//
// It sits behind an OpenTelemetry Collector (its otlphttp exporter), which does
// the batching, retrying and queueing. otel-sink answers a request only after
// the sink commit: 200 when every record is committed or refused (refusals are
// counted in partial_success), 503 when the sink failed, so the collector
// retries. Checkpoint, verify and erase the folder (-dir) with `proof sink`.
//
// OTLP has no delivery position, so each record must carry a stable delivery
// id, log.record.uid (the collector's transform processor adds one when the app
// did not). It is the record's sink Source: a retried request's records are
// recognised and not committed twice. A record without one is refused.
// -crash-after-commit exits after the sink commit, before answering.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aleutian-ai/proof/sink"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2 // also: a configuration error the operator must fix
	exitCrash  = 3 // -crash-after-commit
)

// crash is the demo's crash: a variable only so tests can observe it.
var crash = func() { os.Exit(exitCrash) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("otel-sink", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:4320", "address for OTLP/HTTP (POST /v1/logs)")
	class := fs.String("class", "", "the evidence class every record is committed under")
	subjectAttr := fs.String("subject-attr", "enduser.pseudo.id",
		"the attribute holding the subject (a pseudonym), on the log record or else its resource")
	dir := fs.String("dir", "sink-data", "the sink folder")
	crashAfter := fs.Bool("crash-after-commit", false, "DEMO — exit after the first sink commit, before answering")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// A class the sink refuses would make it refuse EVERY record: checked here,
	// at startup, not discovered as a stream of refusals.
	if !sink.ValidClass(*class) {
		fmt.Fprintln(stderr, "otel-sink: -class must match [a-z0-9][a-z0-9_-]{0,30}")
		return exitUsage
	}
	if *subjectAttr == "" {
		fmt.Fprintln(stderr, "otel-sink: -subject-attr is required")
		return exitUsage
	}

	dst, closeKey, err := openSink(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "otel-sink: %v\n", err)
		return exitFailed
	}
	defer closeKey()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "otel-sink: %v\n", err)
		return exitFailed
	}
	rv := newReceiver(dst, options{class: *class, subjectAttr: *subjectAttr}, stderr)
	if *crashAfter {
		rv.o.afterCommit = func() {
			fmt.Fprintln(stderr, "otel-sink: -crash-after-commit: exiting after the sink commit, before answering")
			crash()
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/logs", rv)
	// No WriteTimeout: it could cut an answer off after its commit. Reads and
	// idle connections are bounded.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	fmt.Fprintf(stderr, "otel-sink: listening on %s (POST /v1/logs), class %s\n", ln.Addr(), *class)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := exitOK
	select {
	case <-ctx.Done():
	case f := <-rv.fatal:
		fmt.Fprintf(stderr, "otel-sink: stopping: %v\n", f.err)
		code = f.code
	case err := <-served:
		fmt.Fprintf(stderr, "otel-sink: %v\n", err)
		code = exitFailed
	}
	stop() // a second Ctrl-C now kills the process instead of waiting for Shutdown
	// Requests in progress finish (their commit and their answer) first.
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "otel-sink: shutdown: %v\n", err)
	}
	st := rv.totals()
	fmt.Fprintf(stdout, "committed %d · already committed %d · refused %d\n", st.committed, st.duplicates, st.refused)
	return code
}
