// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"github.com/aleutian-ai/proof/sink"
)

// A class the sink would refuse is a usage error at startup, before listening,
// never a stream of silently refused records.
func TestRun_RefusesInvalidClass(t *testing.T) {
	for _, class := range []string{"", "Payments", "pay.ments", "-x", strings.Repeat("a", 32)} {
		var out, errs bytes.Buffer
		if code := run([]string{"-class", class, "-dir", t.TempDir()}, &out, &errs); code != exitUsage {
			t.Fatalf("-class %q: exit %d, want %d (%s)", class, code, exitUsage, errs.String())
		}
		if !strings.Contains(errs.String(), "-class") {
			t.Fatalf("-class %q: the error does not name the flag: %s", class, errs.String())
		}
	}
}

func TestRun_RefusesEmptySubjectAttr(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"-class", "app-logs", "-subject-attr", "", "-dir", t.TempDir()}, &out, &errs); code != exitUsage ||
		!strings.Contains(errs.String(), "-subject-attr") {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
}

func TestRun_BadListenAddress(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"-class", "app-logs", "-listen", "not an address", "-dir", t.TempDir()}, &out, &errs); code != exitFailed {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
}

// The whole fatal path through run(): a sink that signs, a receiver without
// the key. The first request is answered 503, the receiver stops, and run
// returns exit 2 with its totals.
func TestRun_ConfigurationErrorStops(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(recordKeyEnv, writeRecordKey(t))
	signed, closeKey, err := openSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signed.Commit(context.Background(), []sink.Record{{Class: "app-logs", Subject: "u-1", Content: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	closeKey()
	t.Setenv(recordKeyEnv, "")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	var out, errs syncBuffer
	code := make(chan int, 1)
	go func() { code <- run([]string{"-class", "app-logs", "-dir", dir, "-listen", addr}, &out, &errs) }()

	b, _ := plogotlp.NewExportRequestFromLogs(logsOf(lrec{uid: "s1", subject: "u-1", body: "a"})).MarshalProto()
	var resp *http.Response
	for range 100 {
		if resp, err = http.Post("http://"+addr+"/v1/logs", contentProto, bytes.NewReader(b)); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("answer %d", resp.StatusCode)
	}
	select {
	case c := <-code:
		if c != exitUsage || !strings.Contains(errs.String(), "configuration error") ||
			!strings.Contains(out.String(), "committed 0 · already committed 0 · refused 0") {
			t.Fatalf("exit %d, stderr %q, stdout %q", c, errs.String(), out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the receiver did not stop")
	}
}

// syncBuffer is a bytes.Buffer safe for the server goroutine and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
