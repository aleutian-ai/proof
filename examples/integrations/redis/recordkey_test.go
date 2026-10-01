// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

func writeRecordKey(t *testing.T) string {
	t.Helper()
	pem, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "record.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The env var names a FILE; set, every record is signed, and the sink then
// refuses a consumer without it, as a configuration error.
func TestOpenSink_RecordKeyFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(recordKeyEnv, writeRecordKey(t))
	s, closeKey, err := openSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, []sink.Record{{Class: "events", Subject: "u-1", Content: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	closeKey()

	t.Setenv(recordKeyEnv, "")
	plain, closePlain, err := openSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closePlain()
	_, err = plain.Commit(ctx, []sink.Record{{Class: "events", Subject: "u-1", Content: []byte("{}")}})
	cerr := configurationError(err)
	if !errors.Is(cerr, sink.ErrRecordSignerRequired) || !strings.Contains(cerr.Error(), "not retried") ||
		!strings.Contains(cerr.Error(), recordKeyEnv) {
		t.Fatalf("err = %v", cerr)
	}
}

func TestOpenSink_BadKeyFile(t *testing.T) {
	t.Setenv(recordKeyEnv, filepath.Join(t.TempDir(), "missing.pem"))
	if _, _, err := openSink(t.TempDir()); err == nil || !strings.Contains(err.Error(), recordKeyEnv) {
		t.Fatalf("err = %v", err)
	}
	notAKey := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(notAKey, []byte("-----BEGIN NOTHING-----\n"), 0o600)
	t.Setenv(recordKeyEnv, notAKey)
	if _, _, err := openSink(t.TempDir()); err == nil {
		t.Fatal("a file that is not a key was accepted")
	}
}

func TestConfigurationError_NotSigning(t *testing.T) {
	err := configurationError(sink.ErrSinkNotSigning)
	if !errors.Is(err, sink.ErrSinkNotSigning) || !strings.Contains(err.Error(), "unset "+recordKeyEnv) {
		t.Fatalf("err = %v", err)
	}
	other := errors.New("disk full")
	if configurationError(other) != other {
		t.Fatal("an ordinary error was rewritten")
	}
}
