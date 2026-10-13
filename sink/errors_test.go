// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// What a caller can branch on: typed errors that say which record, ErrBusy,
// and the kind of an anomaly in a report.

// One validation authority, and typed errors that say which record.
func TestValidateAndRecordError(t *testing.T) {
	ok := Record{Class: testClass, Subject: "u-1", Content: []byte("{}"), Source: "S@1:1"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid record refused: %v", err)
	}
	cases := map[string]struct {
		r       Record
		subject bool
	}{
		"bad subject":   {Record{Class: testClass, Subject: "Jo-Smith", Content: []byte("{}")}, true},
		"empty content": {Record{Class: testClass, Subject: "u-1"}, false},
		"large content": {Record{Class: testClass, Subject: "u-1", Content: make([]byte, MaxContentBytes+1)}, false},
		"large source":  {Record{Class: testClass, Subject: "u-1", Content: []byte("{}"), Source: strings.Repeat("s", MaxSourceBytes+1)}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.r.Validate()
			if !errors.Is(err, ErrInvalidRecord) || errors.Is(err, ErrInvalidSubject) != c.subject {
				t.Fatalf("Validate = %v", err)
			}
			if strings.Contains(err.Error(), "Jo-Smith") {
				t.Fatal("the error echoes the key")
			}
			s, _ := Open(t.TempDir())
			_, cerr := s.Commit(context.Background(), []Record{ok, c.r})
			var re *RecordError
			if !errors.As(cerr, &re) || re.Index != 1 || !errors.Is(cerr, ErrInvalidRecord) {
				t.Fatalf("Commit = %v; want a *RecordError at index 1", cerr)
			}
		})
	}
	if !ValidSubject("u-1") || ValidSubject("jo@example.com") || ValidChainID("u-1") {
		t.Fatal("ValidChainID disagrees with the rule")
	}
}

// A folder held by someone else is ErrBusy (retryable), not an I/O error.
func TestErrBusy(t *testing.T) {
	s, _, ring := setup(t)
	holder, err := boltstore.Open(s.DBPath()) // another writer holds the evidence file
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	quick, _ := Open(s.dir, WithLockTimeout(50*time.Millisecond))
	if _, err := quick.Commit(context.Background(), events("u-1", 1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("Commit on a held folder = %v; want ErrBusy", err)
	}
	if _, err := quick.Verify(context.Background(), ring); !errors.Is(err, ErrBusy) {
		t.Fatalf("Verify on a held folder = %v; want ErrBusy", err)
	}
}

// Anomalies carry a kind, and the chain id stays raw.
func TestAnomaly(t *testing.T) {
	s, _, ring := setup(t)
	orphan := testClass + "." + strings.Repeat("7", 32) // a chain id no subject is bound to
	if err := os.MkdirAll(filepath.Join(s.dir, "anchors", orphan), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	c := chainReport(t, r, orphan)
	if c.Anomaly != "removed" {
		t.Fatalf("anomaly = %q, want removed", c.Anomaly)
	}
	if c := chainReport(t, r, cid(t, s, "u-81")); c.Anomaly != "" {
		t.Fatalf("an ordinary chain has an anomaly: %q", c.Anomaly)
	}
}
