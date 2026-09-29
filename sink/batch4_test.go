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

	"github.com/aleutian-ai/proof/anchor"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// 4.2 / 4.3: one validation authority, typed errors that say which record.
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

// 4.1: a folder held by someone else is ErrBusy (retryable), not an I/O error.
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

// 4.4: one chain that cannot be checkpointed does not stop the others.
func TestCheckpoint_ContinuesPastABadChain(t *testing.T) {
	ctx := context.Background()
	s, signer, _ := setup(t)
	// u-81 (first in order) gets a malformed series; u-82 and u-90 get new entries.
	if err := os.WriteFile(filepath.Join(s.anchorDir(cid(t, s, "u-81")), "stray.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"u-81", "u-82", "u-90"} {
		if _, err := s.Commit(ctx, events(c, 1)); err != nil {
			t.Fatal(err)
		}
	}
	done, err := s.Checkpoint(ctx, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if problemFor(done, cid(t, s, "u-81")) == "" {
		t.Fatalf("the bad chain was not reported: %+v", done)
	}
	for _, c := range []string{"u-82", "u-90"} {
		if _, err := os.Stat(filepath.Join(s.anchorDir(cid(t, s, c)), "0002.json")); err != nil {
			t.Fatalf("%s was not checkpointed after a bad chain before it: %v", c, err)
		}
	}
}

// 4.5: after a key rotation, the new key checkpoints on top of a series signed
// by the old one, when the old key is trusted; and verify accepts both.
func TestCheckpoint_KeyRotation(t *testing.T) {
	ctx := context.Background()
	s, oldSigner, _ := setup(t)
	newSigner, _ := newSigner(t)
	ring := func(signers ...*anchor.MLDSA65Signer) anchor.KeySource {
		keys := map[string][]byte{}
		for _, sg := range signers {
			id, pub, err := anchor.KeyIDOf(sg)
			if err != nil {
				t.Fatal(err)
			}
			keys[id] = pub
		}
		r, err := anchor.NewKeyRing(anchor.TrustProvided, keys)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	// Without trusting the old key: refused, as a problem, not an error.
	done, err := s.Checkpoint(ctx, newSigner, nil)
	if err != nil || problemFor(done, cid(t, s, "u-81")) == "" {
		t.Fatalf("new key alone: %+v, %v", done, err)
	}
	// Trusting both: the new key signs 0002 on top of the old key's 0001.
	both := ring(oldSigner, newSigner)
	done, err = s.Checkpoint(ctx, newSigner, both)
	if err != nil || problemFor(done, cid(t, s, "u-81")) != "" {
		t.Fatalf("rotation: %+v, %v", done, err)
	}
	if c := chainReport(t, mustVerify(t, s, both), cid(t, s, "u-81")); c.Checkpoints != 2 {
		t.Fatalf("after rotation: %+v", c)
	}
}

// 4.7: anomalies carry a kind, and the chain id stays raw.
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
