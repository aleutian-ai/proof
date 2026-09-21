// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/fixtures"
)

// Cross-implementation golden vectors for chain linkage.
//
// # Why these vectors and not freshly generated ones
//
// A fixture baked from this module would prove only that the encoder is
// deterministic — it would agree with itself by construction and catch nothing.
// These vectors come from the JavaScript verifier and were independently
// confirmed against the Go producer, so reproducing them is evidence of
// agreement between implementations that were written separately.
//
// # A caution about the other copies
//
// `chain_vectors.json` exists in three places upstream. Only the JavaScript copy
// is real: the Go and Python SDK copies hold fabricated 64-char placeholders
// (SHA-256 length for a SHA-512 chain) that mismatch the implementation on every
// vector, and neither SDK reads its own copy. If these vectors are ever
// refreshed, take them from a source that has been checked against a running
// implementation — not from whichever file is nearest.
//
// Deliberately an external test package: everything below goes through the
// public API, so a vector that needs an unexported helper is a signal the
// public surface is incomplete.

// chainVector mirrors one record of the shared fixture.
type chainVector struct {
	Name         string `json:"name"`
	PreviousHash string `json:"previous_hash"`
	RunID        string `json:"run_id"`
	SequenceNum  int64  `json:"sequence_num"`
	Timestamp    string `json:"timestamp"`
	ContentHash  string `json:"content_hash"`
	ExpectedHash string `json:"expected_hash"`
}

func loadChainVectors(t *testing.T) []chainVector {
	t.Helper()
	var vs []chainVector
	if err := json.Unmarshal(fixtures.ChainVectors(), &vs); err != nil {
		t.Fatalf("decode chain vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("chain vectors fixture is empty")
	}
	return vs
}

// TestChainVectors_Reproduce asserts the encoder reproduces every published
// vector byte-for-byte.
//
// This is the load-bearing test of the package: a failure means this
// implementation and the JavaScript verifier no longer agree on what a chain
// hash is, and chains produced by one would be reported broken by the other.
func TestChainVectors_Reproduce(t *testing.T) {
	t.Parallel()

	for _, v := range loadChainVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()

			ts, err := time.Parse(time.RFC3339Nano, v.Timestamp)
			if err != nil {
				t.Fatalf("parse timestamp %q: %v", v.Timestamp, err)
			}
			got := chainformat.ComputeChainHashUnchecked(
				v.PreviousHash, v.RunID, v.SequenceNum, ts, v.ContentHash)

			if got != v.ExpectedHash {
				t.Errorf("chain hash diverges from the cross-language contract:\n"+
					"  want %s\n  got  %s", v.ExpectedHash, got)
			}
		})
	}
}

// TestChainVectors_CoverTheCasesThatMatter asserts the fixture still exercises
// the three structurally distinct situations, so a future edit cannot quietly
// reduce it to three variations of the same happy path.
func TestChainVectors_CoverTheCasesThatMatter(t *testing.T) {
	t.Parallel()

	var (
		sawGenesis     bool // previous_hash == "" — the chain head
		sawLinked      bool // previous_hash set — ordinary linkage
		sawTombstone   bool // a tombstone content hash flowing through the hash
		sawSubSecondTS bool // a timestamp with non-zero microseconds
	)
	for _, v := range loadChainVectors(t) {
		switch {
		case v.PreviousHash == "":
			sawGenesis = true
		default:
			sawLinked = true
		}
		if chainformat.IsTombstoneContentHash(v.ContentHash) {
			sawTombstone = true
		}
		if ts, err := time.Parse(time.RFC3339Nano, v.Timestamp); err == nil && ts.Nanosecond() != 0 {
			sawSubSecondTS = true
		}
	}

	for _, c := range []struct {
		got  bool
		what string
	}{
		{sawGenesis, "an entry with an empty previous_hash (the chain head)"},
		{sawLinked, "an entry linked to a predecessor"},
		{sawTombstone, "a tombstone content hash (erasure must not break linkage)"},
		{sawSubSecondTS, "a timestamp with non-zero microseconds (the precision path)"},
	} {
		if !c.got {
			t.Errorf("fixture no longer covers %s", c.what)
		}
	}
}

// TestChainVectors_TombstoneDoesNotBreakLinkage states the property the
// tombstone vector exists to prove.
//
// A tombstone content hash is 74 characters and carries a prefix rather than
// being 128 hex, so an implementation that assumes a fixed-width content hash —
// or validates before hashing without the tombstone exemption — would refuse it.
// The vector proves a tombstoned entry hashes like any other.
func TestChainVectors_TombstoneDoesNotBreakLinkage(t *testing.T) {
	t.Parallel()

	for _, v := range loadChainVectors(t) {
		if !chainformat.IsTombstoneContentHash(v.ContentHash) {
			continue
		}
		if !chainformat.ValidateTombstoneContentHash(v.ContentHash) {
			t.Fatalf("%s: fixture carries a malformed tombstone content hash", v.Name)
		}
		if err := chainformat.ValidateChainHashInputs(
			v.PreviousHash, v.RunID, v.SequenceNum, v.ContentHash); err != nil {
			t.Errorf("%s: a tombstone content hash must pass chain-hash validation, "+
				"otherwise an erased entry cannot be linked: %v", v.Name, err)
		}
		return
	}
	t.Fatal("no tombstone vector found — see TestChainVectors_CoverTheCasesThatMatter")
}
