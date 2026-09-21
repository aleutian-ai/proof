// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Known-Answer Tests
// =============================================================================

func TestComputeChainHash_KnownAnswers(t *testing.T) {
	t.Parallel()

	// These test vectors are frozen. Any change to the hash algorithm will break
	// these tests, which is the intended behavior — hash stability is a correctness
	// requirement for chain integrity.
	//
	// Formula: SHA512("aleutian.chain.v2:" + prev + "|" + runID + "|" + seq + "|" + ts + "|" + content)
	//
	// Vectors independently computed via Python hashlib.sha512 (reference implementation).
	// previousHash and contentHash are 128 lowercase hex characters (SHA-512).
	tests := []struct {
		name         string
		previousHash string
		runID        string
		sequenceNum  int64
		timestamp    time.Time
		contentHash  string
		want         string // lowercase hex SHA-512 (frozen)
	}{
		{
			name:         "first entry in chain",
			previousHash: "",
			runID:        "run-550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  0,
			timestamp:    time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC),
			contentHash:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:         "638e0ec2a768c8ab5a73f2dcba64ad8476cdbb6449dfb7d6deb2451b021565035291f982ed6cbe5df8caed8980cc2a3d4a29c9e59a00aa3d114a64ffdc09f02a",
		},
		{
			name:         "second entry with previous hash",
			previousHash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			runID:        "run-550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  1,
			timestamp:    time.Date(2026, 1, 19, 12, 0, 1, 0, time.UTC),
			contentHash:  "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
			want:         "cd2de98dc5ce0f72329cde94d77848c317a6e03fb799d5cd32804639922eb1511244b30349ead5962295ff41a6e2f2b901f738d393489c0d3e43f1bf11983b7b",
		},
		{
			name:         "entry with microsecond timestamp",
			previousHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			runID:        "run-6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			sequenceNum:  999,
			timestamp:    time.Date(2026, 6, 15, 23, 59, 59, 123456000, time.UTC),
			contentHash:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			want:         "50bb41d71009904c1062d9e8679313a9469a17ce1c7496a2a385f27b0c0a25e94f7ff07e5215cb18a6a91017e5bba66677f4dbcb56a3b5f93ca88c2b2091966a",
		},
		{
			name:         "large sequence number",
			previousHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			runID:        "run-deadbeef-cafe-babe-0123-456789abcdef",
			sequenceNum:  1000000,
			timestamp:    time.Date(2026, 12, 31, 23, 59, 59, 999999000, time.UTC),
			contentHash:  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			want:         "8b2c14ee65b34656a2f7710ae41fb3423dba34555efe72d95020110bcedcc4ec4935d2a2d58992ba4e20e72a14ae3df3d639041eb51f6eaf061b89c4a3a92e98",
		},
		{
			name:         "tombstone content hash",
			previousHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			runID:        "run-550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  42,
			timestamp:    time.Date(2026, 3, 14, 15, 9, 26, 535897000, time.UTC),
			contentHash:  "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:         "4a6b321c4ab19c67ec39025f84777820b9a628139ba3815b805b554a87d49c29431a5595677766fb78d51d77c8798917fb8cd8d43b8f40c6680d00f68eee860d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ComputeChainHashUnchecked(tt.previousHash, tt.runID, tt.sequenceNum, tt.timestamp, tt.contentHash)
			if got != tt.want {
				t.Errorf("ComputeChainHashUnchecked() = %q, want %q", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Format Tests
// =============================================================================

func TestComputeChainHash_OutputFormat(t *testing.T) {
	t.Parallel()

	hash := ComputeChainHashUnchecked(
		"",
		"run-test",
		0,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		"abc123",
	)

	// Must be exactly 128 characters (512 bits / 4 bits per hex char)
	if len(hash) != 128 {
		t.Errorf("hash length = %d, want 128", len(hash))
	}

	// Must be lowercase hex only
	for i, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash[%d] = %c, not a lowercase hex character", i, c)
		}
	}
}

func TestComputeChainHash_AlwaysLowercaseHex(t *testing.T) {
	t.Parallel()

	// Run with various inputs to ensure no uppercase ever appears
	inputs := []struct {
		prev    string
		content string
	}{
		{"", "abc"},
		{"AAAA", "BBBB"},
		{"0000", "ffff"},
		{strings.Repeat("f", 128), strings.Repeat("0", 128)},
	}

	for _, input := range inputs {
		hash := ComputeChainHashUnchecked(input.prev, "run", 0, time.Now().UTC(), input.content)
		if hash != strings.ToLower(hash) {
			t.Errorf("hash contains uppercase: %q", hash)
		}
	}
}

// =============================================================================
// Determinism Tests
// =============================================================================

func TestComputeChainHash_Deterministic(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC)
	prev := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	runID := "run-550e8400-e29b-41d4-a716-446655440000"
	content := "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

	first := ComputeChainHashUnchecked(prev, runID, 42, ts, content)

	// Call 1000 times — must always produce the same result
	for i := 0; i < 1000; i++ {
		got := ComputeChainHashUnchecked(prev, runID, 42, ts, content)
		if got != first {
			t.Fatalf("non-deterministic at iteration %d: got %q, want %q", i, got, first)
		}
	}
}

// =============================================================================
// Sensitivity Tests (Avalanche Property)
// =============================================================================

func TestComputeChainHash_SensitiveToInputs(t *testing.T) {
	t.Parallel()

	basePrev := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	baseRunID := "run-550e8400-e29b-41d4-a716-446655440000"
	baseSeq := int64(42)
	baseTS := time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC)
	baseContent := "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

	baseline := ComputeChainHashUnchecked(basePrev, baseRunID, baseSeq, baseTS, baseContent)

	tests := []struct {
		name         string
		prev         string
		runID        string
		seq          int64
		ts           time.Time
		content      string
		shouldDiffer bool
	}{
		{
			name:         "different previousHash",
			prev:         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			runID:        baseRunID,
			seq:          baseSeq,
			ts:           baseTS,
			content:      baseContent,
			shouldDiffer: true,
		},
		{
			name:         "different runID",
			prev:         basePrev,
			runID:        "run-different-uuid-value-here",
			seq:          baseSeq,
			ts:           baseTS,
			content:      baseContent,
			shouldDiffer: true,
		},
		{
			name:         "different sequenceNum",
			prev:         basePrev,
			runID:        baseRunID,
			seq:          43,
			ts:           baseTS,
			content:      baseContent,
			shouldDiffer: true,
		},
		{
			name:         "different timestamp by 1 microsecond",
			prev:         basePrev,
			runID:        baseRunID,
			seq:          baseSeq,
			ts:           time.Date(2026, 1, 19, 12, 0, 0, 124456000, time.UTC),
			content:      baseContent,
			shouldDiffer: true,
		},
		{
			name:         "different contentHash",
			prev:         basePrev,
			runID:        baseRunID,
			seq:          baseSeq,
			ts:           baseTS,
			content:      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			shouldDiffer: true,
		},
		{
			name:         "previousHash empty vs non-empty",
			prev:         "",
			runID:        baseRunID,
			seq:          baseSeq,
			ts:           baseTS,
			content:      baseContent,
			shouldDiffer: true,
		},
		{
			name:         "sequenceNum 0 vs 1",
			prev:         basePrev,
			runID:        baseRunID,
			seq:          0,
			ts:           baseTS,
			content:      baseContent,
			shouldDiffer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ComputeChainHashUnchecked(tt.prev, tt.runID, tt.seq, tt.ts, tt.content)
			if tt.shouldDiffer && got == baseline {
				t.Errorf("hash should differ from baseline but is identical: %q", got)
			}
		})
	}
}

// =============================================================================
// First Entry Tests
// =============================================================================

func TestComputeChainHash_FirstEntry(t *testing.T) {
	t.Parallel()

	// First entry uses empty previousHash (not "NULL" or any other placeholder)
	hash := ComputeChainHashUnchecked(
		"",
		"run-550e8400-e29b-41d4-a716-446655440000",
		0,
		time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC),
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	)

	if len(hash) != 128 {
		t.Errorf("first entry hash length = %d, want 128", len(hash))
	}

	// Verify it's different from using "NULL" as previous hash
	hashWithNull := ComputeChainHashUnchecked(
		"NULL",
		"run-550e8400-e29b-41d4-a716-446655440000",
		0,
		time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC),
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	)

	if hash == hashWithNull {
		t.Error("empty previousHash and 'NULL' previousHash should produce different hashes")
	}
}

// =============================================================================
// Sequence Number Edge Cases
// =============================================================================

func TestComputeChainHash_SequenceEdgeCases(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)
	prev := ""
	runID := "run-test"
	content := "abc123"

	tests := []struct {
		name string
		seq  int64
	}{
		{"zero", 0},
		{"one", 1},
		{"large", 999999999},
		{"max_int64", math.MaxInt64},
		{"negative", -1},
	}

	seen := make(map[string]string)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := ComputeChainHashUnchecked(prev, runID, tt.seq, ts, content)
			if len(hash) != 128 {
				t.Errorf("hash length = %d, want 128 for seq=%d", len(hash), tt.seq)
			}
			if prev, exists := seen[hash]; exists {
				t.Errorf("hash collision: seq=%d produces same hash as %s", tt.seq, prev)
			}
			seen[hash] = tt.name
		})
	}
}

// =============================================================================
// Timestamp Precision Tests
// =============================================================================

func TestComputeChainHash_TimestampMicrosecondPrecision(t *testing.T) {
	t.Parallel()

	prev := ""
	runID := "run-test"
	content := "abc123"

	// Two timestamps that differ only in the microsecond component
	ts1 := time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC) // .123456
	ts2 := time.Date(2026, 1, 19, 12, 0, 0, 123457000, time.UTC) // .123457

	hash1 := ComputeChainHashUnchecked(prev, runID, 0, ts1, content)
	hash2 := ComputeChainHashUnchecked(prev, runID, 0, ts2, content)

	if hash1 == hash2 {
		t.Error("timestamps differing by 1 microsecond should produce different hashes")
	}
}

func TestComputeChainHash_TimestampSubMicrosecondTruncated(t *testing.T) {
	t.Parallel()

	prev := ""
	runID := "run-test"
	content := "abc123"

	// Two timestamps that differ only in nanoseconds below microsecond precision
	ts1 := time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC) // .123456000
	ts2 := time.Date(2026, 1, 19, 12, 0, 0, 123456789, time.UTC) // .123456789

	hash1 := ComputeChainHashUnchecked(prev, runID, 0, ts1, content)
	hash2 := ComputeChainHashUnchecked(prev, runID, 0, ts2, content)

	if hash1 != hash2 {
		t.Error("sub-microsecond differences should be truncated and produce identical hashes")
	}
}

func TestComputeChainHash_TimestampZeroMicroseconds(t *testing.T) {
	t.Parallel()

	prev := ""
	runID := "run-test"
	content := "abc123"

	// Whole-second timestamp should format as .000000
	ts := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)
	hash := ComputeChainHashUnchecked(prev, runID, 0, ts, content)

	if len(hash) != 128 {
		t.Errorf("hash length = %d, want 128", len(hash))
	}
}

func TestComputeChainHash_TimestampUTCConversion(t *testing.T) {
	t.Parallel()

	prev := ""
	runID := "run-test"
	content := "abc123"

	// Same instant in different timezones should produce the same hash
	utc := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)
	est := time.Date(2026, 1, 19, 7, 0, 0, 0, time.FixedZone("EST", -5*3600))
	jst := time.Date(2026, 1, 19, 21, 0, 0, 0, time.FixedZone("JST", 9*3600))

	hashUTC := ComputeChainHashUnchecked(prev, runID, 0, utc, content)
	hashEST := ComputeChainHashUnchecked(prev, runID, 0, est, content)
	hashJST := ComputeChainHashUnchecked(prev, runID, 0, jst, content)

	if hashUTC != hashEST {
		t.Error("UTC and EST (same instant) should produce identical hashes")
	}
	if hashUTC != hashJST {
		t.Error("UTC and JST (same instant) should produce identical hashes")
	}
}

// =============================================================================
// SQL Format Cross-Validation
// =============================================================================

func TestComputeChainHash_MatchesSQLInputFormat(t *testing.T) {
	t.Parallel()

	// Manually construct the expected input string and compute SHA-512
	// to cross-validate against the function's output.
	//
	// This mirrors BigQuery SQL:
	//   TO_HEX(SHA512(CONCAT('aleutian.chain.v2:', prev, '|', run_id, '|',
	//     CAST(seq AS STRING), '|', FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts),
	//     '|', content_hash)))
	previousHash := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	runID := "run-550e8400-e29b-41d4-a716-446655440000"
	sequenceNum := int64(42)
	timestamp := time.Date(2026, 6, 15, 23, 59, 59, 123456000, time.UTC)
	contentHash := "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"

	// Build the SQL-equivalent CONCAT string
	// SQL: CONCAT('aleutian.chain.v2:', prev, '|', run_id, '|', CAST(seq AS STRING), '|',
	//            FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts), '|', content_hash)
	expectedInput := fmt.Sprintf("aleutian.chain.v2:%s|%s|%d|%s|%s",
		previousHash,
		runID,
		sequenceNum,
		"2026-06-15T23:59:59.123456Z", // FORMAT_TIMESTAMP output
		contentHash,
	)

	// Compute SHA-512 of the expected input
	sum := sha512.Sum512([]byte(expectedInput))
	expectedHash := hex.EncodeToString(sum[:])

	// The function should produce the same result
	got := ComputeChainHashUnchecked(previousHash, runID, sequenceNum, timestamp, contentHash)

	if got != expectedHash {
		t.Errorf("hash mismatch with SQL format\n  got:  %q\n  want: %q\n  input: %q", got, expectedHash, expectedInput)
	}
}

func TestComputeChainHash_TimestampFormatMatchesBigQuery(t *testing.T) {
	t.Parallel()

	// Verify the timestamp formatting matches BigQuery's FORMAT_TIMESTAMP output exactly
	tests := []struct {
		name     string
		ts       time.Time
		expected string // what BigQuery FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts) produces
	}{
		{
			name:     "whole second",
			ts:       time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC),
			expected: "2026-01-19T12:00:00.000000Z",
		},
		{
			name:     "with milliseconds only",
			ts:       time.Date(2026, 1, 19, 12, 0, 0, 123000000, time.UTC),
			expected: "2026-01-19T12:00:00.123000Z",
		},
		{
			name:     "with microseconds",
			ts:       time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC),
			expected: "2026-01-19T12:00:00.123456Z",
		},
		{
			name:     "end of day",
			ts:       time.Date(2026, 12, 31, 23, 59, 59, 999999000, time.UTC),
			expected: "2026-12-31T23:59:59.999999Z",
		},
		{
			name:     "midnight",
			ts:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: "2026-01-01T00:00:00.000000Z",
		},
		{
			name:     "single digit month and day",
			ts:       time.Date(2026, 3, 5, 9, 7, 3, 1000, time.UTC),
			expected: "2026-03-05T09:07:03.000001Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Use appendTimestampMicro directly to verify formatting
			var buf [27]byte
			result := appendTimestampMicro(buf[:0], tt.ts)
			got := string(result)
			if got != tt.expected {
				t.Errorf("appendTimestampMicro() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Chain Property Tests
// =============================================================================

func TestComputeChainHash_ChainLinkage(t *testing.T) {
	t.Parallel()

	// Simulate a 5-entry chain and verify each entry's hash depends on the previous
	runID := "run-550e8400-e29b-41d4-a716-446655440000"
	baseTime := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)

	var hashes [5]string
	prevHash := ""

	for i := range hashes {
		ts := baseTime.Add(time.Duration(i) * time.Second)
		content := fmt.Sprintf("%0128x", i) // deterministic 128-char content hash per entry
		hashes[i] = ComputeChainHashUnchecked(prevHash, runID, int64(i), ts, content)
		prevHash = hashes[i]
	}

	// All hashes must be unique
	seen := make(map[string]bool)
	for i, h := range hashes {
		if seen[h] {
			t.Errorf("hash[%d] is a duplicate: %s", i, h)
		}
		seen[h] = true
	}

	// Changing any entry in the middle invalidates all subsequent hashes
	// Recompute entry 2 with a different content hash
	altContent := fmt.Sprintf("%0128x", 999)
	altHash2 := ComputeChainHashUnchecked(hashes[1], runID, 2, baseTime.Add(2*time.Second), altContent)
	if altHash2 == hashes[2] {
		t.Error("changing content of entry 2 should produce a different hash")
	}

	// Entry 3 computed with the altered entry 2 hash should also differ
	altHash3 := ComputeChainHashUnchecked(altHash2, runID, 3, baseTime.Add(3*time.Second), fmt.Sprintf("%0128x", 3))
	if altHash3 == hashes[3] {
		t.Error("altered chain should propagate: entry 3 hash should differ")
	}
}

// =============================================================================
// appendTimestampMicro Tests
// =============================================================================

func TestAppendTimestampMicro_NonUTC(t *testing.T) {
	t.Parallel()

	// Non-UTC timezone should be converted to UTC
	est := time.FixedZone("EST", -5*3600)
	ts := time.Date(2026, 1, 19, 7, 0, 0, 0, est) // 07:00 EST = 12:00 UTC

	var buf [27]byte
	result := appendTimestampMicro(buf[:0], ts)
	got := string(result)

	if got != "2026-01-19T12:00:00.000000Z" {
		t.Errorf("appendTimestampMicro() = %q, want %q", got, "2026-01-19T12:00:00.000000Z")
	}
}

func TestAppendTimestampMicro_NanosecondTruncation(t *testing.T) {
	t.Parallel()

	// 123456789 nanoseconds should truncate to 123456 microseconds (not round)
	ts := time.Date(2026, 1, 19, 12, 0, 0, 123456789, time.UTC)

	var buf [27]byte
	result := appendTimestampMicro(buf[:0], ts)
	got := string(result)

	if got != "2026-01-19T12:00:00.123456Z" {
		t.Errorf("appendTimestampMicro() = %q, want %q (should truncate, not round)", got, "2026-01-19T12:00:00.123456Z")
	}
}

// =============================================================================
// appendIntPadded Tests
// =============================================================================

func TestAppendIntPadded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		val   int
		width int
		want  string
	}{
		{0, 1, "0"},
		{0, 2, "00"},
		{0, 6, "000000"},
		{5, 2, "05"},
		{12, 2, "12"},
		{2026, 4, "2026"},
		{123456, 6, "123456"},
		{1, 6, "000001"},
		{999999, 6, "999999"},
		// Value wider than width: no truncation
		{12345, 2, "12345"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_width%d", tt.val, tt.width), func(t *testing.T) {
			t.Parallel()
			var buf [20]byte
			result := appendIntPadded(buf[:0], tt.val, tt.width)
			got := string(result)
			if got != tt.want {
				t.Errorf("appendIntPadded(%d, %d) = %q, want %q", tt.val, tt.width, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Timestamp precision (replaces the producer's ComputeChainHashMs suite —
// this module does not ship that function)
// =============================================================================

// TestChainHash_MillisecondTruncationChangesTheHash demonstrates the trap that
// the dropped ComputeChainHashMs variant embodied.
//
// # Why this is a test and not a comment
//
// The producer shipped a millisecond-taking convenience wrapper whose only
// behavioural difference was silent precision loss. It had ZERO production
// callers in either the producer or the published SDK, so it was not ported —
// but the underlying hazard survives it: any caller who routes a timestamp
// through a millisecond representation before hashing gets a DIFFERENT hash for
// the same logical entry, and the failure appears later as an unverifiable chain
// rather than as an error at the point of the mistake.
//
// Pinning it here means the divergence is demonstrated rather than described.
func TestChainHash_MillisecondTruncationChangesTheHash(t *testing.T) {
	t.Parallel()

	const (
		prev    = "b"
		runID   = "run-precision"
		content = "c"
	)
	// A timestamp with microsecond resolution that milliseconds cannot represent.
	full := time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC)
	viaMillis := time.UnixMilli(full.UnixMilli()).UTC()

	if full.Equal(viaMillis) {
		t.Fatal("test fixture is wrong: the timestamp survives a millisecond round-trip")
	}

	hashFull := ComputeChainHashUnchecked(prev, runID, 0, full, content)
	hashLossy := ComputeChainHashUnchecked(prev, runID, 0, viaMillis, content)

	if hashFull == hashLossy {
		t.Fatal("a millisecond round-trip did NOT change the hash — either the " +
			"encoder stopped binding sub-millisecond precision, or this test no " +
			"longer exercises it")
	}
}

// TestChainHash_SubMicrosecondIsTruncated pins the other half: precision BELOW a
// microsecond is deliberately discarded, so two timestamps differing only in
// nanoseconds hash identically.
//
// Without this, a producer on a nanosecond-precision clock and a verifier
// re-parsing a microsecond-formatted timestamp would disagree forever.
func TestChainHash_SubMicrosecondIsTruncated(t *testing.T) {
	t.Parallel()

	a := time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC)
	b := time.Date(2026, 1, 20, 12, 0, 1, 123456999, time.UTC)

	if ComputeChainHashUnchecked("b", "run", 0, a, "c") !=
		ComputeChainHashUnchecked("b", "run", 0, b, "c") {
		t.Fatal("nanosecond difference changed the hash; the encoder must truncate " +
			"to microseconds or producer and verifier can never agree")
	}
}

func TestValidateChainHashInputs_ValidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prev        string
		runID       string
		seq         int64
		contentHash string
	}{
		{
			name:        "first entry (empty prev)",
			prev:        "",
			runID:       "run-550e8400-e29b-41d4-a716-446655440000",
			seq:         0,
			contentHash: strings.Repeat("a", 128), // 128 lowercase hex chars (SHA-512)
		},
		{
			name:        "subsequent entry (128 hex prev)",
			prev:        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			runID:       "run-550e8400-e29b-41d4-a716-446655440000",
			seq:         42,
			contentHash: strings.Repeat("b", 128), // 128 lowercase hex chars (SHA-512)
		},
		{
			name:        "tombstone content hash",
			prev:        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			runID:       "run-test-uuid",
			seq:         0,
			contentHash: "TOMBSTONE:" + strings.Repeat("c", 64), // valid tombstone format (10 + 64 = 74 chars)
		},
		{
			name:        "zero sequence",
			prev:        "",
			runID:       "run-1",
			seq:         0,
			contentHash: strings.Repeat("d", 128), // 128 lowercase hex chars (SHA-512)
		},
		{
			name:        "large sequence",
			prev:        "",
			runID:       "run-1",
			seq:         999999999,
			contentHash: strings.Repeat("e", 128), // 128 lowercase hex chars (SHA-512)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs(tt.prev, tt.runID, tt.seq, tt.contentHash)
			if err != nil {
				t.Errorf("ValidateChainHashInputs() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateChainHashInputs_InvalidPreviousHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		prev string
	}{
		{"too short", "abcdef"},
		{"too long (129 chars)", strings.Repeat("a", 129)},
		{"64 chars (old SHA-256 length)", strings.Repeat("a", 64)},
		{"127 chars (one too short)", strings.Repeat("a", 127)},
		{"uppercase hex (128 chars)", strings.Repeat("A", 128)},
		{"mixed case (128 chars)", strings.Repeat("aB", 64)},
		{"contains space", "e3b0c44298fc1c149afbf4c8996fb924 7ae41e4649b934ca495991b7852b855cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs(tt.prev, "run-test", 0, strings.Repeat("a", 128))
			if err == nil {
				t.Errorf("ValidateChainHashInputs() should reject previousHash %q", tt.prev)
			}
		})
	}
}

func TestValidateChainHashInputs_InvalidRunID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		runID string
	}{
		{"empty", ""},
		{"contains pipe", "run|test"},
		{"pipe at start", "|run-test"},
		{"pipe at end", "run-test|"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs("", tt.runID, 0, strings.Repeat("a", 128))
			if err == nil {
				t.Errorf("ValidateChainHashInputs() should reject runID %q", tt.runID)
			}
		})
	}
}

func TestValidateChainHashInputs_InvalidSequenceNum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seq  int64
	}{
		{"negative one", -1},
		{"negative large", -999999},
		{"min int64", math.MinInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs("", "run-test", tt.seq, strings.Repeat("a", 128))
			if err == nil {
				t.Errorf("ValidateChainHashInputs() should reject sequenceNum %d", tt.seq)
			}
		})
	}
}

func TestValidateChainHashInputs_InvalidContentHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"contains pipe", "abc|123"},
		{"pipe only", "|"},
		{"127 chars (too short by 1)", strings.Repeat("a", 127)},
		{"129 chars (too long by 1)", strings.Repeat("a", 129)},
		{"64 chars (old SHA-256 length)", strings.Repeat("a", 64)},
		{"128 uppercase hex chars", strings.Repeat("A", 128)},
		{"128 mixed case", strings.Repeat("aB", 64)},
		{"non-hex char in 128-length string", strings.Repeat("a", 127) + "g"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs("", "run-test", 0, tt.content)
			if err == nil {
				t.Errorf("ValidateChainHashInputs() should reject contentHash %q", tt.content)
			}
		})
	}
}

func TestValidateChainHashInputs_ErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prev        string
		runID       string
		seq         int64
		content     string
		wantContain string
	}{
		{
			name:        "prev hash length error",
			prev:        "abc",
			runID:       "run-test",
			seq:         0,
			content:     strings.Repeat("a", 128), // valid SHA-512 content hash
			wantContain: "128 hex chars",
		},
		{
			name:        "prev hash character error",
			prev:        strings.Repeat("a", 127) + "G", // 128 chars, last char invalid
			runID:       "run-test",
			seq:         0,
			content:     strings.Repeat("a", 128), // valid SHA-512 content hash
			wantContain: "non-lowercase-hex",
		},
		{
			name:        "empty runID error",
			prev:        "",
			runID:       "",
			seq:         0,
			content:     strings.Repeat("a", 128), // valid SHA-512 content hash
			wantContain: "non-empty",
		},
		{
			name:        "runID pipe error",
			prev:        "",
			runID:       "run|id",
			seq:         0,
			content:     strings.Repeat("a", 128), // valid SHA-512 content hash
			wantContain: "pipe separator",
		},
		{
			name:        "negative sequence error",
			prev:        "",
			runID:       "run-test",
			seq:         -5,
			content:     strings.Repeat("a", 128), // valid SHA-512 content hash
			wantContain: "non-negative",
		},
		{
			name:        "empty content error",
			prev:        "",
			runID:       "run-test",
			seq:         0,
			content:     "",
			wantContain: "128 lowercase hex chars",
		},
		{
			name:        "content too short error",
			prev:        "",
			runID:       "run-test",
			seq:         0,
			content:     strings.Repeat("a", 64), // old SHA-256 length — rejected
			wantContain: "128 lowercase hex chars",
		},
		{
			name:        "content non-hex chars error",
			prev:        "",
			runID:       "run-test",
			seq:         0,
			content:     strings.Repeat("a", 127) + "G", // 128 chars but non-hex last char
			wantContain: "non-lowercase-hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateChainHashInputs(tt.prev, tt.runID, tt.seq, tt.content)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantContain)
			}
		})
	}
}

// TestComputeChainHash_DomainPrefix verifies the domain prefix is included in the hash input.
func TestComputeChainHash_DomainPrefix(t *testing.T) {
	t.Parallel()

	prev := ""
	runID := "run-test"
	seq := int64(0)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	content := "abc123"

	// Compute with our function
	got := ComputeChainHashUnchecked(prev, runID, seq, ts, content)

	// Compute manually with domain prefix (v2 = SHA-512)
	input := fmt.Sprintf("aleutian.chain.v2:%s|%s|%d|%s|%s",
		prev, runID, seq, "2026-01-01T00:00:00.000000Z", content)
	sum := sha512.Sum512([]byte(input))
	expected := hex.EncodeToString(sum[:])

	if got != expected {
		t.Errorf("domain prefix mismatch\n  got:  %s\n  want: %s\n  input: %s", got, expected, input)
	}

	// Verify it differs from hash WITHOUT domain prefix
	inputNoDomain := fmt.Sprintf("%s|%s|%d|%s|%s",
		prev, runID, seq, "2026-01-01T00:00:00.000000Z", content)
	sumNoDomain := sha512.Sum512([]byte(inputNoDomain))
	hashNoDomain := hex.EncodeToString(sumNoDomain[:])

	if got == hashNoDomain {
		t.Error("hash with domain prefix should differ from hash without domain prefix")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkComputeChainHash(b *testing.B) {
	prev := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3ecf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	runID := "run-550e8400-e29b-41d4-a716-446655440000"
	ts := time.Date(2026, 1, 19, 12, 0, 0, 123456000, time.UTC)
	content := "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ComputeChainHashUnchecked(prev, runID, int64(i), ts, content)
	}
}

func BenchmarkComputeChainHash_FirstEntry(b *testing.B) {
	runID := "run-550e8400-e29b-41d4-a716-446655440000"
	ts := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)
	content := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ComputeChainHashUnchecked("", runID, 0, ts, content)
	}
}

func BenchmarkAppendTimestampMicro(b *testing.B) {
	ts := time.Date(2026, 6, 15, 23, 59, 59, 123456000, time.UTC)
	var buf [64]byte

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = appendTimestampMicro(buf[:0], ts)
	}
}

// =============================================================================
// Additions made during the lift
// =============================================================================

// TestTombstoneContentHash_WorksWithChainHash is the half of the producer's
// tombstone/chain-hash integration test; the delimiter half is in
// tombstone_test.go.
func TestTombstoneContentHash_WorksWithChainHash(t *testing.T) {
	t.Parallel()

	contentHash, err := GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("GenerateTombstoneContentHash: %v", err)
	}
	hash := ComputeChainHashUnchecked("", "run-550e8400-e29b-41d4-a716-446655440000", 0,
		time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC), contentHash)
	if len(hash) != 128 {
		t.Errorf("chain hash length = %d, want 128", len(hash))
	}
	if err := ValidateChainHashInputs("", "run-550e8400-e29b-41d4-a716-446655440000", 0, contentHash); err != nil {
		t.Errorf("a tombstone content hash must pass validation: %v", err)
	}
}

// TestComputeChainHash_RejectsWhatUncheckedAccepts is the reason the validated
// form carries the shorter name.
func TestComputeChainHash_RejectsWhatUncheckedAccepts(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	content := strings.Repeat("c", 128)

	bad := []struct {
		name        string
		prev, runID string
		seq         int64
	}{
		{"malformed previous_hash", "abc|d", "run-1", 0},
		{"short previous_hash", "abc", "run-1", 0},
		{"uppercase previous_hash", strings.ToUpper(strings.Repeat("a", 128)), "run-1", 0},
		{"pipe in run_id", strings.Repeat("b", 128), "run|1", 0},
		{"empty run_id", strings.Repeat("b", 128), "", 0},
		{"negative sequence_num", strings.Repeat("b", 128), "run-1", -1},
	}
	for _, tc := range bad {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ComputeChainHash(tc.prev, tc.runID, tc.seq, ts, content); err == nil {
				t.Error("validated form accepted an input it must reject")
			}
			// The unchecked primitive is expected to accept it — that is the whole
			// distinction, and if it ever stops the two functions have converged.
			if got := ComputeChainHashUnchecked(tc.prev, tc.runID, tc.seq, ts, content); len(got) != 128 {
				t.Errorf("unchecked primitive returned %d chars, want 128", len(got))
			}
		})
	}
}

// TestComputeChainHash_AgreesWithUncheckedOnValidInput asserts validation changes
// only ACCEPTANCE, never the bytes — otherwise the two functions would produce
// different chains for the same entry.
func TestComputeChainHash_AgreesWithUncheckedOnValidInput(t *testing.T) {
	t.Parallel()

	prev, runID := strings.Repeat("b", 128), "run-550e8400-e29b-41d4-a716-446655440000"
	content := strings.Repeat("c", 128)
	ts := time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC)

	checked, err := ComputeChainHash(prev, runID, 7, ts, content)
	if err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if unchecked := ComputeChainHashUnchecked(prev, runID, 7, ts, content); checked != unchecked {
		t.Fatalf("validated and unchecked forms disagree:\n  checked:   %s\n  unchecked: %s",
			checked, unchecked)
	}
}

// TestChainHash_DelimiterCollisionIsBlockedByValidation pins the concrete attack
// that motivates validating at all.
//
// # The collision
//
// The preimage is '|'-delimited and NOT self-delimiting, so moving the split
// point between previous_hash and run_id yields two different entries with one
// hash:
//
//	prev="abc|d" run="ef"    ─┐
//	                          ├─► "…:abc|d|ef|0|<ts>|<content>"
//	prev="abc"   run="d|ef"  ─┘
//
// Note WHICH rule stops it. Banning '|' in run_id does not: with a well-formed
// previous_hash, run_id pipes are harmless because every other field is
// fixed-shape and the boundaries are recoverable from the right. The load-bearing
// rule is that previous_hash is empty or exactly 128 lowercase hex.
func TestChainHash_DelimiterCollisionIsBlockedByValidation(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	content := strings.Repeat("c", 128)

	// The unchecked primitive collides — demonstrating the hazard is real.
	a := ComputeChainHashUnchecked("abc|d", "ef", 0, ts, content)
	b := ComputeChainHashUnchecked("abc", "d|ef", 0, ts, content)
	if a != b {
		t.Fatal("expected the unchecked primitive to collide on a malformed " +
			"previous_hash; if this no longer holds the preimage format changed")
	}

	// The validated form refuses both, so the collision is unreachable through it.
	if _, err := ComputeChainHash("abc|d", "ef", 0, ts, content); err == nil {
		t.Error("validated form accepted a pipe-bearing previous_hash")
	}
	if _, err := ComputeChainHash("abc", "d|ef", 0, ts, content); err == nil {
		t.Error("validated form accepted a malformed previous_hash")
	}

	// And with a WELL-FORMED previous_hash, a pipe in run_id cannot collide —
	// pinning that the previous_hash shape is what does the work.
	prev := strings.Repeat("b", 128)
	if ComputeChainHashUnchecked(prev, "r|9", 0, ts, content) ==
		ComputeChainHashUnchecked(prev, "r", 9, ts, content) {
		t.Error("run_id pipes collided despite a well-formed previous_hash")
	}
}
