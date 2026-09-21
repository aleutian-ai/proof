// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Constants Tests
// =============================================================================

func TestTombstoneConstants(t *testing.T) {
	t.Parallel()

	// These constants must match the assumptions in storage/retention_types.go.
	// If these change, tombstone detection across the system breaks.
	t.Run("content hash prefix", func(t *testing.T) {
		t.Parallel()
		if TombstoneContentHashPrefix != "TOMBSTONE:" {
			t.Errorf("TombstoneContentHashPrefix = %q, want %q", TombstoneContentHashPrefix, "TOMBSTONE:")
		}
	})

	t.Run("entry ID prefix", func(t *testing.T) {
		t.Parallel()
		if TombstoneEntryIDPrefix != "tomb_" {
			t.Errorf("TombstoneEntryIDPrefix = %q, want %q", TombstoneEntryIDPrefix, "tomb_")
		}
	})

	t.Run("entry type", func(t *testing.T) {
		t.Parallel()
		if TombstoneEntryType != "tombstone" {
			t.Errorf("TombstoneEntryType = %q, want %q", TombstoneEntryType, "tombstone")
		}
	})

	t.Run("content hash total length", func(t *testing.T) {
		t.Parallel()
		// "TOMBSTONE:" (10) + 64 hex chars = 74
		expectedLen := 10 + 64
		if tombstoneContentHashLen != expectedLen {
			t.Errorf("tombstoneContentHashLen = %d, want %d", tombstoneContentHashLen, expectedLen)
		}
	})
}

// =============================================================================
// IsTombstone Tests
// =============================================================================

func TestIsTombstone_ValidTombstones(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entryType string
		entryID   string
	}{
		{
			name:      "standard tombstone",
			entryType: "tombstone",
			entryID:   "tomb_550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:      "minimal valid",
			entryType: "tombstone",
			entryID:   "tomb_x",
		},
		{
			name:      "tombstone with long suffix",
			entryType: "tombstone",
			entryID:   "tomb_" + strings.Repeat("a", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !IsTombstone(tt.entryType, tt.entryID) {
				t.Errorf("IsTombstone(%q, %q) = false, want true", tt.entryType, tt.entryID)
			}
		})
	}
}

func TestIsTombstone_NonTombstones(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entryType string
		entryID   string
	}{
		{
			name:      "regular entry",
			entryType: "request",
			entryID:   "req_550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:      "wrong type correct prefix",
			entryType: "request",
			entryID:   "tomb_550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:      "correct type wrong prefix",
			entryType: "tombstone",
			entryID:   "req_550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:      "empty type",
			entryType: "",
			entryID:   "tomb_12345",
		},
		{
			name:      "empty ID",
			entryType: "tombstone",
			entryID:   "",
		},
		{
			name:      "both empty",
			entryType: "",
			entryID:   "",
		},
		{
			name:      "case sensitive type - uppercase",
			entryType: "Tombstone",
			entryID:   "tomb_12345",
		},
		{
			name:      "case sensitive type - all caps",
			entryType: "TOMBSTONE",
			entryID:   "tomb_12345",
		},
		{
			name:      "prefix only",
			entryType: "tombstone",
			entryID:   "tomb",
		},
		{
			name:      "prefix without underscore",
			entryType: "tombstone",
			entryID:   "tombX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if IsTombstone(tt.entryType, tt.entryID) {
				t.Errorf("IsTombstone(%q, %q) = true, want false", tt.entryType, tt.entryID)
			}
		})
	}
}

// =============================================================================
// IsTombstoneContentHash Tests
// =============================================================================

func TestIsTombstoneContentHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"valid prefix", "TOMBSTONE:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"valid prefix short", "TOMBSTONE:abc", true}, // only checks prefix
		{"no prefix", "abcdef1234567890", false},
		{"empty", "", false},
		{"lowercase prefix", "tombstone:abc", false},
		{"partial prefix", "TOMBSTON", false},
		{"just prefix", "TOMBSTONE:", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsTombstoneContentHash(tt.hash)
			if got != tt.want {
				t.Errorf("IsTombstoneContentHash(%q) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

// =============================================================================
// ValidateTombstoneContentHash Tests
// =============================================================================

func TestValidateTombstoneContentHash_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash string
	}{
		{"all zeros", "TOMBSTONE:0000000000000000000000000000000000000000000000000000000000000000"},
		{"all f's", "TOMBSTONE:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"mixed hex", "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"sequential", "TOMBSTONE:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !ValidateTombstoneContentHash(tt.hash) {
				t.Errorf("ValidateTombstoneContentHash(%q) = false, want true", tt.hash)
			}
		})
	}
}

func TestValidateTombstoneContentHash_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"no prefix", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"too short", "TOMBSTONE:abcdef"},
		{"too long", "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a"},
		{"63 hex chars", "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b"},
		{"uppercase hex", "TOMBSTONE:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"},
		{"mixed case hex", "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6A1B2C3D4E5F6a1b2"},
		{"non-hex char g", "TOMBSTONE:g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"space in hex", "TOMBSTONE:a1b2c3d4e5f6a1b2 3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"lowercase prefix", "tombstone:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"wrong prefix", "DELETED:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"just prefix", "TOMBSTONE:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if ValidateTombstoneContentHash(tt.hash) {
				t.Errorf("ValidateTombstoneContentHash(%q) = true, want false", tt.hash)
			}
		})
	}
}

// =============================================================================
// IsValidTombstoneFormat Tests
// =============================================================================

func TestIsValidTombstoneFormat_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		entryID     string
		entryType   string
		companyID   string
		contentHash string
		timestamp   time.Time
	}{
		{
			name:        "standard tombstone",
			entryID:     "tomb_550e8400-e29b-41d4-a716-446655440000",
			entryType:   "tombstone",
			companyID:   "company-123",
			contentHash: "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			timestamp:   time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC),
		},
		{
			name:        "uppercase UUID",
			entryID:     "tomb_550E8400-E29B-41D4-A716-446655440000",
			entryType:   "tombstone",
			companyID:   "comp_abc",
			contentHash: "TOMBSTONE:0000000000000000000000000000000000000000000000000000000000000000",
			timestamp:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name:        "mixed case UUID",
			entryID:     "tomb_6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			entryType:   "tombstone",
			companyID:   "x",
			contentHash: "TOMBSTONE:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			timestamp:   time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := IsValidTombstoneFormat(tt.entryID, tt.entryType, tt.companyID, tt.contentHash, tt.timestamp)
			if err != nil {
				t.Errorf("IsValidTombstoneFormat() unexpected error: %v", err)
			}
		})
	}
}

func TestIsValidTombstoneFormat_InvalidEntryID(t *testing.T) {
	t.Parallel()

	validType := "tombstone"
	validCompany := "company-123"
	validHash := "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	validTime := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		entryID string
		wantErr string
	}{
		{"no prefix", "550e8400-e29b-41d4-a716-446655440000", "prefix"},
		{"wrong prefix", "req_550e8400-e29b-41d4-a716-446655440000", "prefix"},
		{"empty", "", "prefix"},
		{"prefix only", "tomb_", "36 characters"},
		{"UUID too short", "tomb_550e8400-e29b-41d4-a716", "36 characters"},
		{"UUID too long", "tomb_550e8400-e29b-41d4-a716-446655440000x", "36 characters"},
		{"UUID missing hyphen", "tomb_550e8400xe29b-41d4-a716-446655440000", "hyphens"},
		{"UUID non-hex char", "tomb_550g8400-e29b-41d4-a716-446655440000", "non-hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := IsValidTombstoneFormat(tt.entryID, validType, validCompany, validHash, validTime)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestIsValidTombstoneFormat_InvalidEntryType(t *testing.T) {
	t.Parallel()

	validID := "tomb_550e8400-e29b-41d4-a716-446655440000"
	validCompany := "company-123"
	validHash := "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	validTime := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		entryType string
	}{
		{"empty", ""},
		{"request", "request"},
		{"response", "response"},
		{"uppercase", "Tombstone"},
		{"all caps", "TOMBSTONE"},
		{"extra space", "tombstone "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := IsValidTombstoneFormat(validID, tt.entryType, validCompany, validHash, validTime)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "entryType") {
				t.Errorf("error %q should mention entryType", err.Error())
			}
		})
	}
}

func TestIsValidTombstoneFormat_InvalidCompanyID(t *testing.T) {
	t.Parallel()

	validID := "tomb_550e8400-e29b-41d4-a716-446655440000"
	validType := "tombstone"
	validHash := "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	validTime := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)

	err := IsValidTombstoneFormat(validID, validType, "", validHash, validTime)
	if err == nil {
		t.Fatal("expected error for empty companyID, got nil")
	}
	if !strings.Contains(err.Error(), "companyID") {
		t.Errorf("error %q should mention companyID", err.Error())
	}
}

func TestIsValidTombstoneFormat_InvalidContentHash(t *testing.T) {
	t.Parallel()

	validID := "tomb_550e8400-e29b-41d4-a716-446655440000"
	validType := "tombstone"
	validCompany := "company-123"
	validTime := time.Date(2026, 1, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"no prefix", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"too short", "TOMBSTONE:abc"},
		{"uppercase hex", "TOMBSTONE:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := IsValidTombstoneFormat(validID, validType, validCompany, tt.hash, validTime)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "contentHash") {
				t.Errorf("error %q should mention contentHash", err.Error())
			}
		})
	}
}

func TestIsValidTombstoneFormat_ZeroTimestamp(t *testing.T) {
	t.Parallel()

	validID := "tomb_550e8400-e29b-41d4-a716-446655440000"
	validType := "tombstone"
	validCompany := "company-123"
	validHash := "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	err := IsValidTombstoneFormat(validID, validType, validCompany, validHash, time.Time{})
	if err == nil {
		t.Fatal("expected error for zero timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error %q should mention timestamp", err.Error())
	}
}

func TestIsValidTombstoneFormat_FirstFailureReported(t *testing.T) {
	t.Parallel()

	// Multiple invalid fields — should report the first one (entryID)
	err := IsValidTombstoneFormat("bad", "bad", "", "bad", time.Time{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "entryID") {
		t.Errorf("first error should be about entryID, got: %v", err)
	}
}

// =============================================================================
// GenerateTombstoneContentHash Tests
// =============================================================================

func TestGenerateTombstoneContentHash_Format(t *testing.T) {
	t.Parallel()

	hash, err := GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("GenerateTombstoneContentHash() error: %v", err)
	}

	// Must have correct prefix
	if !strings.HasPrefix(hash, TombstoneContentHashPrefix) {
		t.Errorf("hash %q missing prefix %q", hash, TombstoneContentHashPrefix)
	}

	// Must be valid tombstone format
	if !ValidateTombstoneContentHash(hash) {
		t.Errorf("generated hash %q fails ValidateTombstoneContentHash", hash)
	}

	// Must be exactly 74 chars
	if len(hash) != tombstoneContentHashLen {
		t.Errorf("hash length = %d, want %d", len(hash), tombstoneContentHashLen)
	}
}

func TestGenerateTombstoneContentHash_Unique(t *testing.T) {
	t.Parallel()

	// Generate 100 hashes — all should be unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		hash, err := GenerateTombstoneContentHash()
		if err != nil {
			t.Fatalf("iteration %d: GenerateTombstoneContentHash() error: %v", i, err)
		}
		if seen[hash] {
			t.Fatalf("iteration %d: duplicate hash %q", i, hash)
		}
		seen[hash] = true
	}
}

func TestGenerateTombstoneContentHash_LowercaseHex(t *testing.T) {
	t.Parallel()

	hash, err := GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("GenerateTombstoneContentHash() error: %v", err)
	}

	// hex portion must be lowercase
	hexPart := hash[len(TombstoneContentHashPrefix):]
	if hexPart != strings.ToLower(hexPart) {
		t.Errorf("hex portion contains uppercase: %q", hexPart)
	}
}

func TestGenerateTombstoneContentHash_PassesValidation(t *testing.T) {
	t.Parallel()

	// Generate 50 hashes and verify each passes full validation
	for i := 0; i < 50; i++ {
		hash, err := GenerateTombstoneContentHash()
		if err != nil {
			t.Fatalf("iteration %d: error: %v", i, err)
		}
		if !ValidateTombstoneContentHash(hash) {
			t.Errorf("iteration %d: generated hash %q fails validation", i, hash)
		}
	}
}

// =============================================================================
// Delimiter safety (the half of the old chain-hash integration test that is a
// TOMBSTONE property; the ComputeChainHash half lives in chain_hash_test.go)
// =============================================================================

// TestTombstoneContentHash_IsDelimiterSafe asserts a generated tombstone content
// hash can never contain the chain-hash field separator.
//
// # Why this matters
//
// The chain hash concatenates its fields with '|'. content_hash is the LAST
// field, so a pipe inside it cannot shift a later field — but it could make the
// input string ambiguous with a different field assignment, and "the last field
// is safe" is a property of today's layout rather than of the format. Since a
// tombstone content hash is the one content_hash NOT produced by a hash function,
// it is the one place a stray byte could plausibly appear, so it gets pinned here.
//
// Structurally guaranteed by construction (prefix + hex), which is exactly why it
// is cheap to assert and would be expensive to discover the hard way.
func TestTombstoneContentHash_IsDelimiterSafe(t *testing.T) {
	t.Parallel()

	for i := 0; i < 64; i++ {
		contentHash, err := GenerateTombstoneContentHash()
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if strings.ContainsRune(contentHash, '|') {
			t.Fatalf("iteration %d: tombstone content hash contains the chain-hash "+
				"field separator: %q", i, contentHash)
		}
	}
}

// =============================================================================
// validateUUIDFormat Tests
// =============================================================================

func TestValidateUUIDFormat_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uuid string
	}{
		{"lowercase", "550e8400-e29b-41d4-a716-446655440000"},
		{"uppercase", "550E8400-E29B-41D4-A716-446655440000"},
		{"mixed case", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"all zeros", "00000000-0000-0000-0000-000000000000"},
		{"all f's", "ffffffff-ffff-ffff-ffff-ffffffffffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateUUIDFormat(tt.uuid); err != nil {
				t.Errorf("validateUUIDFormat(%q) error: %v", tt.uuid, err)
			}
		})
	}
}

func TestValidateUUIDFormat_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uuid string
	}{
		{"empty", ""},
		{"too short", "550e8400-e29b-41d4-a716"},
		{"too long", "550e8400-e29b-41d4-a716-4466554400001"},
		{"no hyphens", "550e8400e29b41d4a716446655440000xxxx"},
		{"wrong hyphen position", "550e840-0e29b-41d4-a716-446655440000"},
		{"non-hex character", "550g8400-e29b-41d4-a716-446655440000"},
		{"space", "550e8400-e29b-41d4-a716-44665544 000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateUUIDFormat(tt.uuid); err == nil {
				t.Errorf("validateUUIDFormat(%q) should return error", tt.uuid)
			}
		})
	}
}

// =============================================================================
// Gaps closed during the lift (absent from the producer suite)
// =============================================================================

// TestValidateTombstoneContentHash_RejectsDelimiter pins that the strict
// validator refuses a pipe in the payload.
//
// # Why the loose predicate is not enough
//
// IsTombstoneContentHash checks only the prefix, so it accepts "TOMBSTONE:"
// followed by anything — including a chain-hash field separator. The two
// functions are NOT interchangeable, and using the loose one where the strict
// one belongs would let a caller-supplied string reach the hash input. This test
// exists so that distinction is enforced rather than merely documented.
func TestValidateTombstoneContentHash_RejectsDelimiter(t *testing.T) {
	t.Parallel()

	// 64 payload chars with a pipe substituted in — correct length, wrong charset.
	payload := strings.Repeat("a", 63) + "|"
	bad := TombstoneContentHashPrefix + payload

	if len(bad) != len(TombstoneContentHashPrefix)+64 {
		t.Fatalf("test fixture is malformed: got length %d", len(bad))
	}
	if ValidateTombstoneContentHash(bad) {
		t.Fatal("strict validator accepted a pipe in the payload")
	}
	if !IsTombstoneContentHash(bad) {
		t.Fatal("loose predicate should still match on prefix alone — if this " +
			"fails the two functions are no longer meaningfully different")
	}
}

// =============================================================================
// Orphan tombstones — a DIFFERENT thing that shares the word
// =============================================================================

// TestComputeOrphanTombstoneContentHash_IsDerived asserts the orphan variant is
// a real hash, unlike the ordinary tombstone content hash.
//
// # The distinction being pinned
//
//	ordinary tombstone   "TOMBSTONE:" + 64 hex   RANDOM, not recomputable
//	orphan tombstone     128 hex                 DERIVED, recomputable
//
// Two different constructs share the word "tombstone". Conflating them would
// mean either treating a recomputable hash as unverifiable, or — far worse —
// expecting a random nonce to reproduce.
func TestComputeOrphanTombstoneContentHash_IsDerived(t *testing.T) {
	t.Parallel()

	const (
		company = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"
		entryID = "entry-1"
		path    = "gs://bucket/a/b.json"
		discov  = int64(1751068800000)
	)

	first := ComputeOrphanTombstoneContentHash(company, entryID, path, discov)
	if len(first) != 128 {
		t.Fatalf("orphan content hash is %d chars, want 128 (SHA-512 hex)", len(first))
	}
	if IsTombstoneContentHash(first) {
		t.Fatal("orphan content hash must NOT carry the TOMBSTONE: prefix — it is a " +
			"derived digest, not the random-nonce form")
	}
	if again := ComputeOrphanTombstoneContentHash(company, entryID, path, discov); again != first {
		t.Fatal("orphan content hash is not deterministic")
	}
}

// TestComputeOrphanTombstoneContentHash_BindsEveryField asserts each input is
// bound into the digest — an unbound field is one an attacker may rewrite.
func TestComputeOrphanTombstoneContentHash_BindsEveryField(t *testing.T) {
	t.Parallel()

	const (
		company = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"
		entryID = "entry-1"
		path    = "gs://bucket/a/b.json"
		discov  = int64(1751068800000)
	)
	base := ComputeOrphanTombstoneContentHash(company, entryID, path, discov)

	cases := []struct {
		field string
		got   string
	}{
		{"company_id", ComputeOrphanTombstoneContentHash(company+"x", entryID, path, discov)},
		{"entry_id", ComputeOrphanTombstoneContentHash(company, entryID+"x", path, discov)},
		{"payload_path", ComputeOrphanTombstoneContentHash(company, entryID, path+"x", discov)},
		{"discovery_ms", ComputeOrphanTombstoneContentHash(company, entryID, path, discov+1)},
	}
	for _, tc := range cases {
		if tc.got == base {
			t.Errorf("changing %s did not change the digest — the field is not bound", tc.field)
		}
	}
}

// TestComputeOrphanTombstoneContentHash_FieldsAreUnambiguous asserts that moving
// a character across a field boundary changes the digest.
//
// # What this catches
//
// The construction separates fields with a NUL byte. Without a separator,
// ("ab","c") and ("a","bc") would concatenate identically and collide — two
// different orphan records producing one digest. NUL is a sound choice precisely
// because it cannot occur in the identifiers being joined; this test pins the
// property rather than the mechanism.
func TestComputeOrphanTombstoneContentHash_FieldsAreUnambiguous(t *testing.T) {
	t.Parallel()

	const discov = int64(1751068800000)
	a := ComputeOrphanTombstoneContentHash("comp_ab", "c", "path", discov)
	b := ComputeOrphanTombstoneContentHash("comp_a", "bc", "path", discov)
	if a == b {
		t.Fatal("field boundaries are ambiguous: two different records collided")
	}
}
