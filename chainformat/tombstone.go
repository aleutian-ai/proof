// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Constants
// =============================================================================

// TombstoneContentHashPrefix is the prefix used for tombstone content hashes.
//
// When an entry is hard-deleted, a tombstone replaces it in the chain. The
// tombstone's content hash uses this prefix followed by 64 random hex characters
// (32 bytes), ensuring it cannot be confused with a real content hash (which is
// a raw SHA-256 digest). The random bytes prevent correlation between the
// tombstone and the original entry's content.
//
// Format: "TOMBSTONE:" + 64 lowercase hex chars = 74 chars total.
const TombstoneContentHashPrefix = "TOMBSTONE:"

// TombstoneEntryIDPrefix is the prefix used for tombstone entry IDs.
//
// Tombstone entry IDs use this prefix followed by a UUID, enabling O(1)
// identification of tombstones by entry ID without reading other fields.
//
// Format: "tomb_" + UUID (36 chars) = 41 chars total.
const TombstoneEntryIDPrefix = "tomb_"

// TombstoneEntryType is the entry_type value for tombstone entries.
//
// This is the canonical value stored in the entry_type column of audit_entries
// for tombstone entries.
const TombstoneEntryType = "tombstone"

// tombstoneContentHashLen is the total length of a valid tombstone content hash.
// "TOMBSTONE:" (10) + 64 hex chars = 74.
const tombstoneContentHashLen = len(TombstoneContentHashPrefix) + 64

// tombstoneRandomBytesLen is the number of random bytes used to generate
// the tombstone content hash (32 bytes = 64 hex chars).
const tombstoneRandomBytesLen = 32

// =============================================================================
// Detection Functions
// =============================================================================

// IsTombstone checks whether an entry is a tombstone based on its entry_type
// and entry_id prefix.
//
// # Description
//
// Performs a fast check using two fields that are always present in audit_entries
// rows. Both conditions must be true for the entry to be identified as a tombstone:
//   - entryType must equal "tombstone" (exact match, case-sensitive)
//   - entryID must start with "tomb_" prefix
//
// This function does NOT validate the full tombstone format (e.g., UUID after
// the prefix, content hash format). Use [IsValidTombstoneFormat] for full
// validation.
//
// # Inputs
//
//   - entryType: The entry_type column value from audit_entries
//   - entryID: The entry_id column value from audit_entries
//
// # Outputs
//
//   - bool: true if the entry is a tombstone, false otherwise
//
// # Examples
//
// Tombstone entry:
//
//	IsTombstone("tombstone", "tomb_550e8400-e29b-41d4-a716-446655440000") // true
//
// Regular entry:
//
//	IsTombstone("request", "req_550e8400-e29b-41d4-a716-446655440000") // false
//
// Partial match (both conditions required):
//
//	IsTombstone("tombstone", "req_12345") // false (wrong ID prefix)
//	IsTombstone("request", "tomb_12345")  // false (wrong type)
//
// # Limitations
//
//   - Does not validate UUID format after the "tomb_" prefix
//   - Case-sensitive: "Tombstone" or "TOMBSTONE" entry types return false
//
// # Assumptions
//
//   - entryType and entryID come from trusted storage (already persisted)
//   - Both fields are non-empty for valid audit entries
func IsTombstone(entryType, entryID string) bool {
	return entryType == TombstoneEntryType && strings.HasPrefix(entryID, TombstoneEntryIDPrefix)
}

// IsTombstoneContentHash checks whether a content hash uses the tombstone format.
//
// # Description
//
// A lighter check than [ValidateTombstoneContentHash] — only verifies the prefix
// is present, not the full format. Useful for quick classification in hot paths
// where full validation is performed elsewhere.
//
// # Inputs
//
//   - contentHash: The content_hash column value from audit_entries
//
// # Outputs
//
//   - bool: true if contentHash starts with "TOMBSTONE:", false otherwise
//
// # Examples
//
//	IsTombstoneContentHash("TOMBSTONE:abcdef...") // true
//	IsTombstoneContentHash("a1b2c3d4e5f6...")     // false
//
// # Limitations
//
//   - Does not validate hex format or length after prefix
//   - Use [ValidateTombstoneContentHash] for full format validation
//
// # Assumptions
//
//   - contentHash comes from trusted storage
func IsTombstoneContentHash(contentHash string) bool {
	return strings.HasPrefix(contentHash, TombstoneContentHashPrefix)
}

// =============================================================================
// Validation Functions
// =============================================================================

// ValidateTombstoneContentHash validates that a content hash has the correct
// tombstone format.
//
// # Description
//
// A valid tombstone content hash is:
//
//	"TOMBSTONE:" + 64 lowercase hexadecimal characters
//
// Total length: 74 characters.
//
// # Inputs
//
//   - contentHash: The content_hash value to validate
//
// # Outputs
//
//   - bool: true if the content hash has valid tombstone format, false otherwise
//
// # Examples
//
//	ValidateTombstoneContentHash("TOMBSTONE:a1b2...64 hex chars...") // true
//	ValidateTombstoneContentHash("TOMBSTONE:ABC1...")                // false (uppercase)
//	ValidateTombstoneContentHash("TOMBSTONE:short")                 // false (too short)
//	ValidateTombstoneContentHash("a1b2c3...")                       // false (no prefix)
//
// # Limitations
//
//   - Only validates format, not whether the random bytes were generated securely
//   - Returns bool (not error) for use in conditional checks
//
// # Assumptions
//
//   - Valid hex characters are [0-9a-f] (lowercase only, matching chain hash output)
func ValidateTombstoneContentHash(contentHash string) bool {
	if len(contentHash) != tombstoneContentHashLen {
		return false
	}
	if !strings.HasPrefix(contentHash, TombstoneContentHashPrefix) {
		return false
	}
	// Validate hex portion (after "TOMBSTONE:" prefix)
	hexPart := contentHash[len(TombstoneContentHashPrefix):]
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsValidTombstoneFormat validates that a tombstone entry has correct format
// across all required fields.
//
// # Description
//
// Performs comprehensive validation of tombstone entry fields:
//   - EntryID: Must start with "tomb_" followed by a valid UUID (36 chars, 8-4-4-4-12 hex with hyphens)
//   - EntryType: Must be exactly "tombstone"
//   - Subject: Must be non-empty
//   - ContentHash: Must match tombstone format ("TOMBSTONE:" + 64 hex chars)
//   - Timestamp: Must not be the zero value
//
// Returns nil if all validations pass, or a descriptive error identifying
// the first constraint violation found.
//
// # Inputs
//
//   - entryID: The tombstone's entry_id
//   - entryType: The tombstone's entry_type
//   - subject: The tombstone's subject (the namespace the chain is about).
//     Named company_id before 2026-09-23; the rename is a parameter name only
//     and changes no bytes, since this function validates rather than encodes.
//   - contentHash: The tombstone's content_hash
//   - timestamp: The tombstone's timestamp (should match original entry)
//
// # Outputs
//
//   - error: nil if valid, or descriptive error for the first violation
//
// # Examples
//
// Valid tombstone:
//
//	err := IsValidTombstoneFormat(
//	    "tomb_550e8400-e29b-41d4-a716-446655440000",
//	    "tombstone",
//	    "company-123",
//	    "TOMBSTONE:a1b2c3d4...64 hex chars...",
//	    time.Now(),
//	)
//	// err == nil
//
// Invalid entry ID:
//
//	err := IsValidTombstoneFormat("req_12345", ...)
//	// err: "entryID must start with \"tomb_\" prefix"
//
// # Limitations
//
//   - Does not validate that the timestamp matches any original entry
//   - Does not validate RunID, SequenceNum, or other chain-related fields
//   - Does not check uniqueness of the entryID
//   - Uses individual parameters to avoid coupling to storage.TombstoneEntry
//
// # Assumptions
//
//   - Caller has all required fields available
//   - UUID format is standard: 8-4-4-4-12 hex characters with hyphens
func IsValidTombstoneFormat(entryID, entryType, subject, contentHash string, timestamp time.Time) error {
	// Validate entryID: "tomb_" + UUID (36 chars)
	if !strings.HasPrefix(entryID, TombstoneEntryIDPrefix) {
		return fmt.Errorf("chainformat: entryID must start with %q prefix, got %q", TombstoneEntryIDPrefix, truncateForError(entryID, 20))
	}
	uuidPart := entryID[len(TombstoneEntryIDPrefix):]
	if err := validateUUIDFormat(uuidPart); err != nil {
		return fmt.Errorf("chainformat: entryID UUID portion invalid: %w", err)
	}

	// Validate entryType
	if entryType != TombstoneEntryType {
		return fmt.Errorf("chainformat: entryType must be %q, got %q", TombstoneEntryType, entryType)
	}

	// Validate subject
	if subject == "" {
		return fmt.Errorf("chainformat: subject must be non-empty")
	}

	// Validate contentHash
	if !ValidateTombstoneContentHash(contentHash) {
		return fmt.Errorf("chainformat: contentHash must be %q followed by 64 lowercase hex chars (got length %d)", TombstoneContentHashPrefix, len(contentHash))
	}

	// Validate timestamp
	if timestamp.IsZero() {
		return fmt.Errorf("chainformat: timestamp must not be zero")
	}

	return nil
}

// =============================================================================
// Generation Functions
// =============================================================================

// GenerateTombstoneContentHash creates a cryptographically random tombstone
// content hash.
//
// # Description
//
// Generates 32 random bytes using crypto/rand and formats them as a tombstone
// content hash: "TOMBSTONE:" + lowercase hex encoding of the random bytes.
//
// The random bytes ensure that:
//   - No two tombstones share the same content hash (collision probability: 2^-128)
//   - The tombstone cannot be correlated with the original entry's content
//   - The tombstone's chain hash is unique and unpredictable
//
// # Outputs
//
//   - string: A valid tombstone content hash (74 characters total)
//   - error: Non-nil if crypto/rand fails (system entropy exhaustion)
//
// # Examples
//
//	hash, err := GenerateTombstoneContentHash()
//	if err != nil {
//	    return fmt.Errorf("chainformat: generate tombstone content hash: %w", err)
//	}
//	// hash = "TOMBSTONE:a1b2c3d4...64 hex chars..."
//
// # Limitations
//
//   - Returns error on crypto/rand failure (extremely rare on modern systems)
//   - Output is not deterministic (by design)
//
// # Assumptions
//
//   - crypto/rand is available and functional (OS entropy source)
//   - The caller will use this as the content_hash for a tombstone entry
func GenerateTombstoneContentHash() (string, error) {
	var randomBytes [tombstoneRandomBytesLen]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("chainformat: read random bytes for tombstone: %w", err)
	}
	return TombstoneContentHashPrefix + hex.EncodeToString(randomBytes[:]), nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// validateUUIDFormat checks that a string is a valid UUID format (8-4-4-4-12).
// Does not validate UUID version or variant bits — only structural format.
func validateUUIDFormat(s string) error {
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	if len(s) != 36 {
		return fmt.Errorf("chainformat: UUID must be 36 characters, got %d", len(s))
	}
	// Check hyphen positions: 8, 13, 18, 23
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return fmt.Errorf("chainformat: UUID must have hyphens at positions 8, 13, 18, 23")
	}
	// Check hex characters in all other positions
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue // already checked hyphens
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("chainformat: UUID contains non-hex character %q at position %d", c, i)
		}
	}
	return nil
}

// truncateForError truncates a string for inclusion in error messages,
// appending "..." if truncated.
func truncateForError(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// OrphanTombstoneDomainPrefix domain-separates the orphan-tombstone content
// hash preimage from every other hash in the system.
//
// code_audit_92 R6/R7. Orphan tombstones previously carried a 128-zero
// sentinel: a compile-time constant, identical in every tenant, that bound
// nothing about the object it attested to. Because the chain hash preimage is
// only (prev_hash, run_id, seq, timestamp, content_hash), and payload_path is
// NOT in it, that made payload_path — the record's entire evidentiary claim —
// unprotected by the chain. Rewriting it left every verifier reporting valid.
//
// NOTE ON SHAPE: unlike the hard-delete TombstoneContentHashPrefix, this value
// is NOT prepended to the stored hash. Hard-delete tombstones are DML-inserted
// straight into audit_entries and never traverse the linker; orphan tombstones
// go through the reference platform's linker, whose content_hash allowlist
// admits only ^[a-f0-9]{128}$ or ^TOMBSTONE:[a-f0-9]{64}$ and dead-letters
// everything else. A prefixed orphan hash would therefore never link. The domain
// separation is applied INSIDE the preimage instead, so the stored value keeps
// the 128-hex shape while remaining unforgeable and non-constant. Making the
// shape self-identifying as well would require extending that allowlist, which
// is an open format decision.
const OrphanTombstoneDomainPrefix = "aleutian.orphan.tombstone.v1"

// ComputeOrphanTombstoneContentHash derives the content hash for an orphan
// tombstone by binding the claim the tombstone makes.
//
// # Description
//
// Returns SHA-512 over a NUL-delimited canonical form of the assertion:
// "at discovery time T, company C had an unreferenced payload object at path P
// with entry id E". NUL is not legal in any of the inputs (company ids are
// comp_<ULID>, entry ids are UUIDs, GCS paths cannot contain NUL), so the
// encoding is unambiguous and no length-extension between fields is possible.
//
// This welds payload_path into the chain: the chain hash covers content_hash,
// content_hash now covers payload_path, so altering the path invalidates the
// chain from that entry onward.
//
// # Inputs
//
//   - companyID: canonical comp_<ULID> owning the payload
//   - entryID: the entry id parsed from the object path
//   - payloadPath: the full GCS object path being tombstoned
//   - discoveryMs: discovery time in Unix milliseconds (the tombstone's timestamp)
//
// # Outputs
//
//   - string: 128 lowercase hex chars, satisfying the linker's content_hash allowlist
//
// # Example
//
//	h := chain.ComputeOrphanTombstoneContentHash(cid, entryID, path, now.UnixMilli())
//
// # Limitations
//
//   - Shape-indistinguishable from a real SHA-512 content hash; entry_type is
//     the discriminator until the linker allowlist is extended.
//   - Not a digest of the payload BYTES — the job never reads the object. A
//     content-recomputing verifier must exclude this entry type.
//
// # Assumptions
//
//   - Inputs contain no NUL bytes (guaranteed by their respective grammars).
func ComputeOrphanTombstoneContentHash(companyID, entryID, payloadPath string, discoveryMs int64) string {
	h := sha512.New()
	h.Write([]byte(OrphanTombstoneDomainPrefix))
	h.Write([]byte{0})
	h.Write([]byte(companyID))
	h.Write([]byte{0})
	h.Write([]byte(entryID))
	h.Write([]byte{0})
	h.Write([]byte(payloadPath))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(discoveryMs, 10)))
	return hex.EncodeToString(h.Sum(nil))
}
