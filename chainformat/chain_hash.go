// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// chainHashDomainPrefix is the domain separation prefix for chain hash computation.
// It provides:
//   - Namespace isolation: prevents cross-context hash confusion with other SHA-512 uses
//   - Version identifier: "v2" identifies the SHA-512 chain hash algorithm
//   - Distinct terminator: ':' separates the domain prefix from field data (field
//     separator is '|'), eliminating any ambiguity between prefix and content
//
// v2 replaced v1 (SHA-256) to achieve ~2^170 quantum collision resistance (BHT)
// vs ~2^85 for SHA-256, matching NIST guidance for long-term tamper-evident logs.
// ChainHashPrefix is the domain-separation prefix for chain hashes.
//
// Exported because a verifier in another language must reproduce it exactly, and
// a constant a reimplementer has to guess at is a constant they will get wrong.
const ChainHashPrefix = "aleutian.chain.v2:"

// chainHashDomainPrefix is the internal alias retained so the hash body reads
// the same as the producer it was lifted from.
const chainHashDomainPrefix = ChainHashPrefix

// ComputeChainHashUnchecked computes the SHA-512 chain hash for an audit entry.
//
// Canonical bytes contract: docs/chain_canonical_bytes.md is the single
// source of truth shared by writer (chain-linker) and verifier (audit-api).
// Any change here is a hash-format version bump.
//
// # Description
//
// Computes the canonical chain hash that links each audit entry to its
// predecessor, forming an immutable append-only chain. This is the single
// source of truth for hash computation — both the chain linker (writing
// hashes) and the chain verifier (checking hashes) must use this function
// to guarantee identical output.
//
// The formula is:
//
//	SHA512("aleutian.chain.v2:" + previous_hash + "|" + run_id + "|" + sequence_num + "|" + timestamp + "|" + content_hash)
//
// The "aleutian.chain.v2:" domain prefix provides:
//   - Domain separation: prevents cross-context hash confusion
//   - Version identifier: v2 = SHA-512 (upgraded from v1 SHA-256)
//   - Distinct terminator: ':' vs '|' eliminates prefix/field ambiguity
//
// This matches the BigQuery SQL implementation:
//
//	TO_HEX(SHA512(CONCAT('aleutian.chain.v2:', prev_hash, '|', run_id, '|',
//	  CAST(seq AS STRING), '|',
//	  FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', timestamp), '|', content_hash)))
//
// # Inputs
//
//   - previousHash: The chain_hash of the previous entry in the chain.
//     For the first entry in a chain, use the empty string "".
//   - runID: The UUID identifying the batch run that linked this entry.
//   - sequenceNum: The entry's position within the batch run (0-indexed).
//   - timestamp: The entry's timestamp. Formatted as RFC3339 with microsecond
//     precision in UTC: "2006-01-02T15:04:05.000000Z". This matches BigQuery's
//     FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts). The time.Time type is used
//     (not int64 UnixMilli) because microsecond precision is required and the
//     BigQuery client returns time.Time for TIMESTAMP columns.
//   - contentHash: The SHA-512 hex digest of the entry's content payload
//     (128 lowercase hex characters). Produced by storage.ComputeContentHash.
//
// # Outputs
//
//   - string: Lowercase hex-encoded SHA-512 hash (128 characters).
//     Matches BigQuery's TO_HEX() output format.
//
// # Examples
//
// First entry in a chain (no predecessor):
//
//	hash := ComputeChainHash("", "run-550e8400", 0, entryTime, "a1b2c3...")
//
// Subsequent entry:
//
//	hash := ComputeChainHash(prevHash, "run-550e8400", 1, entryTime, "d4e5f6...")
//
// # Limitations
//
//   - Caller must ensure timestamp is the exact value stored in BigQuery.
//     Any precision loss (e.g., converting through int64 milliseconds) will
//     produce a different hash.
//   - The function does not validate inputs. Empty runID or contentHash will
//     produce a valid hash but may indicate a bug in the caller.
//
// # Assumptions
//
//   - previousHash is either "" (first entry) or a 128-character lowercase hex string (SHA-512 chain hash)
//   - runID is a non-empty UUID string that does NOT contain '|'
//   - sequenceNum is non-negative (0-indexed within the batch run)
//   - timestamp is in UTC (or will be converted to UTC internally)
//   - contentHash is exactly 128 lowercase hex characters (SHA-512, from storage.ComputeContentHash)
//   - The separator character is always '|' (pipe, ASCII 0x7C)
//   - The domain prefix is always "aleutian.chain.v2:" (with ':' terminator)
//   - No field may contain the separator '|' (delimiter safety invariant)
//
// Use [ValidateChainHashInputs] at API boundaries to enforce these constraints.
func ComputeChainHashUnchecked(previousHash, runID string, sequenceNum int64, timestamp time.Time, contentHash string) string {
	// Use a stack-allocated buffer for the hash input. Typical input is ~342 bytes:
	//   domain prefix (19) + previousHash (128) + run_id (36) + seq (1-19) +
	//   timestamp (27) + contentHash (128) + separators (4) = ~342
	// Maximum theoretical: 19+128+36+19+27+128+4 = 361 bytes.
	// Tombstone entries produce shorter preimages (307 bytes max, contentHash=74).
	// The 512-byte buffer handles all cases without heap allocation.
	var buf [512]byte
	input := buf[:0]

	// Build: "aleutian.chain.v2:" + previous_hash|run_id|sequence_num|timestamp|content_hash
	input = append(input, chainHashDomainPrefix...)
	input = append(input, previousHash...)
	input = append(input, '|')
	input = append(input, runID...)
	input = append(input, '|')
	input = strconv.AppendInt(input, sequenceNum, 10)
	input = append(input, '|')
	input = appendTimestampMicro(input, timestamp)
	input = append(input, '|')
	input = append(input, contentHash...)

	// Compute SHA-512. Sum512 uses a stack-allocated [64]byte return.
	sum := sha512.Sum512(input)

	// Return lowercase hex (matches BigQuery TO_HEX). 64 bytes → 128 hex chars.
	return hex.EncodeToString(sum[:])
}

// ValidateChainHashInputs validates that all inputs conform to the chain hash
// specification's delimiter safety invariant and field format constraints.
//
// # Description
//
// Enforces the following constraints on chain hash inputs:
//   - previousHash: Must be "" (first entry) or exactly 128 lowercase hex characters
//     (SHA-512 chain hash, FIPS 180-4 §6.4)
//   - runID: Must be non-empty and must NOT contain the pipe separator '|'
//   - sequenceNum: Must be non-negative (0-indexed within batch run)
//   - contentHash: Must be exactly 128 lowercase hex characters (SHA-512 content
//     hash, FIPS 180-4 §6.4). The content hash formula changed from SHA-256 (64 chars)
//     to SHA-512 (128 chars) in ticket 06_1. Callers still using old SHA-256 content
//     hashes must migrate to storage.ComputeContentHash.
//
// This function does NOT validate timestamps because time.Time cannot contain
// the pipe separator by construction (the timestamp is formatted internally by
// [ComputeChainHash]).
//
// # Inputs
//
//   - previousHash: The chain_hash of the previous entry (or "" for first entry)
//   - runID: The UUID identifying the batch run
//   - sequenceNum: The entry's position within the batch run
//   - contentHash: The SHA-512 hex digest of the entry's content (128 lowercase hex chars)
//
// # Outputs
//
//   - error: nil if all inputs are valid, or a descriptive error identifying
//     the first constraint violation found
//
// # Examples
//
// Validate at API boundary before computing hash:
//
//	if err := ValidateChainHashInputs(prev, runID, seq, content); err != nil {
//	    return fmt.Errorf("invalid chain hash inputs: %w", err)
//	}
//	hash := ComputeChainHash(prev, runID, seq, ts, content)
//
// # Limitations
//
//   - Does not validate timestamp (time.Time is inherently safe)
//   - Does not check whether previousHash actually exists in the chain
//   - Does not validate runID UUID format (only checks non-empty, no separator)
//
// # Assumptions
//
//   - Callers use this at API boundaries, not in hot loops (validation adds overhead)
//   - ComputeChainHash remains safe to call without validation (produces valid
//     but potentially meaningless hashes for invalid inputs)
//   - contentHash was produced by storage.ComputeContentHash (SHA-512, 128 hex chars)
//
// # Standards
//
//   - FIPS 180-4 §6.4: both previousHash (chain hash) and contentHash (content hash)
//     are SHA-512, 128 hex chars each.
func ValidateChainHashInputs(previousHash, runID string, sequenceNum int64, contentHash string) error {
	// previousHash: "" or exactly 128 lowercase hex chars (SHA-512 chain hash, FIPS 180-4 §6.4).
	if previousHash != "" {
		if len(previousHash) != 128 {
			return fmt.Errorf("previousHash must be empty or 128 hex chars (SHA-512), got %d chars", len(previousHash))
		}
		for i := 0; i < len(previousHash); i++ {
			c := previousHash[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return fmt.Errorf("previousHash contains non-lowercase-hex characters (must be lowercase hex)")
			}
		}
	}

	// runID: non-empty, no pipe separator
	if runID == "" {
		return errors.New("runID must be non-empty")
	}
	if strings.ContainsRune(runID, '|') {
		return fmt.Errorf("runID must not contain pipe separator '|'")
	}

	// sequenceNum: non-negative
	if sequenceNum < 0 {
		return fmt.Errorf("sequenceNum must be non-negative, got %d", sequenceNum)
	}

	// contentHash: exactly 128 lowercase hex characters (SHA-512, FIPS 180-4 §6.4),
	// OR a valid tombstone content hash (ValidateTombstoneContentHash).
	//
	// Tombstone entries use a special content hash format ("TOMBSTONE:" + 64 random
	// hex chars = 74 chars total) that is deliberately distinct from a real content hash.
	// They must be allowed through validation so chain linkage can include tombstone
	// entries in the chain without special-casing the linker.
	//
	// Full format validation (not just prefix) is required here to prevent malformed
	// inputs like "TOMBSTONE:BADDATA" from bypassing the content hash length check.
	if ValidateTombstoneContentHash(contentHash) {
		return nil
	}
	if len(contentHash) != 128 {
		return fmt.Errorf("contentHash must be exactly 128 lowercase hex chars (SHA-512), got %d chars", len(contentHash))
	}
	for i := 0; i < len(contentHash); i++ {
		c := contentHash[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("contentHash contains non-lowercase-hex characters (must be lowercase hex)")
		}
	}

	return nil
}

// appendTimestampMicro appends a timestamp formatted as "2006-01-02T15:04:05.000000Z"
// to the buffer without allocating. This matches BigQuery's
// FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts) output.
//
// The timestamp is always converted to UTC and truncated to microsecond precision.
// Nanoseconds beyond microseconds are discarded (floor, not round).
func appendTimestampMicro(buf []byte, t time.Time) []byte {
	t = t.UTC()
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	micro := t.Nanosecond() / 1000 // truncate to microseconds

	// Year: 4 digits, zero-padded
	buf = appendIntPadded(buf, year, 4)
	buf = append(buf, '-')
	// Month: 2 digits, zero-padded
	buf = appendIntPadded(buf, int(month), 2)
	buf = append(buf, '-')
	// Day: 2 digits, zero-padded
	buf = appendIntPadded(buf, day, 2)
	buf = append(buf, 'T')
	// Hour: 2 digits, zero-padded
	buf = appendIntPadded(buf, hour, 2)
	buf = append(buf, ':')
	// Minute: 2 digits, zero-padded
	buf = appendIntPadded(buf, min, 2)
	buf = append(buf, ':')
	// Second: 2 digits, zero-padded
	buf = appendIntPadded(buf, sec, 2)
	buf = append(buf, '.')
	// Microseconds: 6 digits, zero-padded
	buf = appendIntPadded(buf, micro, 6)
	buf = append(buf, 'Z')

	return buf
}

// appendIntPadded appends a non-negative integer to buf, zero-padded to the
// specified width. For example, appendIntPadded(buf, 5, 2) appends "05".
//
// If the integer has more digits than width, all digits are written (no truncation).
func appendIntPadded(buf []byte, val int, width int) []byte {
	// Format into a fixed temporary buffer (right-to-left).
	// Maximum width needed is 10 (for year 9999 or 6-digit microseconds).
	var tmp [10]byte
	pos := len(tmp)
	if val == 0 {
		pos--
		tmp[pos] = '0'
	} else {
		for val > 0 {
			pos--
			tmp[pos] = byte('0' + val%10)
			val /= 10
		}
	}
	// Zero-pad to desired width
	for len(tmp)-pos < width {
		pos--
		tmp[pos] = '0'
	}
	return append(buf, tmp[pos:]...)
}

// ComputeChainHash validates its inputs and then computes the chain hash.
//
// # Description
//
// This is the function to reach for. It runs [ValidateChainHashInputs] first and
// refuses to produce a hash for inputs that could be ambiguous, which
// [ComputeChainHashUnchecked] will happily do.
//
// # Why validation is not optional in practice
//
// The preimage is '|'-delimited and is NOT self-delimiting. Field boundaries are
// recoverable only because every other field has a fixed shape — so if
// previousHash is malformed, two DIFFERENT entries can produce the SAME hash:
//
//	previousHash="abc|d" runID="ef"     ─┐
//	                                     ├─►  "…:abc|d|ef|0|<ts>|<content>"
//	previousHash="abc"   runID="d|ef"   ─┘        identical preimage
//
// Note which rule does the work. Banning '|' in runID does NOT prevent this on
// its own: with a well-formed previousHash, pipes inside runID are harmless,
// because sequenceNum, timestamp and contentHash are all fixed-shape and the
// boundaries are recoverable from the right. **The load-bearing rule is that
// previousHash is either empty or exactly 128 lowercase hex characters.**
//
// In a closed producer this is safe by provenance — previousHash comes from the
// chain tail and runID from a UUID generator. A library has no such guarantee,
// which is why the validated form carries the shorter name here.
//
// # Inputs
//
//   - previousHash: preceding entry's chain hash; "" for the first entry
//   - runID: identifier for the batch that linked this entry
//   - sequenceNum: 0-indexed position WITHIN that run (not chain-wide)
//   - timestamp: entry timestamp; truncated to microseconds for hashing
//   - contentHash: 128-hex SHA-512, or a tombstone content hash
//
// # Outputs
//
//   - string: 128-character lowercase hex SHA-512
//   - error: wrapping the first validation failure; the hash is "" on error
//
// # Example
//
//	h, err := chainformat.ComputeChainHash(prev, runID, seq, ts, contentHash)
//	if err != nil {
//	    return fmt.Errorf("link entry %s: %w", entryID, err)
//	}
//
// # Limitations
//
//   - Proves nothing about a chain as a WHOLE. See the package documentation on
//     what chain hashing does and does not detect.
//
// # Assumptions
//
//   - The caller stores the timestamp in the exact form it was hashed in.
//     Re-deriving it from a lower-precision value changes the hash.
func ComputeChainHash(previousHash, runID string, sequenceNum int64, timestamp time.Time, contentHash string) (string, error) {
	if err := ValidateChainHashInputs(previousHash, runID, sequenceNum, contentHash); err != nil {
		return "", fmt.Errorf("chainformat: compute chain hash: %w", err)
	}
	return ComputeChainHashUnchecked(previousHash, runID, sequenceNum, timestamp, contentHash), nil
}
