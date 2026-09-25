// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// ChainHashPrefixV3 is the domain-separation prefix for v3 chain hashes.
//
// Exported because a verifier in another language must reproduce it exactly,
// and a constant a reimplementer has to guess at is a constant they will get
// wrong. The ':' terminator distinguishes the prefix from field data, which is
// separated by '|'.
const ChainHashPrefixV3 = "aleutian.chain.v3:"

// Chain hash format versions. An entry records which preimage produced its
// hash, because the two cannot be told apart by looking at the digest.
//
// Zero means v2, deliberately: every entry written before v3 existed has no
// version field at all, and an absent field decodes as zero. Treating zero as
// "the format that was current when versions were not recorded" is what keeps
// those entries verifiable without rewriting them.
const (
	// FormatV2 binds run_id and a batch-local sequence_num.
	FormatV2 = 2

	// FormatV3 binds global_seq and has no run id.
	FormatV3 = 3
)

// NormalizeFormatVersion maps a stored version field onto a known format.
//
// # Description
//
// Zero — an absent field on an entry written before versions were recorded —
// means v2. Every other value is returned unchanged, including unknown ones,
// so a caller can reject them explicitly rather than have them quietly
// treated as a format they are not.
//
// # Inputs
//
//   - version: the entry's recorded format version, possibly zero
//
// # Outputs
//
//   - int: FormatV2 for zero, otherwise version unchanged
//
// # Example
//
//	switch chainformat.NormalizeFormatVersion(e.FormatVersion) {
//	case chainformat.FormatV2: // …
//	case chainformat.FormatV3: // …
//	default: return fmt.Errorf("unknown format version %d", e.FormatVersion)
//	}
//
// # Limitations
//
//   - Does not validate that the version is one this build understands.
//
// # Assumptions
//
//   - No format will ever be numbered 0.
func NormalizeFormatVersion(version int) int {
	if version == 0 {
		return FormatV2
	}
	return version
}

// ComputeChainHashV3Unchecked computes the v3 SHA-512 chain hash for an entry.
//
// # Description
//
// v3 exists to make a chain a property of its ENTRIES rather than of the API
// calls that happened to create it:
//
//	v2  SHA-512("aleutian.chain.v2:" ‖ prev|run_id|sequence_num|ts|content)
//	v3  SHA-512("aleutian.chain.v3:" ‖ prev|global_seq|ts|content)
//
// v2 binds run_id and a BATCH-LOCAL sequence_num, so the same entries in the
// same order hash differently depending on how they were grouped into append
// calls — appending A and B together does not equal appending A then B. That
// makes a chain impossible to reconstruct from its entries alone, since the
// batch boundaries are part of the artefact and are nowhere recorded.
//
// v3 binds global_seq, the entry's chain-wide position, which v2 never hashed
// at all. The result is batch-independent: the hashes depend only on what was
// appended and in what order.
//
// v2 is NOT deprecated by this and NOT rewritten. Existing chains are v2 and
// verify as v2 forever; see [ComputeChainHashUnchecked].
//
// # Inputs
//
//   - previousHash: the previous entry's chain hash, or "" for the first entry
//   - globalSeq: the entry's chain-wide position, non-negative
//   - timestamp: the entry timestamp; formatted as UTC to microsecond precision
//   - contentHash: 128 lowercase hex characters, or a tombstone content hash
//
// # Outputs
//
//   - string: 128 lowercase hex characters
//
// # Example
//
//	h := chainformat.ComputeChainHashV3Unchecked("", 0, ts, contentHash)
//
// # Limitations
//
//   - Validates nothing. Use [ComputeChainHashV3] at API boundaries, or
//     [ValidateChainHashInputsV3] directly; this variant will happily hash
//     malformed input into a valid-looking but meaningless digest.
//
// # Assumptions
//
//   - No field contains the '|' separator. globalSeq and the timestamp cannot
//     by construction; previousHash and contentHash are checked by
//     [ValidateChainHashInputsV3].
//   - timestamp carries at most microsecond precision that matters; anything
//     finer is truncated (floor), exactly as in v2.
func ComputeChainHashV3Unchecked(previousHash string, globalSeq int64, timestamp time.Time, contentHash string) string {
	// Stack-allocated: prefix (18) + previousHash (128) + globalSeq (≤19) +
	// timestamp (27) + contentHash (128) + separators (3) = 323 bytes maximum.
	var buf [512]byte
	input := buf[:0]

	input = append(input, ChainHashPrefixV3...)
	input = append(input, previousHash...)
	input = append(input, '|')
	input = strconv.AppendInt(input, globalSeq, 10)
	input = append(input, '|')
	input = appendTimestampMicro(input, timestamp)
	input = append(input, '|')
	input = append(input, contentHash...)

	sum := sha512.Sum512(input)
	return hex.EncodeToString(sum[:])
}

// ValidateChainHashInputsV3 checks v3 chain hash inputs.
//
// # Description
//
// Enforces the delimiter-safety invariant and the field formats: a previous
// hash that is empty or 128 lowercase hex characters, a non-negative
// global sequence, and a content hash that is either 128 lowercase hex
// characters or a well-formed tombstone value.
//
// Unlike v2 there is no run id to check — v3 does not have one.
//
// # Inputs
//
//   - previousHash: the previous entry's chain hash, or ""
//   - globalSeq: the entry's chain-wide position
//   - contentHash: the entry's content hash or tombstone value
//
// # Outputs
//
//   - error: nil, or a description of the first violation found
//
// # Example
//
//	if err := chainformat.ValidateChainHashInputsV3(prev, seq, content); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Does not validate the timestamp: a time.Time cannot contain the
//     separator, and the formatter handles precision.
//   - Does not check that previousHash exists in any chain.
//
// # Assumptions
//
//   - Called at API boundaries rather than in hot loops.
func ValidateChainHashInputsV3(previousHash string, globalSeq int64, contentHash string) error {
	if err := validateHashField("previousHash", previousHash, true); err != nil {
		return err
	}
	if globalSeq < 0 {
		return fmt.Errorf("globalSeq must be non-negative, got %d", globalSeq)
	}
	// Tombstones carry "TOMBSTONE:" + 64 hex characters instead of a content
	// hash, so that an erased entry still links. Full-format validation, not a
	// prefix test, so "TOMBSTONE:BADDATA" cannot slip past the length check.
	if ValidateTombstoneContentHash(contentHash) {
		return nil
	}
	return validateHashField("contentHash", contentHash, false)
}

// validateHashField checks a 128-character lowercase hex SHA-512 digest,
// optionally allowing the empty string for the first entry in a chain.
func validateHashField(name, value string, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s must be exactly 128 lowercase hex chars (SHA-512), got 0", name)
	}
	if len(value) != 128 {
		return fmt.Errorf("%s must be %sexactly 128 lowercase hex chars (SHA-512), got %d chars",
			name, emptyOr(allowEmpty), len(value))
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%s contains non-lowercase-hex characters (must be lowercase hex)", name)
		}
	}
	return nil
}

// emptyOr returns the "empty or " qualifier for fields where "" is legal.
func emptyOr(allowEmpty bool) string {
	if allowEmpty {
		return "empty or "
	}
	return ""
}

// ComputeChainHashV3 validates its inputs and then computes the v3 chain hash.
//
// # Description
//
// The checked entry point. Prefer it anywhere the inputs came from outside the
// process — a malformed hash that is computed anyway propagates into a chain
// nobody can verify, and the error is discovered far from its cause.
//
// # Inputs
//
//   - previousHash: the previous entry's chain hash, or "" for the first entry
//   - globalSeq: the entry's chain-wide position, non-negative
//   - timestamp: the entry timestamp
//   - contentHash: 128 lowercase hex characters, or a tombstone content hash
//
// # Outputs
//
//   - string: 128 lowercase hex characters, or "" on error
//   - error: the first input violation found
//
// # Example
//
//	h, err := chainformat.ComputeChainHashV3(prev, seq, ts, contentHash)
//	if err != nil {
//	    return fmt.Errorf("chain hash: %w", err)
//	}
//
// # Limitations
//
//   - Validation costs a pass over two 128-character strings; in a tight
//     linking loop with already-validated inputs, use the Unchecked variant.
//
// # Assumptions
//
//   - As [ComputeChainHashV3Unchecked].
func ComputeChainHashV3(previousHash string, globalSeq int64, timestamp time.Time, contentHash string) (string, error) {
	if err := ValidateChainHashInputsV3(previousHash, globalSeq, contentHash); err != nil {
		return "", fmt.Errorf("invalid chain hash inputs: %w", err)
	}
	return ComputeChainHashV3Unchecked(previousHash, globalSeq, timestamp, contentHash), nil
}
