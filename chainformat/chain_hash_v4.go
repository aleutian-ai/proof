// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// FormatV4 links through a salted leaf hash, so that erasure removes the
// fields and the salt and keeps every link recomputable
// (docs/format-spec.md §2.0, §5.0).
const FormatV4 = 4

// ChainHashPrefixV4 and LeafHashPrefixV4 are the domain-separation prefixes of
// the two v4 hashes. Exported for the same reason as [ChainHashPrefixV3].
const (
	ChainHashPrefixV4 = "aleutian.chain.v4:"
	LeafHashPrefixV4  = "aleutian.chain.leaf.v4:"
)

// SaltV4Bytes is the length of a v4 entry's salt before hex encoding. Its hex
// form, 64 lowercase characters, is what the leaf hash covers.
const SaltV4Bytes = 32

// MaxEntryFieldBytesV4 is the longest entry_id or entry_type a v4 entry may
// carry, in bytes.
const MaxEntryFieldBytesV4 = 256

// ErrTombstoneInV4 is returned for a v4 entry shaped like a v2 or v3
// tombstone: v4 has none (format-spec §2.0). A verifier reports it as
// format_field_misuse, not as a malformed field.
var ErrTombstoneInV4 = errors.New("a v4 entry has no tombstone type, tomb_ id or TOMBSTONE: content hash")

// NewSaltV4 mints a v4 entry's salt: 32 bytes from crypto/rand, hex encoded.
//
// # Description
//
// The writer that links an entry mints its salt; a caller never supplies one
// (format-spec §2.0). A salt shared by two entries, or chosen by a caller,
// would make a leaf hash guessable once the other entry is disclosed.
//
// # Outputs
//
//   - string: 64 lowercase hex characters
//   - error: only if the system's random source fails
//
// # Example
//
//	salt, err := chainformat.NewSaltV4()
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - crypto/rand is a cryptographically secure source.
func NewSaltV4() (string, error) {
	var b [SaltV4Bytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint salt: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ComputeLeafHashV4Unchecked computes a v4 entry's leaf hash.
//
// # Description
//
//	SHA-512("aleutian.chain.leaf.v4:" ‖ len(entryID) ‖ entryID
//	        ‖ len(entryType) ‖ entryType ‖ contentHash ‖ salt)
//
// len is a 4-byte big-endian byte count. entryID and entryType are hashed as
// given, never normalised: two spellings that hashed the same would be a field
// an editor could change unseen. contentHash and salt are hashed as their hex
// text.
//
// # Inputs
//
//   - entryID, entryType: as stored
//   - contentHash: 128 lowercase hex characters
//   - salt: 64 lowercase hex characters
//
// # Outputs
//
//   - string: 128 lowercase hex characters
//
// # Example
//
//	leaf := chainformat.ComputeLeafHashV4Unchecked(id, typ, contentHash, salt)
//
// # Limitations
//
//   - Validates nothing; see [ComputeLeafHashV4].
//
// # Assumptions
//
//   - Neither entryID nor entryType is longer than 2³²−1 bytes.
func ComputeLeafHashV4Unchecked(entryID, entryType, contentHash, salt string) string {
	h := sha512.New()
	var n [4]byte
	h.Write([]byte(LeafHashPrefixV4))
	binary.BigEndian.PutUint32(n[:], uint32(len(entryID)))
	h.Write(n[:])
	h.Write([]byte(entryID))
	binary.BigEndian.PutUint32(n[:], uint32(len(entryType)))
	h.Write(n[:])
	h.Write([]byte(entryType))
	h.Write([]byte(contentHash))
	h.Write([]byte(salt))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateLeafInputsV4 checks a v4 entry's leaf inputs.
//
// # Description
//
// A v4 entry shaped like a tombstone returns [ErrTombstoneInV4], checked
// first. Otherwise: entryID and entryType are each 1 to 256 bytes of valid
// UTF-8 with no control character, contentHash is 128 lowercase hex characters
// and salt is 64 (format-spec §2.0).
//
// # Inputs
//
//   - entryID, entryType, contentHash, salt: as for [ComputeLeafHashV4Unchecked]
//
// # Outputs
//
//   - error: nil, ErrTombstoneInV4, or a description of the first violation.
//     It names the field and its length, never its value.
//
// # Example
//
//	if err := chainformat.ValidateLeafInputsV4(id, typ, contentHash, salt); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - None.
func ValidateLeafInputsV4(entryID, entryType, contentHash, salt string) error {
	if entryType == TombstoneEntryType || strings.HasPrefix(entryID, TombstoneEntryIDPrefix) ||
		strings.HasPrefix(contentHash, TombstoneContentHashPrefix) {
		return ErrTombstoneInV4
	}
	if err := ValidateEntryFieldV4("entry_id", entryID); err != nil {
		return err
	}
	if err := ValidateEntryFieldV4("entry_type", entryType); err != nil {
		return err
	}
	if err := validateHashField("contentHash", contentHash, false); err != nil {
		return err
	}
	return ValidateSaltV4(salt)
}

// ValidateEntryFieldV4 checks a v4 entry_id or entry_type: 1 to 256 bytes of
// valid UTF-8 with no control character (U+0000 to U+001F, U+007F). name is
// used in the error, which never quotes the value.
func ValidateEntryFieldV4(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if len(value) > MaxEntryFieldBytesV4 {
		return fmt.Errorf("%s is %d bytes; at most %d", name, len(value), MaxEntryFieldBytesV4)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

// ValidateSaltV4 checks a v4 salt: 64 lowercase hex characters.
func ValidateSaltV4(salt string) error {
	if len(salt) != 2*SaltV4Bytes {
		return fmt.Errorf("salt must be %d lowercase hex chars, got %d", 2*SaltV4Bytes, len(salt))
	}
	for i := 0; i < len(salt); i++ {
		c := salt[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return errors.New("salt contains non-lowercase-hex characters")
		}
	}
	return nil
}

// ComputeLeafHashV4 validates its inputs and then computes the leaf hash.
//
// # Description
//
// The checked entry point; see [ValidateLeafInputsV4] for what is refused.
//
// # Inputs
//
//   - as for [ComputeLeafHashV4Unchecked]
//
// # Outputs
//
//   - string: 128 lowercase hex characters, or "" on error
//   - error: the first violation found
//
// # Example
//
//	leaf, err := chainformat.ComputeLeafHashV4(id, typ, contentHash, salt)
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - None.
func ComputeLeafHashV4(entryID, entryType, contentHash, salt string) (string, error) {
	if err := ValidateLeafInputsV4(entryID, entryType, contentHash, salt); err != nil {
		return "", fmt.Errorf("invalid leaf hash inputs: %w", err)
	}
	return ComputeLeafHashV4Unchecked(entryID, entryType, contentHash, salt), nil
}

// ComputeChainHashV4Unchecked computes the v4 chain hash.
//
// # Description
//
//	SHA-512("aleutian.chain.v4:" ‖ previousHash ‖ "|" ‖ globalSeq ‖ "|"
//	        ‖ timestamp ‖ "|" ‖ leafHash)
//
// v3's preimage with the leaf hash in place of the content hash. An erased
// entry keeps its leaf hash, so its chain hash is recomputed like any other.
//
// # Inputs
//
//   - previousHash: the previous entry's chain hash, or "" for the first entry
//   - globalSeq: the entry's chain-wide position; 0 exactly for the first entry
//   - timestamp: formatted as UTC to microsecond precision, truncated
//   - leafHash: 128 lowercase hex characters
//
// # Outputs
//
//   - string: 128 lowercase hex characters
//
// # Example
//
//	h := chainformat.ComputeChainHashV4Unchecked(prev, seq, ts, leaf)
//
// # Limitations
//
//   - Validates nothing; see [ComputeChainHashV4].
//
// # Assumptions
//
//   - As [ComputeChainHashV3Unchecked].
func ComputeChainHashV4Unchecked(previousHash string, globalSeq int64, timestamp time.Time, leafHash string) string {
	var buf [512]byte
	input := buf[:0]
	input = append(input, ChainHashPrefixV4...)
	input = append(input, previousHash...)
	input = append(input, '|')
	input = strconv.AppendInt(input, globalSeq, 10)
	input = append(input, '|')
	input = appendTimestampMicro(input, timestamp)
	input = append(input, '|')
	input = append(input, leafHash...)
	sum := sha512.Sum512(input)
	return hex.EncodeToString(sum[:])
}

// ValidateChainHashInputsV4 checks v4 chain hash inputs: previousHash empty or
// 128 lowercase hex, globalSeq non-negative, globalSeq 0 exactly when
// previousHash is empty (the first entry; format-spec §2.0), and leafHash 128
// lowercase hex.
func ValidateChainHashInputsV4(previousHash string, globalSeq int64, leafHash string) error {
	if err := validateHashField("previousHash", previousHash, true); err != nil {
		return err
	}
	if globalSeq < 0 {
		return fmt.Errorf("globalSeq must be non-negative, got %d", globalSeq)
	}
	if previousHash == "" && globalSeq != 0 {
		return fmt.Errorf("an entry with no predecessor is the first of its chain and has globalSeq 0, got %d"+
			"; a segment needs its predecessor's hash", globalSeq)
	}
	if previousHash != "" && globalSeq == 0 {
		return errors.New("an entry at globalSeq 0 is the first of its chain and has no predecessor")
	}
	return validateHashField("leafHash", leafHash, false)
}

// ComputeChainHashV4 validates its inputs and then computes the v4 chain hash.
//
// # Description
//
// The checked entry point; see [ValidateChainHashInputsV4] and
// [ValidateTimestamp] for what is refused.
//
// # Inputs
//
//   - as for [ComputeChainHashV4Unchecked]
//
// # Outputs
//
//   - string: 128 lowercase hex characters, or "" on error
//   - error: the first violation found
//
// # Example
//
//	h, err := chainformat.ComputeChainHashV4(prev, seq, ts, leaf)
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - None.
func ComputeChainHashV4(previousHash string, globalSeq int64, timestamp time.Time, leafHash string) (string, error) {
	if err := ValidateChainHashInputsV4(previousHash, globalSeq, leafHash); err != nil {
		return "", fmt.Errorf("invalid chain hash inputs: %w", err)
	}
	if err := ValidateTimestamp(timestamp); err != nil {
		return "", fmt.Errorf("invalid chain hash inputs: %w", err)
	}
	return ComputeChainHashV4Unchecked(previousHash, globalSeq, timestamp, leafHash), nil
}
