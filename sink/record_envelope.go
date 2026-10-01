// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// The record-signing envelope, aleutian.proof.record.v1: the exact bytes a
// record signature covers (docs/sink-format.md, Record signatures).
//
//	"aleutian.proof.record.v1" 0x00
//	‖ field(1, chain_id) ‖ field(2, entry_id) ‖ field(3, entry_type)
//	‖ field(4, global_seq) ‖ field(5, previous_hash) ‖ field(6, timestamp)
//	‖ field(7, content_hash) ‖ field(8, signing_key_id)
//
//	field(tag, v) = tag (1 byte) ‖ len(v) (uint32 big-endian) ‖ v
//
// Every value is ASCII, in the string encoding format-spec already gives that
// field, so nothing is decoded and a verifier in any language reuses its
// chain-hash encoders. Length-prefixed binary rather than canonical JSON: one
// encoding, no escaping. The version lives in the domain string only.
//
// previous_hash is signed so record signatures chain like the entries do: a
// signature orphaned by a failed or crashed commit can then only stand in at
// the chain's tail, never be spliced into the middle. It is empty exactly when
// global_seq is 0.
//
// Purpose-built for the sink: it shares no code with anchors or capture_v3.

// recordDomain opens every envelope. The trailing NUL ends it: no field value
// holds a NUL, and an anchor's signed bytes begin with '{'.
const recordDomain = "aleutian.proof.record.v1\x00"

var (
	// lowerHex128 is a SHA-512 content hash as the chain stores it.
	lowerHex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
	// lowerHex32 is a key id as keyfile.KeyIDHex prints it.
	lowerHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// recordFields are the seven values a record signature covers.
type recordFields struct {
	chainID     string
	entryID     string
	entryType   string
	globalSeq   int64
	prevHash    string // the previous entry's chain hash; "" for the first entry
	timestamp   time.Time
	contentHash string
	keyID       string
}

// recordEnvelope returns the envelope for f, refusing any value the sink would
// never write: a record signature must never cover something Verify could not
// rebuild exactly.
func recordEnvelope(f recordFields) ([]byte, error) {
	if !ValidChainID(f.chainID) {
		return nil, errors.New("sink: record envelope: not a chain id this sink mints")
	}
	if !entryIDPattern.MatchString(f.entryID) {
		return nil, errors.New("sink: record envelope: not an entry id this sink assigns")
	}
	if f.entryType != EntryTypeEvent && f.entryType != EntryTypeErasure {
		return nil, errors.New("sink: record envelope: not an entry type this sink writes")
	}
	if f.globalSeq < 0 {
		return nil, fmt.Errorf("sink: record envelope: sequence %d is negative", f.globalSeq)
	}
	switch {
	case f.globalSeq == 0 && f.prevHash != "":
		return nil, errors.New("sink: record envelope: the first entry has no previous hash")
	case f.globalSeq > 0 && !lowerHex128.MatchString(f.prevHash):
		return nil, errors.New("sink: record envelope: previous hash is not 128 lowercase hex")
	}
	if f.timestamp.IsZero() {
		return nil, errors.New("sink: record envelope: the timestamp is unset")
	}
	if y := f.timestamp.UTC().Year(); y < 1 || y > 9999 {
		return nil, fmt.Errorf("sink: record envelope: year %d is outside 0001-9999", y)
	}
	if !lowerHex128.MatchString(f.contentHash) {
		return nil, errors.New("sink: record envelope: content hash is not 128 lowercase hex")
	}
	if !lowerHex32.MatchString(f.keyID) {
		return nil, errors.New("sink: record envelope: key id is not 32 lowercase hex")
	}

	values := []string{
		f.chainID,
		f.entryID,
		f.entryType,
		strconv.FormatInt(f.globalSeq, 10),
		f.prevHash,
		// format-spec §4: UTC, six fractional digits; Format truncates.
		f.timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
		f.contentHash,
		f.keyID,
	}
	env := make([]byte, 0, 640)
	env = append(env, recordDomain...)
	for i, v := range values {
		env = append(env, byte(i+1))
		env = binary.BigEndian.AppendUint32(env, uint32(len(v)))
		env = append(env, v...)
	}
	return env, nil
}
