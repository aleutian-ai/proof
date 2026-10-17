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

	"github.com/aleutian-ai/proof/chainformat"
)

// recordContext is the ML-DSA context string an envelope is signed with: the
// v2 context for a record.v2 envelope, none for record.v1.
func recordContext(env []byte) string {
	if len(env) >= len(recordDomainV2) && string(env[:len(recordDomainV2)]) == recordDomainV2 {
		return RecordContextV2
	}
	return ""
}

// The record-signing envelopes: the exact bytes a record signature covers
// (docs/sink-format.md §9.1). aleutian.proof.record.v2, for a v4 entry, is
// what this sink writes; aleutian.proof.record.v1, for a v3 entry, is verified
// and never written.
//
//	"aleutian.proof.record.v2" 0x00
//	‖ field(1, chain_id) ‖ field(2, entry_id) ‖ field(3, entry_type)
//	‖ field(4, global_seq) ‖ field(5, previous_hash) ‖ field(6, timestamp)
//	‖ field(7, content_hash) ‖ field(8, signing_key_id) ‖ field(9, leaf_hash)
//
// v2 is signed with the ML-DSA context "aleutian.proof.record.v2"; v1, which
// stops at field 8, with the empty context.
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
const (
	recordDomain   = "aleutian.proof.record.v1\x00"
	recordDomainV2 = "aleutian.proof.record.v2\x00"

	// RecordContextV2 is the ML-DSA context string a record.v2 signature is
	// made with (docs/decisions.md D21). A record.v1 signature has none.
	RecordContextV2 = "aleutian.proof.record.v2"
)

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

	// formatVersion is the entry's chain format: 4 gives the record.v2
	// envelope, which also covers leafHash; 3 gives record.v1.
	formatVersion int
	leafHash      string
}

// recordEnvelope returns the envelope for f, refusing any value the sink would
// never write: a record signature must never cover something Verify could not
// rebuild exactly.
func recordEnvelope(f recordFields) ([]byte, error) {
	v2 := f.formatVersion == chainformat.FormatV4
	if !v2 && f.formatVersion != chainformat.FormatV3 {
		return nil, fmt.Errorf("sink: record envelope: chain format %d has no record envelope", f.formatVersion)
	}
	if v2 && !lowerHex128.MatchString(f.leafHash) {
		return nil, errors.New("sink: record envelope: leaf hash is not 128 lowercase hex")
	}
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
	domain := recordDomain
	if v2 {
		domain = recordDomainV2
		values = append(values, f.leafHash)
	}
	env := make([]byte, 0, 800)
	env = append(env, domain...)
	for i, v := range values {
		env = append(env, byte(i+1))
		env = binary.BigEndian.AppendUint32(env, uint32(len(v)))
		env = append(env, v...)
	}
	return env, nil
}
