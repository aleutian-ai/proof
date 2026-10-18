// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// SequenceRangeVersion is anchor v7: the range is named by sequence, the
// predecessor's hash is signed, and the signature carries a context string
// (docs/format-spec.md §9, docs/decisions.md D20 and D21).
const SequenceRangeVersion = 7

// ContextV7 is the ML-DSA context string a v7 anchor is signed with. v1 to v6
// are signed with the empty context.
const ContextV7 = "aleutian.proof.anchor.v7"

// ChainDomainV7 is the domain-separation prefix of a v7 anchor chain hash.
const ChainDomainV7 = "aleutian.anchor.v7:"

// SigningContext returns the ML-DSA context string an anchor of this version
// is signed and verified with: [ContextV7] for v7, empty for v1 to v6. It is
// chosen from the declared version, never from the signature.
func SigningContext(version int) string {
	if version == SequenceRangeVersion {
		return ContextV7
	}
	return ""
}

// ChainHashV7 computes a v7 anchor chain hash (format-spec §9.4):
//
//	SHA-512("aleutian.anchor.v7:" ‖ previousAnchorHash ‖ "|" ‖ len(subject) ‖
//	        subject ‖ "|" ‖ startSeq ‖ "|" ‖ endSeq ‖ "|" ‖ tipChainHash)
//
// len is a 4-byte big-endian byte count, so the subject may contain '|'. The
// other fields are fixed-shape or decimal; previousAnchorHash and tipChainHash
// are the caller's to have checked as 128 lowercase hex.
func ChainHashV7(previousAnchorHash, subject string, startSeq, endSeq int64, tipChainHash string) string {
	h := sha512.New()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(subject)))
	h.Write([]byte(ChainDomainV7))
	h.Write([]byte(previousAnchorHash))
	h.Write([]byte("|"))
	h.Write(n[:])
	h.Write([]byte(subject))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(startSeq, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(endSeq, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(tipChainHash))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalRangeV7 and canonicalV7 are v7's canonical form: members sorted,
// the sequence numbers and the count as decimal strings.
type canonicalRangeV7 struct {
	EndSeq   string `json:"end_seq"`
	StartSeq string `json:"start_seq"`
}

type canonicalV7 struct {
	AnchorID           string           `json:"anchor_id"`
	ChainHash          string           `json:"chain_hash"`
	CreatedAtMs        int64            `json:"created_at_ms"`
	EntryCount         string           `json:"entry_count"`
	PreviousAnchorHash string           `json:"previous_anchor_hash"`
	PreviousAnchorID   string           `json:"previous_anchor_id"`
	Range              canonicalRangeV7 `json:"range"`
	SigningKeyID       string           `json:"signing_key_id"`
	Subject            string           `json:"subject"`
	Version            int              `json:"version"`
}

// wireV7 is a v7 anchor as a file holds it: the canonical members, then the
// signature.
type wireV7 struct {
	canonicalV7
	Signature string `json:"signature"`
}

func toCanonicalV7(a Anchor) canonicalV7 {
	return canonicalV7{
		AnchorID:           a.AnchorID,
		ChainHash:          a.ChainHash,
		CreatedAtMs:        a.CreatedAtMs,
		EntryCount:         strconv.FormatInt(a.EntryCount, 10),
		PreviousAnchorHash: a.PreviousAnchorHash,
		PreviousAnchorID:   a.PreviousAnchorID,
		Range: canonicalRangeV7{
			EndSeq:   strconv.FormatInt(a.Range.EndSeq, 10),
			StartSeq: strconv.FormatInt(a.Range.StartSeq, 10),
		},
		SigningKeyID: a.SigningKeyID,
		Subject:      a.Subject,
		Version:      a.Version,
	}
}

var (
	// anchorMembersV7 are a v7 anchor's members. Every one is required.
	anchorMembersV7 = map[string]bool{
		"version": true, "anchor_id": true, "subject": true, "chain_hash": true, "range": true,
		"entry_count": true, "signature": true, "signing_key_id": true, "created_at_ms": true,
		"previous_anchor_id": true, "previous_anchor_hash": true,
	}
	rangeMembersV7 = map[string]bool{"start_seq": true, "end_seq": true}
)

// unmarshalV7 reads a v7 anchor strictly (format-spec §9.8): exactly its
// members, each once and each present, with the JSON type the canonical form
// gives it, and the sequence numbers and count in the one decimal spelling.
func (a *Anchor) unmarshalV7(data []byte) error {
	names, err := objectMembers(data, anchorMembersV7, "the anchor")
	if err != nil {
		return err
	}
	for name := range anchorMembersV7 {
		if !names[name] {
			return fmt.Errorf("anchor: a v7 anchor has no %q", name)
		}
	}
	if err := refuseNull(data, "the anchor"); err != nil {
		return err
	}
	var raw struct {
		Range json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("anchor: a member has the wrong JSON type")
	}
	rnames, err := objectMembers(raw.Range, rangeMembersV7, "the anchor's range")
	if err != nil {
		return err
	}
	if !rnames["start_seq"] || !rnames["end_seq"] {
		return errors.New("anchor: a v7 range names start_seq and end_seq")
	}
	if err := refuseNull(raw.Range, "the anchor's range"); err != nil {
		return err
	}
	var w wireV7
	if err := json.Unmarshal(data, &w); err != nil {
		return errors.New("anchor: a member has the wrong JSON type (v7 sequence numbers and " +
			"entry_count are strings; version and created_at_ms are integers)")
	}
	count, err := parseDecimal("entry_count", w.EntryCount)
	if err != nil {
		return err
	}
	start, err := parseDecimal("start_seq", w.Range.StartSeq)
	if err != nil {
		return err
	}
	end, err := parseDecimal("end_seq", w.Range.EndSeq)
	if err != nil {
		return err
	}
	*a = Anchor{
		Version: w.Version, AnchorID: w.AnchorID, Subject: w.Subject, ChainHash: w.ChainHash,
		Range: EntryRange{StartSeq: start, EndSeq: end}, EntryCount: count, Signature: w.Signature,
		SigningKeyID: w.SigningKeyID, CreatedAtMs: w.CreatedAtMs, PreviousAnchorID: w.PreviousAnchorID,
		PreviousAnchorHash: w.PreviousAnchorHash,
	}
	return nil
}

// refuseNull refuses an object with a member whose value is null: encoding/json
// reads null into a string as "", so a null would be a second spelling of an
// empty value (format-spec §9.8). Member names were checked by objectMembers,
// so the map's exact-name keys are the members.
func refuseNull(data []byte, what string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return fmt.Errorf("anchor: %s is not a JSON object", what)
	}
	for name, v := range members {
		if string(v) == "null" {
			return fmt.Errorf("anchor: %s has %q null", what, name)
		}
	}
	return nil
}

// parseDecimal reads format-spec §2.1's decimal grammar: no sign, no leading
// zero, 0 to 2⁶³−1. Any other spelling of a number is refused, so a value has
// one spelling, as the signed bytes do.
func parseDecimal(name, s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != s {
		return 0, fmt.Errorf("anchor: %s is not a decimal number from 0 to 2^63-1 in its one spelling", name)
	}
	return n, nil
}

// validateV7 checks a v7 anchor's invariants (format-spec §9.3, §9.8).
func validateV7(a Anchor) error {
	if a.Subject == "" {
		return errors.New("anchor: v7 must declare a non-empty subject")
	}
	if a.AnchorID == "" {
		return errors.New("anchor: v7 must have a non-empty anchor_id")
	}
	if a.PreviousAnchorID == "" {
		return errors.New("anchor: v7 must have a non-empty previous_anchor_id")
	}
	// The signed bytes and the chain hash must cover the same string: an
	// invalid byte would be escaped in one and hashed raw in the other.
	for _, f := range []struct{ name, v string }{
		{"subject", a.Subject}, {"anchor_id", a.AnchorID},
		{"previous_anchor_id", a.PreviousAnchorID}, {"signing_key_id", a.SigningKeyID},
	} {
		if !utf8.ValidString(f.v) {
			return fmt.Errorf("anchor: %s is not valid UTF-8", f.name)
		}
	}
	if a.VerifiedThrough != 0 {
		return errors.New("anchor: v7 has no verified_through")
	}
	if a.Range.StartEntryID != "" || a.Range.EndEntryID != "" {
		return errors.New("anchor: a v7 range is named by sequence, not by entry id")
	}
	if a.Range.StartSeq < 0 || a.Range.EndSeq < a.Range.StartSeq {
		return fmt.Errorf("anchor: v7 range %d..%d is not a range", a.Range.StartSeq, a.Range.EndSeq)
	}
	if a.Range.EndSeq-a.Range.StartSeq == math.MaxInt64 || a.EntryCount != a.Range.EndSeq-a.Range.StartSeq+1 {
		return fmt.Errorf("anchor: entry_count %d is not end_seq - start_seq + 1", a.EntryCount)
	}
	if !isSHA512Hex(a.PreviousAnchorHash) {
		return errors.New("anchor: previous_anchor_hash is not 128 lowercase hex")
	}
	if !isSHA512Hex(a.ChainHash) {
		return errors.New("anchor: chain_hash is not 128 lowercase hex")
	}
	if (a.PreviousAnchorID == SeedAnchorID) != (a.PreviousAnchorHash == SeedAnchorHash) {
		return errors.New("anchor: the seed id goes with the seed hash and with no other")
	}
	if a.CreatedAtMs < 0 {
		return errors.New("anchor: created_at_ms is negative")
	}
	return nil
}

func isSHA512Hex(s string) bool {
	if len(s) != 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
