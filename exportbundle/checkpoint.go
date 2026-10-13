// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
)

// maxSafeInteger is 2^53-1, the largest number checkpoint text may hold (§3).
const maxSafeInteger = 1<<53 - 1

// signatureSize is an ML-DSA-65 signature, in bytes.
const signatureSize = 3309

// The value shapes of §4.3 and §4.4.
var (
	hex32Pattern   = regexp.MustCompile(`\A[0-9a-f]{32}\z`)
	hex64Pattern   = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
	hex128Pattern  = regexp.MustCompile(`\A[0-9a-f]{128}\z`)
	entryIDPattern = regexp.MustCompile(`\Asink-[0-9a-f]{32}\z`)
)

// checkpoint is one checkpoint's text, read and found in shape (§4.4).
type checkpoint struct {
	version          uint64
	anchorID         string
	chainHash        string
	createdAtMs      uint64
	entryCount       uint64
	previousAnchorID string
	rangeStart       string
	rangeEnd         string
	signature        []byte
	signingKeyID     string
	subject          string
	verifiedThrough  uint64

	// signatureText is the member as written, until it is decoded.
	signatureText string
}

// parseCheckpoint is step a of §7.6: the text satisfies §3, and has exactly
// the members of §4.4, each of its type and shape. A nil text is one that was
// over the size limit. ok false is `checkpoint-malformed`.
func parseCheckpoint(text []byte) (checkpoint, bool) {
	var ck checkpoint
	if text == nil {
		return ck, false
	}
	r := newReader(text, Limits{Depth: DefaultLimits().Depth, Values: math.MaxInt})
	r.ck = &ck
	if c, ok := r.peek(); !ok || c != '{' {
		return ck, false
	}
	seen, ok := r.object(kindCheckpoint)
	if !ok || seen != ckAll || r.duplicate || r.structure {
		return ck, false
	}
	if _, more := r.peek(); more {
		return ck, false
	}
	sig, ok := decodeCanonicalBase64(ck.signatureText)
	ck.signature, ck.signatureText = sig, ""
	if !ok || len(sig) != signatureSize {
		return ck, false
	}
	inShape := ck.version == 6 &&
		label(ck.anchorID) &&
		hex128Pattern.MatchString(ck.chainHash) &&
		ck.entryCount >= 1 &&
		label(ck.previousAnchorID) &&
		entryIDPattern.MatchString(ck.rangeStart) &&
		entryIDPattern.MatchString(ck.rangeEnd) &&
		hex32Pattern.MatchString(ck.signingKeyID) &&
		label(ck.subject) &&
		ck.verifiedThrough >= 1
	return ck, inShape
}

// checkpointMember reads one member of a checkpoint, or of its range. A value
// of the wrong type ends the read: any violation is `checkpoint-malformed`,
// and none outranks another.
func (r *reader) checkpointMember(kind objectKind, idx int) bool {
	ck := r.ck
	if ck == nil {
		return false
	}
	if kind == kindRange {
		s, ok := r.checkpointString()
		if idx == 0 {
			ck.rangeStart = s
		} else {
			ck.rangeEnd = s
		}
		return ok
	}
	var ok bool
	switch idx {
	case ckAnchorID:
		ck.anchorID, ok = r.checkpointString()
	case ckChainHash:
		ck.chainHash, ok = r.checkpointString()
	case ckCreatedAtMs:
		ck.createdAtMs, ok = r.checkpointNumber()
	case ckEntryCount:
		ck.entryCount, ok = r.checkpointNumber()
	case ckPreviousAnchorID:
		ck.previousAnchorID, ok = r.checkpointString()
	case ckRange:
		c, more := r.peek()
		if !more || c != '{' {
			return false
		}
		seen, closed := r.object(kindRange)
		ok = closed && seen == 3
	case ckSignature:
		ck.signatureText, ok = r.checkpointString()
	case ckSigningKeyID:
		ck.signingKeyID, ok = r.checkpointString()
	case ckSubject:
		ck.subject, ok = r.checkpointString()
	case ckVerifiedThrough:
		ck.verifiedThrough, ok = r.checkpointNumber()
	case ckVersion:
		ck.version, ok = r.checkpointNumber()
	}
	return ok
}

// checkpointString reads a member of checkpoint text that must be a string.
func (r *reader) checkpointString() (string, bool) {
	s, isString, ok := r.stringValue(len(r.b), true)
	return s, ok && isString
}

// checkpointNumber reads a member of checkpoint text that must be a number:
// `0|[1-9][0-9]*`, at most 2^53-1 (§3). A sign, a fraction, an exponent or a
// leading zero fails here or at the byte after the digits.
func (r *reader) checkpointNumber() (uint64, bool) {
	c, ok := r.peek()
	if !ok || !isDigit(c) {
		return 0, false
	}
	r.countValue()
	end := digits(r.b, r.i)
	text := r.b[r.i:end]
	// 2^53-1 has 16 digits.
	if len(text) > 16 || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	if end < len(r.b) && (r.b[end] == '.' || r.b[end] == 'e' || r.b[end] == 'E') {
		return 0, false
	}
	var v uint64
	for _, d := range text {
		v = v*10 + uint64(d-'0')
	}
	if v > maxSafeInteger {
		return 0, false
	}
	r.i = end
	return v, true
}

// label reports whether s can be an anchor id or a subject: not empty, and
// without the `|` that delimits the anchor chain hash's preimage.
func label(s string) bool {
	return s != "" && !strings.Contains(s, "|")
}

// decodeCanonicalBase64 decodes canonical base64 (§3): the standard alphabet
// with padding, no whitespace, and the unused bits of the last character zero.
func decodeCanonicalBase64(s string) ([]byte, bool) {
	if len(s)%4 != 0 {
		return nil, false
	}
	out, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, false
	}
	return out, true
}
