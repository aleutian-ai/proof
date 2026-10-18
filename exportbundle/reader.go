// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math"
	"slices"
	"unicode/utf8"
)

// FormatV1 and FormatV2 are the bundle's `format` member (bundle-format §4.1,
// §16). A bundle is one or the other throughout: v1 carries chain format v3
// and v6 checkpoints, v2 chain format v4 and v7 checkpoints.
const (
	FormatV1 = "aleutian.proof.bundle.v1"
	FormatV2 = "aleutian.proof.bundle.v2"
)

// valuesV1 and valuesV2 are §5's JSON value limit for each format (§16: a v2
// entry has two more values).
const (
	valuesV1 = 15_000_000
	valuesV2 = 17_000_000
)

// The reasons a bundle is unreadable (bundle-format §9.1).
const (
	ReasonTooLarge     = "too-large"
	ReasonJSON         = "json"
	ReasonDuplicateKey = "duplicate-key"
	ReasonFormat       = "format"
	ReasonStructure    = "structure"
)

// oversize stands in for a string member longer than any value its shape
// allows. It holds a NUL, which no §4.3 shape admits, so it is judged out of
// shape like the value it replaces, without that value being held in memory.
const oversize = "\x00"

// The longest value each shaped member can have and still be in shape.
const (
	maxEntryID     = 37          // "sink-" and 32 hex
	maxEntryType   = math.MaxInt // held whole: a v2 leaf hashes it as stored (§16); §5's value limit bounds it
	maxGlobalSeq   = 19          // 2^63-1
	maxHash        = 128         // SHA-512 as hex
	maxTimestamp   = 27          // YYYY-MM-DDTHH:MM:SS.ffffffZ
	maxKeyID       = 32          // 16 bytes as hex
	maxSignature   = 4412        // base64 of 3309 bytes
	maxContent     = 87384       // base64 of 65,536 bytes
	maxNonce       = 64          // 32 bytes as hex
	maxChainID     = 64          // 31-byte class, a dot, 32 hex
	maxMemberName  = 32          // longer than any defined member name
	firstNameCheck = 4096        // unknown names in one object before the first early duplicate check
	arenaBit       = 1 << 31
	maxInputBytes  = math.MaxInt32
)

// objectKind is a position in §4 where an object is defined, and so which
// member names it may have.
type objectKind uint8

const (
	// kindOther is an object where §4 defines none: every name is unknown.
	kindOther objectKind = iota
	kindBundle
	kindChain
	kindEntry
	kindRecordSignature
	kindDisclosed
	kindCheckpoint
	kindRange
	kindCheckpointV7 // bundle v2's checkpoint text (§16)
	kindRangeV7
)

// elemKind is what an array's elements are, by the array's position.
type elemKind uint8

const (
	elemAny elemKind = iota
	elemChain
	elemEntry
	elemCheckpoint
)

// Member indexes of an entry (§4.3) and of a checkpoint (§4.4), in the order
// of memberNames.
const (
	entryRecordSignature = 7
	entryDisclosed       = 8
	entryRequired        = 1<<entryRecordSignature - 1

	ckAnchorID = iota - 3
	ckChainHash
	ckCreatedAtMs
	ckEntryCount
	ckPreviousAnchorID
	ckRange
	ckSignature
	ckSigningKeyID
	ckSubject
	ckVerifiedThrough
	ckVersion
	ckAll = 1<<(ckVersion+1) - 1
)

// The v2 members of an entry (§16), in their own block: the block above counts
// the checkpoint members from iota.
const (
	entrySalt      = 9
	entryLeafHash  = 10
	entryV2Members = 1<<entrySalt | 1<<entryLeafHash
)

// memberNames lists each object's defined members. A member's index is its
// bit in the mask object returns.
var memberNames = [...][]string{
	kindOther:           nil,
	kindBundle:          {"format", "chains"},
	kindChain:           {"chain_id", "entries", "checkpoints"},
	kindEntry:           {"entry_id", "entry_type", "global_seq", "previous_hash", "timestamp", "content_hash", "chain_hash", "record_signature", "disclosed", "salt", "leaf_hash"},
	kindRecordSignature: {"key_id", "signature"},
	kindDisclosed:       {"content", "nonce"},
	kindCheckpoint: {"anchor_id", "chain_hash", "created_at_ms", "entry_count", "previous_anchor_id", "range",
		"signature", "signing_key_id", "subject", "verified_through", "version"},
	kindRange: {"start_entry_id", "end_entry_id"},
	kindCheckpointV7: {"anchor_id", "chain_hash", "created_at_ms", "entry_count", "previous_anchor_id", "range",
		"signature", "signing_key_id", "subject", "previous_anchor_hash", "version"},
	kindRangeV7: {"start_seq", "end_seq"},
}

// entryCaps is the longest in-shape value of each string member of an entry,
// by member index (7 and 8 are objects).
var entryCaps = [...]int{maxEntryID, maxEntryType, maxGlobalSeq, maxHash, maxTimestamp, maxHash, maxHash, 0, 0,
	maxNonce, maxHash}

// Limits are the §5 limits. The zero value of a field means its §5 value.
type Limits struct {
	// BundleBytes is the largest bundle, in bytes.
	BundleBytes int
	// Chains is the most chains in a bundle.
	Chains int
	// Entries is the most entries, all chains together.
	Entries int
	// Checkpoints is the most checkpoints, all chains together.
	Checkpoints int
	// CheckpointBytes is the longest checkpoint text, in UTF-8 bytes.
	CheckpointBytes int
	// Depth is the deepest nesting; the top-level value is depth 1.
	Depth int
	// Values is the most JSON values in the bundle, at every depth. Zero
	// means §5's value for the bundle's format: 15,000,000 for v1,
	// 17,000,000 for v2 (§16).
	Values int

	valuesExplicit bool // Values was set by the caller, for every format
}

// rawPair is the two string members of a `record_signature` (key_id,
// signature) or of a `disclosed` (content, nonce).
type rawPair struct {
	a, b string
}

// rawEntry is one entry as read: every string as stored, or oversize.
type rawEntry struct {
	entryID      string
	entryType    string
	globalSeq    string
	previousHash string
	timestamp    string
	contentHash  string
	chainHash    string
	salt         string // v2
	leafHash     string // v2
	sig          *rawPair
	disclosed    *rawPair
}

// rawChain is one chain as read. A checkpoint is its text; nil means the text
// was over the §5 limit and was not kept.
type rawChain struct {
	id          string
	entries     []rawEntry
	checkpoints [][]byte
}

// nameRef locates an unknown member name in four bytes. Without arenaBit it
// is the offset in the input of a name that has no escape, which therefore
// ends at the next quote. With arenaBit it is the offset in the reader's arena
// of a name that had escapes: its unescaped length as a uvarint, then its
// unescaped bytes.
type nameRef uint32

// reader is the strict reader of bundle-format §3 and §4: one pass over the
// bytes, knowing at each value which member of §4 it is. It serves the bundle
// and, with ck set, one checkpoint's text.
//
// A grammar error ends the read at once (every method returns ok false): only
// the size limit outranks `json` in §9.1, and that is known before reading.
// Every other finding is a flag, and the read goes on to the end, because a
// later grammar error would outrank it. After the first such finding nothing
// more is built.
type reader struct {
	b   []byte
	i   int
	lim Limits

	depth  int
	values int

	// The findings of §9.1, positions 3 to 7.
	overValues bool
	duplicate  bool
	structure  bool
	overCount  bool
	topObject  bool
	formatOK   bool
	version    int // 1 or 2, from `format`, once it is read

	// Entries with any v2 member, and entries without both: the format may
	// come after the entries, so which is a structure violation is decided
	// when the read ends.
	withV2Members, lackingV2Members int

	// What is built while build holds.
	build        bool
	chains       []rawChain
	chain        rawChain
	entry        rawEntry
	nChains      int
	nEntries     int
	nCheckpoints int

	// ck is the checkpoint being read, when the input is a checkpoint's text.
	ck *checkpoint

	// Unknown member names of each open object, by depth, kept until a
	// duplicate is known or can no longer change the answer.
	track     bool
	unknown   [][]nameRef
	nextCheck []int
	arena     []byte
	scratch   []byte
}

// DefaultLimits returns the limits of bundle-format §5.
//
// # Description
//
// These are the limits every implementation must apply: a bundle within them
// is accepted, and one beyond them is unreadable (`too-large`).
//
// # Inputs
//
// None.
//
// # Outputs
//
//   - Limits: 256 MiB, 100,000 chains, 1,000,000 entries, 100,000 checkpoints,
//     1 MiB per checkpoint text, depth 8, and 17,000,000 JSON values (the
//     v2 limit; a v1 bundle is held to 15,000,000).
//
// # Example
//
//	lim := exportbundle.DefaultLimits()
//	data, err := exportbundle.ReadBundleFile(path, lim.BundleBytes)
//
// # Limitations
//
//   - A verifier that lowers a limit is no longer conformant; lowering is for
//     tests.
//
// # Assumptions
//
//   - The process can hold a bundle of BundleBytes in memory.
func DefaultLimits() Limits {
	return Limits{
		BundleBytes:     256 << 20,
		Chains:          100_000,
		Entries:         1_000_000,
		Checkpoints:     100_000,
		CheckpointBytes: 1 << 20,
		Depth:           8,
		Values:          valuesV2,
	}
}

// withDefaults fills every unset limit with its §5 value.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	l.valuesExplicit = l.Values > 0 && l.Values != valuesV2
	for _, f := range []struct{ have, def *int }{
		{&l.BundleBytes, &d.BundleBytes}, {&l.Chains, &d.Chains}, {&l.Entries, &d.Entries},
		{&l.Checkpoints, &d.Checkpoints}, {&l.CheckpointBytes, &d.CheckpointBytes},
		{&l.Depth, &d.Depth}, {&l.Values, &d.Values},
	} {
		if *f.have <= 0 {
			*f.have = *f.def
		}
	}
	// A nameRef holds an offset in 31 bits.
	l.BundleBytes = min(l.BundleBytes, maxInputBytes)
	return l
}

// readBundle reads a bundle. It returns the chains and an empty reason, or the
// one reason of §9.1 the bundle is unreadable for: the lowest-numbered of all
// that apply.
func readBundle(data []byte, lim Limits) ([]rawChain, int, string) {
	if len(data) > lim.BundleBytes {
		return nil, 0, ReasonTooLarge
	}
	r := newReader(data, lim)
	r.build = true
	if !r.document() {
		return nil, 0, ReasonJSON
	}
	// The findings that depend on the format, known only now: v1's lower
	// value limit, and members of the other format.
	if r.version != 2 && !lim.valuesExplicit && r.values > valuesV1 {
		r.overValues = true
	}
	if (r.version == 1 && r.withV2Members > 0) || (r.version == 2 && r.lackingV2Members > 0) {
		r.structure = true
	}
	switch {
	case r.overValues:
		return nil, 0, ReasonTooLarge
	case r.duplicate:
		return nil, 0, ReasonDuplicateKey
	case r.topObject && !r.formatOK:
		return nil, 0, ReasonFormat
	case r.structure:
		return nil, 0, ReasonStructure
	case r.overCount:
		return nil, 0, ReasonTooLarge
	}
	return r.chains, r.version, ""
}

// newReader returns a reader over b that tracks unknown member names.
func newReader(b []byte, lim Limits) *reader {
	return &reader{
		b:         b,
		lim:       lim,
		track:     true,
		unknown:   make([][]nameRef, lim.Depth+1),
		nextCheck: make([]int, lim.Depth+1),
	}
}

// document reads the bundle's one top-level value and requires nothing but
// whitespace after it.
func (r *reader) document() bool {
	c, ok := r.peek()
	if !ok {
		return false
	}
	if c == '{' {
		r.topObject = true
		seen, ok := r.object(kindBundle)
		if !ok {
			return false
		}
		if seen&2 == 0 {
			r.violate()
		}
	} else {
		r.violate()
		if !r.skipValue() {
			return false
		}
	}
	_, more := r.peek()
	return !more
}

// peek skips whitespace and returns the next byte without consuming it. ok is
// false at the end of the input.
func (r *reader) peek() (byte, bool) {
	for r.i < len(r.b) {
		switch c := r.b[r.i]; c {
		case ' ', '\t', '\n', '\r':
			r.i++
		default:
			return c, true
		}
	}
	return 0, false
}

// violate records a §4 violation and ends building: the bundle is unreadable
// whatever follows.
func (r *reader) violate() {
	r.structure = true
	r.stopBuilding()
}

// stopBuilding drops what was built. The read goes on, to find every reason.
func (r *reader) stopBuilding() {
	r.build = false
	r.chains = nil
	r.chain = rawChain{}
	r.entry = rawEntry{}
}

// stopTracking drops the unknown names: a duplicate can no longer change the
// answer.
func (r *reader) stopTracking() {
	r.track = false
	r.unknown = nil
	r.nextCheck = nil
	r.arena = nil
}

// foundDuplicate records a duplicate member name.
func (r *reader) foundDuplicate() {
	r.duplicate = true
	r.stopBuilding()
	r.stopTracking()
}

// countValue counts one JSON value against the §5 value limit. Past it, only a
// grammar error can still change the answer (§9.1), so nothing is kept.
func (r *reader) countValue() {
	r.values++
	if r.values > r.lim.Values && !r.overValues {
		r.overValues = true
		r.stopBuilding()
		r.stopTracking()
	}
}

// open enters an array or object. Depth past the limit is a grammar error.
func (r *reader) open() bool {
	r.depth++
	if r.depth > r.lim.Depth {
		return false
	}
	r.countValue()
	return true
}

// object reads the object at r.i, whose defined members are memberNames[kind].
// It returns a mask of the defined members present. An unknown name is a §4
// violation; a repeated name, defined or not, is a duplicate.
func (r *reader) object(kind objectKind) (seen uint16, ok bool) {
	if !r.open() {
		return 0, false
	}
	d := r.depth
	mark := len(r.arena)
	if r.track {
		r.unknown[d] = r.unknown[d][:0]
		r.nextCheck[d] = firstNameCheck
	}
	r.i++
	c, ok := r.peek()
	if !ok {
		return 0, false
	}
	if c == '}' {
		r.i++
		r.depth--
		return 0, true
	}
	for {
		if c != '"' {
			return 0, false
		}
		idx, ok := r.name(kind, d)
		if !ok {
			return 0, false
		}
		if c, ok = r.peek(); !ok || c != ':' {
			return 0, false
		}
		r.i++
		switch {
		case idx < 0:
			r.violate()
			ok = r.skipValue()
		case seen&(1<<idx) != 0:
			// The repeat is read as any value, so nothing is built twice.
			r.foundDuplicate()
			ok = r.skipValue()
		default:
			seen |= 1 << idx
			ok = r.member(kind, idx)
		}
		if !ok {
			return 0, false
		}
		if c, ok = r.peek(); !ok {
			return 0, false
		}
		if c == '}' {
			r.i++
			break
		}
		if c != ',' {
			return 0, false
		}
		r.i++
		if c, ok = r.peek(); !ok {
			return 0, false
		}
	}
	if r.track {
		if len(r.unknown[d]) > 1 {
			r.checkNames(d)
		}
		if r.track {
			r.arena = r.arena[:mark]
		}
	}
	r.depth--
	return seen, true
}

// name reads the member name at r.i and returns its index in the object's
// defined members, or -1. Names are compared after unescaping (§3). An unknown
// name is remembered, so that a repeat of it is found.
func (r *reader) name(kind objectKind, d int) (int, bool) {
	start := r.i + 1
	raw, n, escaped, ok := r.scanString()
	if !ok {
		return -1, false
	}
	if known := memberNames[kind]; len(known) > 0 && n <= maxMemberName {
		val := raw
		if escaped {
			r.scratch = appendUnescaped(r.scratch[:0], raw)
			val = r.scratch
		}
		for i, k := range known {
			if string(val) == k {
				return i, true
			}
		}
	}
	if !r.track {
		return -1, true
	}
	ref := nameRef(start)
	if escaped {
		ref = nameRef(len(r.arena)) | arenaBit
		r.arena = binary.AppendUvarint(r.arena, uint64(n))
		r.arena = appendUnescaped(r.arena, raw)
	}
	r.unknown[d] = append(r.unknown[d], ref)
	// Checked early as the list grows, so it only grows while every name in
	// it is distinct: a run of one repeated name costs no memory.
	if len(r.unknown[d]) >= r.nextCheck[d] {
		r.nextCheck[d] = 2 * len(r.unknown[d])
		r.checkNames(d)
	}
	return -1, true
}

// checkNames looks for two equal names among one object's unknown names.
func (r *reader) checkNames(d int) {
	names := r.unknown[d]
	slices.SortFunc(names, func(x, y nameRef) int { return bytes.Compare(r.nameBytes(x), r.nameBytes(y)) })
	for i := 1; i < len(names); i++ {
		if bytes.Equal(r.nameBytes(names[i-1]), r.nameBytes(names[i])) {
			r.foundDuplicate()
			return
		}
	}
}

// nameBytes returns the unescaped name a nameRef locates.
func (r *reader) nameBytes(ref nameRef) []byte {
	if ref&arenaBit != 0 {
		at := r.arena[ref&^arenaBit:]
		n, width := binary.Uvarint(at)
		return at[width : width+int(n)]
	}
	rest := r.b[ref:]
	return rest[:bytes.IndexByte(rest, '"')]
}

// member reads the value of a defined member.
func (r *reader) member(kind objectKind, idx int) bool {
	switch kind {
	case kindBundle:
		if idx == 0 {
			s, isString, ok := r.stringValue(len(FormatV2), true)
			switch {
			case isString && s == FormatV1:
				r.version = 1
			case isString && s == FormatV2:
				r.version = 2
			}
			r.formatOK = r.version != 0
			if !r.formatOK {
				r.stopBuilding()
			}
			return ok
		}
		_, _, ok := r.arrayValue(elemChain)
		return ok
	case kindChain:
		switch idx {
		case 0:
			return r.chainID()
		case 1:
			n, isArray, ok := r.arrayValue(elemEntry)
			if ok && isArray && n == 0 {
				r.violate()
			}
			return ok
		}
		_, _, ok := r.arrayValue(elemCheckpoint)
		return ok
	case kindEntry:
		switch idx {
		case entryRecordSignature:
			return r.pairValue(kindRecordSignature)
		case entryDisclosed:
			return r.pairValue(kindDisclosed)
		}
		s, _, ok := r.stringValue(entryCaps[idx], r.build)
		if r.build {
			*r.entry.field(idx) = s
		}
		return ok
	case kindRecordSignature:
		limit := [...]int{maxKeyID, maxSignature}[idx]
		s, _, ok := r.stringValue(limit, r.build)
		if r.build && r.entry.sig != nil {
			r.entry.sig.set(idx, s)
		}
		return ok
	case kindDisclosed:
		limit := [...]int{maxContent, maxNonce}[idx]
		s, _, ok := r.stringValue(limit, r.build)
		if r.build && r.entry.disclosed != nil {
			r.entry.disclosed.set(idx, s)
		}
		return ok
	case kindCheckpoint, kindRange, kindCheckpointV7, kindRangeV7:
		return r.checkpointMember(kind, idx)
	}
	return r.skipValue()
}

// pairValue reads a `record_signature` or `disclosed`: an object of exactly
// two string members (§4.3).
func (r *reader) pairValue(kind objectKind) bool {
	c, ok := r.peek()
	if !ok {
		return false
	}
	if c != '{' {
		r.violate()
		return r.skipValue()
	}
	if r.build {
		if kind == kindRecordSignature {
			r.entry.sig = &rawPair{}
		} else {
			r.entry.disclosed = &rawPair{}
		}
	}
	seen, ok := r.object(kind)
	if ok && seen != 3 {
		r.violate()
	}
	return ok
}

// chainID reads a `chain_id`. One longer than any valid id is kept as its
// SHA-512 digest behind a NUL: still invalid, still equal exactly when the ids
// are equal (§8 compares invalid ids too), and never held whole.
func (r *reader) chainID() bool {
	c, ok := r.peek()
	if !ok {
		return false
	}
	if c != '"' {
		r.violate()
		return r.skipValue()
	}
	r.countValue()
	raw, n, escaped, ok := r.scanString()
	if !ok || !r.build {
		return ok
	}
	switch {
	case n > maxChainID:
		r.chain.id = oversize + digestUnescaped(raw)
	case escaped:
		r.scratch = appendUnescaped(r.scratch[:0], raw)
		r.chain.id = string(r.scratch)
	default:
		r.chain.id = string(raw)
	}
	return true
}

// stringValue reads a member that must be a string. isString is false for any
// other type, which is a §4 violation and is read past. With keep, s is the
// unescaped value, or oversize when it is longer than limit bytes.
func (r *reader) stringValue(limit int, keep bool) (s string, isString, ok bool) {
	c, ok := r.peek()
	if !ok {
		return "", false, false
	}
	if c != '"' {
		r.violate()
		return "", false, r.skipValue()
	}
	r.countValue()
	raw, n, escaped, ok := r.scanString()
	if !ok || !keep {
		return "", true, ok
	}
	switch {
	case n > limit:
		return oversize, true, true
	case escaped:
		r.scratch = appendUnescaped(r.scratch[:0], raw)
		return string(r.scratch), true, true
	}
	return string(raw), true, true
}

// arrayValue reads a member that must be an array. isArray is false for any
// other type, which is a §4 violation and is read past.
func (r *reader) arrayValue(elem elemKind) (n int, isArray, ok bool) {
	c, ok := r.peek()
	if !ok {
		return 0, false, false
	}
	if c != '[' {
		r.violate()
		return 0, false, r.skipValue()
	}
	n, ok = r.array(elem)
	return n, true, ok
}

// array reads the array at r.i and returns its length.
func (r *reader) array(elem elemKind) (n int, ok bool) {
	if !r.open() {
		return 0, false
	}
	r.i++
	c, ok := r.peek()
	if !ok {
		return 0, false
	}
	if c == ']' {
		r.i++
		r.depth--
		return 0, true
	}
	for {
		if !r.element(elem) {
			return 0, false
		}
		n++
		if c, ok = r.peek(); !ok {
			return 0, false
		}
		if c == ']' {
			r.i++
			break
		}
		if c != ',' {
			return 0, false
		}
		r.i++
	}
	r.depth--
	return n, true
}

// element reads one array element, and counts it against its §5 limit.
func (r *reader) element(elem elemKind) bool {
	c, ok := r.peek()
	if !ok {
		return false
	}
	switch elem {
	case elemChain:
		r.nChains++
		r.overLimit(r.nChains, r.lim.Chains)
		if c != '{' {
			break
		}
		r.chain = rawChain{}
		seen, ok := r.object(kindChain)
		if !ok {
			return false
		}
		if seen != 7 {
			r.violate()
		}
		if r.build {
			r.chains = append(r.chains, r.chain)
			r.chain = rawChain{}
		}
		return true
	case elemEntry:
		r.nEntries++
		r.overLimit(r.nEntries, r.lim.Entries)
		if c != '{' {
			break
		}
		r.entry = rawEntry{}
		seen, ok := r.object(kindEntry)
		if !ok {
			return false
		}
		if seen&entryRequired != entryRequired {
			r.violate()
		}
		if seen&entryV2Members != 0 {
			r.withV2Members++
		}
		if seen&entryV2Members != entryV2Members {
			r.lackingV2Members++
		}
		if r.build {
			r.chain.entries = append(r.chain.entries, r.entry)
			r.entry = rawEntry{}
		}
		return true
	case elemCheckpoint:
		r.nCheckpoints++
		r.overLimit(r.nCheckpoints, r.lim.Checkpoints)
		if c != '"' {
			break
		}
		r.countValue()
		raw, n, _, ok := r.scanString()
		if !ok {
			return false
		}
		if r.build {
			var text []byte
			if n <= r.lim.CheckpointBytes {
				text = appendUnescaped(make([]byte, 0, n), raw)
			}
			r.chain.checkpoints = append(r.chain.checkpoints, text)
		}
		return true
	default:
		return r.skipValue()
	}
	// A typed element of the wrong JSON type.
	r.violate()
	return r.skipValue()
}

// overLimit records a count past its §5 limit. The elements beyond it are
// still read, for the reasons that outrank it, and are not held.
func (r *reader) overLimit(n, limit int) {
	if n > limit && !r.overCount {
		r.overCount = true
		r.stopBuilding()
	}
}

// skipValue reads any JSON value where §4 defines none, or defines another
// type. It keeps nothing but the unknown names of objects, for duplicates.
func (r *reader) skipValue() bool {
	c, ok := r.peek()
	if !ok {
		return false
	}
	switch {
	case c == '{':
		_, ok = r.object(kindOther)
		return ok
	case c == '[':
		_, ok = r.array(elemAny)
		return ok
	case c == '"':
		r.countValue()
		_, _, _, ok = r.scanString()
		return ok
	case c == 't':
		return r.literal("true")
	case c == 'f':
		return r.literal("false")
	case c == 'n':
		return r.literal("null")
	case c == '-' || isDigit(c):
		r.countValue()
		return r.number()
	}
	return false
}

// literal reads true, false or null.
func (r *reader) literal(word string) bool {
	if !bytes.HasPrefix(r.b[r.i:], []byte(word)) {
		return false
	}
	r.i += len(word)
	r.countValue()
	return true
}

// number reads a number of RFC 8259's grammar. What follows it is checked by
// the caller, so `01` fails there: `0`, then a stray `1`.
func (r *reader) number() bool {
	b, i := r.b, r.i
	if i < len(b) && b[i] == '-' {
		i++
	}
	switch {
	case i >= len(b) || !isDigit(b[i]):
		return false
	case b[i] == '0':
		i++
	default:
		i = digits(b, i)
	}
	if i < len(b) && b[i] == '.' {
		j := digits(b, i+1)
		if j == i+1 {
			return false
		}
		i = j
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		j := digits(b, i)
		if j == i {
			return false
		}
		i = j
	}
	r.i = i
	return true
}

// scanString validates the string at r.i (its opening quote) against §3 and
// moves past it. It returns the bytes between the quotes, the length of their
// unescaped form in UTF-8 bytes, and whether they hold an escape.
func (r *reader) scanString() (raw []byte, n int, escaped, ok bool) {
	b := r.b
	start := r.i + 1
	for i := start; i < len(b); {
		c := b[i]
		switch {
		case c == '"':
			r.i = i + 1
			return b[start:i], n, escaped, true
		case c == '\\':
			escaped = true
			ch, size, ok := escapeAt(b, i)
			if !ok {
				return nil, 0, false, false
			}
			i += size
			n += utf8.RuneLen(ch)
		case c < 0x20:
			return nil, 0, false, false
		case c < utf8.RuneSelf:
			i++
			n++
		default:
			// DecodeRune refuses overlong forms, surrogates and anything
			// past U+10FFFF, each as a one-byte error.
			_, size := utf8.DecodeRune(b[i:])
			if size == 1 {
				return nil, 0, false, false
			}
			i += size
			n += size
		}
	}
	return nil, 0, false, false
}

// field returns the string member of an entry at a member index below
// entryRecordSignature.
func (e *rawEntry) field(idx int) *string {
	switch idx {
	case 0:
		return &e.entryID
	case 1:
		return &e.entryType
	case 2:
		return &e.globalSeq
	case 3:
		return &e.previousHash
	case 4:
		return &e.timestamp
	case 5:
		return &e.contentHash
	case entrySalt:
		return &e.salt
	case entryLeafHash:
		return &e.leafHash
	}
	return &e.chainHash
}

// set stores a pair's member by its index.
func (p *rawPair) set(idx int, s string) {
	if idx == 0 {
		p.a = s
		return
	}
	p.b = s
}

// escapeAt decodes the escape at b[i], a backslash. It returns the character,
// and how many input bytes spell it. A `\u` surrogate must be the high half of
// a pair whose low half follows at once; a lone one is an error (§3).
func escapeAt(b []byte, i int) (ch rune, size int, ok bool) {
	if i+1 >= len(b) {
		return 0, 0, false
	}
	switch b[i+1] {
	case '"', '\\', '/':
		return rune(b[i+1]), 2, true
	case 'b':
		return '\b', 2, true
	case 'f':
		return '\f', 2, true
	case 'n':
		return '\n', 2, true
	case 'r':
		return '\r', 2, true
	case 't':
		return '\t', 2, true
	case 'u':
		hi, ok := hex4(b, i+2)
		if !ok || (hi >= 0xDC00 && hi <= 0xDFFF) {
			return 0, 0, false
		}
		if hi < 0xD800 || hi > 0xDBFF {
			return hi, 6, true
		}
		if i+7 >= len(b) || b[i+6] != '\\' || b[i+7] != 'u' {
			return 0, 0, false
		}
		lo, ok := hex4(b, i+8)
		if !ok || lo < 0xDC00 || lo > 0xDFFF {
			return 0, 0, false
		}
		return 0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00), 12, true
	}
	return 0, 0, false
}

// hex4 reads four hex digits, of either case, at b[i].
func hex4(b []byte, i int) (rune, bool) {
	if i+4 > len(b) {
		return 0, false
	}
	var v rune
	for _, c := range b[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// appendUnescaped appends the unescaped form of raw, which scanString has
// validated.
func appendUnescaped(dst, raw []byte) []byte {
	for len(raw) > 0 {
		j := bytes.IndexByte(raw, '\\')
		if j < 0 {
			return append(dst, raw...)
		}
		dst = append(dst, raw[:j]...)
		ch, size, ok := escapeAt(raw, j)
		if !ok {
			return dst
		}
		dst = utf8.AppendRune(dst, ch)
		raw = raw[j+size:]
	}
	return dst
}

// digestUnescaped returns the SHA-512 of raw's unescaped form, as hex, without
// building that form.
func digestUnescaped(raw []byte) string {
	h := sha512.New()
	var buf [utf8.UTFMax]byte
	for len(raw) > 0 {
		j := bytes.IndexByte(raw, '\\')
		if j < 0 {
			h.Write(raw)
			break
		}
		h.Write(raw[:j])
		ch, size, ok := escapeAt(raw, j)
		if !ok {
			break
		}
		h.Write(buf[:utf8.EncodeRune(buf[:], ch)])
		raw = raw[j+size:]
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digits returns the index after the run of digits starting at b[i].
func digits(b []byte, i int) int {
	for i < len(b) && isDigit(b[i]) {
		i++
	}
	return i
}

// isDigit reports whether c is an ASCII digit.
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
