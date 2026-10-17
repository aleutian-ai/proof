// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package verify checks a chain offline.
//
// # Description
//
// Given exported entries, this re-derives every chain hash and reports whether
// the linkage holds. It reads nothing but what it is given: no network, no
// credentials, no clock.
//
// # What a result means
//
// [Result.Verdict] deliberately distinguishes two claims that "verified" would
// blur:
//
//	VerdictIntact    nothing was edited under me            (consistency)
//	VerdictAnchored  …and this is the same chain            (existence)
//
// Only the first is provable from entries alone. Callers reporting results to a
// human MUST keep them apart — see docs/verification-model.md.
//
// # Three chain formats, and why the version is never guessed
//
// An entry names the preimage that produced its hash. v4 links through a
// salted leaf hash over the entry's id, type and content hash; v3 binds the
// chain-wide global_seq and the content hash; v2 binds a run id and a
// batch-local sequence number. They cannot be distinguished by looking at a
// digest, so this package dispatches on the DECLARED version and refuses what
// it does not recognise ([BreakUnknownFormat]) rather than trying another one.
// Guessing would turn an unreadable entry into a reported forgery.
//
// A chain may hold v2 and v3 entries and continue in v4, and never goes back:
// a v2 or v3 entry after a v4 entry is [BreakFormatFieldMisuse], because a v3
// tombstone there would unlink everything before it (docs/format-spec.md §2.5).
//
// An absent format_version decodes as zero and means v2 — every entry written
// before v3 existed has no such field. A v3 entry carrying v2's run_id or
// sequence_num is itself a break ([BreakFormatFieldMisuse]): those fields are
// not in its preimage, so their presence means the entry was assembled by
// something that did not understand the format it claimed.
//
// # Limitations
//
//   - Checks linkage. It cannot see truncation from the front, which needs an
//     anchor — see [BindAnchor].
//   - Reports THAT a chain was altered, never who altered it.
//   - One altered entry breaks every entry after it, so a break count is a blast
//     radius. [Result.FirstBreak] is the signal.
//   - v2 and v3 only: skips hash recomputation for tombstones and validates
//     their format only. A tombstone keeps the original entry's chain hash,
//     which is not reproducible from its remaining fields. THE CONSEQUENCE: a
//     tombstone's chain hash is taken as stored, so nothing links the entries
//     BEFORE a tombstone to the entries after it. Whoever can write the store
//     can replace every entry before a tombstone (or before an entry they turn
//     into one) and the walk still reports INTACT, under a signed anchor too.
//     [Result.TombstonesFound] and [Result.LastTombstone] say whether, and up
//     to where, a result is exposed to this. v2 and v3 are frozen, so this is
//     permanent for them; v4 has no tombstones and recomputes every entry.
//   - v2 and v3 only: entry_id and entry_type are in no hash. Either can be
//     changed without a break. v4 hashes both into the leaf hash.
//   - v4: an erased entry proves an entry existed at its position, not that
//     whoever erased it was allowed to. Anyone who can write the store can
//     produce the erased shape (docs/verification-model.md, "Who may erase").
//
// # Assumptions
//
//   - Entries arrive in ascending global_seq order, as every exporter in this
//     module produces them. Out-of-order input reports breaks on an intact chain.
//   - Timestamps are stored in the form they were hashed in, [TimestampLayout].
//     Any other spelling of the same instant is a break.
package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
)

// TimestampLayout is the one form an entry's timestamp is stored in: UTC, the
// literal Z, exactly six fractional digits (docs/format-spec.md §4). It is the
// form the chain hash covers, so requiring it of the stored string leaves a
// timestamp exactly one spelling.
const TimestampLayout = "2006-01-02T15:04:05.000000Z"

// chainHashPattern is the shape of every chain hash: SHA-512, lowercase hex.
var chainHashPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

// Verdict is the overall outcome of a verification.
type Verdict string

const (
	// VerdictIntact means the linkage holds: no entry was altered by anyone
	// unable to also rewrite everything after it. It does NOT mean this is the
	// same chain the caller saw previously — truncation is undetectable from
	// entries alone.
	VerdictIntact Verdict = "INTACT"

	// VerdictAnchored means the linkage holds AND an anchor bound it to a point
	// in time, so truncation is ruled out over the anchored range.
	//
	// [Chain] never returns this — it sees entries only. A caller that also
	// binds an anchor ([BindAnchor]) promotes the verdict itself; `proof verify
	// --anchor` does exactly that. Binding is the bar, not the signature: the
	// signature is a separate axis, reported by BindResult.SignatureVerified.
	VerdictAnchored Verdict = "INTACT_ANCHORED"

	// VerdictBroken means at least one break was found.
	VerdictBroken Verdict = "BROKEN"
)

// BreakType classifies a failure.
type BreakType string

const (
	// BreakHashMismatch: the recomputed chain hash differs from the stored one.
	BreakHashMismatch BreakType = "hash_mismatch"

	// BreakSequenceGap: global_seq is not contiguous — entries are missing or
	// reordered.
	BreakSequenceGap BreakType = "sequence_gap"

	// BreakInvalidTombstone: an entry claims to be a tombstone but its content
	// hash is malformed.
	BreakInvalidTombstone BreakType = "invalid_tombstone"

	// BreakUnknownFormat: the entry names a chain hash format this build does
	// not implement, so its hash cannot be recomputed. Reported rather than
	// guessed at: picking a preimage at random would produce a confident, wrong
	// answer about whether the chain is intact.
	BreakUnknownFormat BreakType = "unknown_format"

	// BreakFormatFieldMisuse: the entry carries fields its format does not bind
	// into the hash — a v3 entry with a run id or a batch sequence number.
	// Those values would look protected while being free to change.
	BreakFormatFieldMisuse BreakType = "format_field_misuse"

	// BreakInvalidTimestamp: the stored timestamp is not in [TimestampLayout].
	// One that does not parse at all leaves the hash unrecomputable; one that
	// parses but is spelled differently (another offset, another precision)
	// is a second spelling of a value the hash covers only one of.
	BreakInvalidTimestamp BreakType = "invalid_timestamp"

	// BreakInvalidField: a field is not in the shape its format requires: a
	// chain hash or content hash that is not a digest, a negative sequence
	// number, a v2 entry with no run id. Such an entry may still hash to its
	// stored chain hash, which is why the shape is checked on its own.
	BreakInvalidField BreakType = "invalid_field"
)

// Entry is one exported row.
//
// Field names and JSON tags match the published verification SDK's
// ExportedEntry, so an export from this package is readable by it and vice
// versa. Timestamp is a STRING in the exact form it was hashed
// (RFC3339 microseconds) — re-deriving it from a lower-precision value would
// change the hash.
//
// A v4 entry has two shapes (docs/format-spec.md §2.0). Live: every field but
// RunID and SequenceNum, with Salt and LeafHash. Erased: Erased true, and
// EntryID, EntryType, ContentHash and Salt empty. [Entry.MarshalJSON] writes
// each shape with exactly its members.
type Entry struct {
	EntryID   string `json:"entry_id"`
	EntryType string `json:"entry_type"`
	Timestamp string `json:"timestamp"`

	// FormatVersion selects the preimage: 4 for v4, 3 for v3, 2 or ABSENT for
	// v2. It is omitted from v2 output so that exports written before the field
	// existed remain byte-identical.
	FormatVersion int `json:"format_version,omitempty"`

	// RunID and SequenceNum are v2 hash inputs. A v3 entry must leave both at
	// their zero values; see the format check in [Chain].
	//
	// Deliberately NOT omitempty: the published verification SDK reads these
	// field names, and a v2 entry whose sequence_num happens to be 0 must still
	// emit "sequence_num": 0. Dropping it would change the bytes of every v2
	// export whose first entry is included.
	RunID       string `json:"run_id"`
	SequenceNum int64  `json:"sequence_num"`

	GlobalSeq   int64  `json:"global_seq"`
	ContentHash string `json:"content_hash"`
	ChainHash   string `json:"chain_hash"`

	// Salt, LeafHash and Erased are v4's (format-spec §2.0). A v2 or v3 entry
	// carrying any of them is a break.
	Salt     string `json:"salt,omitempty"`
	LeafHash string `json:"leaf_hash,omitempty"`
	Erased   bool   `json:"erased,omitempty"`

	// members records the members an entry read by [DecodeEntries] or an
	// [EntryReader] carried WITH THEIR ZERO VALUE, where that is a break in
	// its format: a v4 entry with "run_id": "", an erased one with
	// "entry_id": "", a v3 one with "salt": "". Every other member is judged
	// by its value, so an ordinary entry decodes with this zero and equals the
	// same entry built in Go.
	members memberSet
}

// memberSet is a set of entry member names, one bit each.
type memberSet uint16

const (
	memberEntryID memberSet = 1 << iota
	memberEntryType
	memberRunID
	memberSequenceNum
	memberContentHash
	memberSalt
	memberLeafHash
	memberErased
)

// has reports whether the entry carries the member: present in what was
// decoded, or, for an entry built in Go, not its zero value.
func (e Entry) has(m memberSet) bool {
	if e.members&m != 0 {
		return true
	}
	switch m {
	case memberEntryID:
		return e.EntryID != ""
	case memberEntryType:
		return e.EntryType != ""
	case memberRunID:
		return e.RunID != ""
	case memberSequenceNum:
		return e.SequenceNum != 0
	case memberContentHash:
		return e.ContentHash != ""
	case memberSalt:
		return e.Salt != ""
	case memberLeafHash:
		return e.LeafHash != ""
	case memberErased:
		return e.Erased
	}
	return false
}

// entryV4Live and entryV4Erased are the two v4 shapes as JSON, members in the
// order an export writes them.
type entryV4Live struct {
	EntryID       string `json:"entry_id"`
	EntryType     string `json:"entry_type"`
	Timestamp     string `json:"timestamp"`
	FormatVersion int    `json:"format_version"`
	GlobalSeq     int64  `json:"global_seq"`
	ContentHash   string `json:"content_hash"`
	Salt          string `json:"salt"`
	LeafHash      string `json:"leaf_hash"`
	ChainHash     string `json:"chain_hash"`
}

type entryV4Erased struct {
	Timestamp     string `json:"timestamp"`
	FormatVersion int    `json:"format_version"`
	GlobalSeq     int64  `json:"global_seq"`
	Erased        bool   `json:"erased"`
	LeafHash      string `json:"leaf_hash"`
	ChainHash     string `json:"chain_hash"`
}

// MarshalJSON writes an entry with exactly the members its format has.
//
// # Description
//
// A v2 or v3 entry is written as it always was: every member of the struct,
// run_id and sequence_num included, format_version omitted for v2. A v4 entry
// is written in its live or erased shape (format-spec §2.0): no run fields,
// and an erased entry without its id, type, content hash or salt, which are
// absent rather than empty.
//
// # Outputs
//
//   - []byte: the entry as JSON
//   - error: from encoding/json
//
// # Example
//
//	raw, err := json.Marshal(entry)
//
// # Limitations
//
//   - A v4 entry's fields are written as they are, valid or not; a v4 entry
//     with Erased set is written in the erased shape whatever else it holds.
//
// # Assumptions
//
//   - None.
func (e Entry) MarshalJSON() ([]byte, error) {
	if e.FormatVersion == chainformat.FormatV4 {
		if e.Erased {
			return json.Marshal(entryV4Erased{e.Timestamp, e.FormatVersion, e.GlobalSeq, true, e.LeafHash, e.ChainHash})
		}
		return json.Marshal(entryV4Live{e.EntryID, e.EntryType, e.Timestamp, e.FormatVersion, e.GlobalSeq,
			e.ContentHash, e.Salt, e.LeafHash, e.ChainHash})
	}
	type plain Entry // drops this method, so the struct tags apply as before
	return json.Marshal(plain(e))
}

// Break is one detected failure.
type Break struct {
	// Position is the index within the supplied entries.
	Position int `json:"position"`

	EntryID string    `json:"entry_id"`
	Type    BreakType `json:"break_type"`

	// Expected and Actual are populated for hash mismatches.
	Expected string `json:"expected_hash,omitempty"`
	Actual   string `json:"actual_hash,omitempty"`

	// Detail is a human-readable note; never contains entry content.
	Detail string `json:"detail,omitempty"`
}

// Result is the outcome of verifying a chain.
type Result struct {
	Verdict Verdict `json:"verdict"`

	// EntriesVerified is how many entries were walked.
	EntriesVerified int `json:"entries_verified"`

	// TombstonesFound counts v2 and v3 tombstones. Their presence is normal
	// and never a break; see the note on Breaks.
	TombstonesFound int `json:"tombstones_found"`

	// ErasedFound counts erased v4 entries. Each is recomputed from its leaf
	// hash like any other entry, so, unlike a tombstone, it leaves nothing
	// unlinked.
	ErasedFound int `json:"erased_found"`

	// LastTombstone is the index of the last erased entry, or -1. A tombstone's
	// chain hash is taken as stored, so the entries up to and including this
	// index are not linked to the entries after it: see the package's
	// Limitations.
	LastTombstone int `json:"last_tombstone"`

	// FirstBreak is the index of the earliest failure, or -1.
	//
	// THIS is the signal. A single altered entry cascades — verification
	// advances on the expected hash, so every later entry mismatches too — which
	// means len(Breaks) describes the blast radius, not the number of problems.
	FirstBreak int `json:"first_break"`

	Breaks []Break `json:"breaks,omitempty"`

	// AnchorChecked records whether an anchor was checked alongside the linkage.
	//
	// [Chain] always leaves it false, because it is handed entries and nothing
	// else. A caller that binds an anchor sets it, which is what makes the
	// difference between "no anchor was checked" and "an anchor was checked and
	// disagreed" visible to a consumer reading the JSON.
	AnchorChecked bool `json:"anchor_checked"`
}

// Options tunes a verification run.
type Options struct {
	// MaxBreaks stops collecting after this many. 0 means unlimited.
	//
	// Because one alteration cascades, an unbounded run over a large damaged
	// chain produces a report as long as the chain. FirstBreak stays correct
	// regardless.
	MaxBreaks int

	// PreviousHash is the chain hash the FIRST supplied entry links from.
	//
	// Empty — the zero value, and the usual case — means these entries begin a
	// chain. Set it to verify a SEGMENT: entries taken from the middle of a
	// chain link from their predecessor, not from nothing, so verifying them
	// against an empty previous hash reports a break on the first entry of a
	// perfectly good segment. [store.Reader.Predecessor] exists to supply it.
	//
	// The first entry's global_seq is NOT checked against either case. The
	// format does not fix where a chain starts: this module's linker starts at
	// 0 and the hosted platform's at 1.
	//
	// This does NOT establish that the predecessor is genuine. It says "these
	// entries link, given that one", which is the most a segment can support.
	PreviousHash string
}

// Chain verifies a chain from exported entries.
//
// # Description
//
// Walks the entries in the order given, re-deriving each chain hash from its
// predecessor. Two rules govern the walk:
//
//  1. an entry's hash must equal ComputeChainHash over its fields and the
//     previous entry's hash
//  2. a TOMBSTONE's hash is not recomputable — validate its format and advance
//     on the stored value, because later entries were chained against it
//
// Rule 2 is the one implementations get wrong; recomputing reports a false break
// on every lawfully erased entry. See docs/format-spec.md §5.
//
// # Inputs
//
//   - entries: exported rows in ascending order. An empty slice is an error, not
//     an intact chain — verifying nothing proves nothing.
//   - opts: see [Options]
//
// # Outputs
//
//   - Result: verdict, first break index, and the breaks found
//   - error: only for input that cannot be verified at all (no entries)
//
// # Example
//
//	res, err := verify.Chain(entries, verify.Options{})
//	if err != nil {
//	    return err
//	}
//	if res.Verdict != verify.VerdictIntact {
//	    return fmt.Errorf("chain broken at index %d", res.FirstBreak)
//	}
//
// # Limitations
//
//   - Proves consistency only. Truncation is undetectable without an anchor.
//   - Does not verify that content_hash matches any payload; it verifies the
//     commitment, not the thing committed to.
func Chain(entries []Entry, opts Options) (Result, error) {
	if len(entries) == 0 {
		return Result{}, fmt.Errorf("verify: no entries supplied; verifying nothing proves nothing")
	}
	w := NewWalker(opts)
	for _, e := range entries {
		w.Add(e)
	}
	return w.Result(), nil
}

// Walker verifies a chain one entry at a time: Chain's walk, streamed.
//
// # Description
//
// Chain holds every entry in memory. A caller reading a long chain from a
// store in pages feeds a Walker instead: the result is identical, because Chain
// IS a Walker over a slice. Between entries the walker can bind an anchor that
// covers exactly the entries seen so far (VerifyAnchor), so a series of
// checkpoints is checked in the same single pass.
//
// # Thread Safety
//
// Not safe for concurrent use.
type Walker struct {
	opts         Options
	res          Result
	previousHash string
	previousSeq  int64
	first, last  Entry
	sawV4        bool // a v4 entry was added; no v2 or v3 entry may follow
}

// NewWalker starts a walk. opts is as for Chain.
func NewWalker(opts Options) *Walker {
	return &Walker{opts: opts, res: Result{Verdict: VerdictIntact, FirstBreak: -1, LastTombstone: -1},
		previousHash: opts.PreviousHash}
}

// Segment reports whether the walk started from a predecessor hash
// (Options.PreviousHash): it is verifying a segment, not a chain from its
// first entry.
func (w *Walker) Segment() bool { return w.opts.PreviousHash != "" }

// Count is how many entries have been added.
func (w *Walker) Count() int { return w.res.EntriesVerified }

// First and Last are the first and most recent entries added.
func (w *Walker) First() Entry { return w.first }
func (w *Walker) Last() Entry  { return w.last }

// Result is the verdict over the entries added so far, as Chain would return it.
func (w *Walker) Result() Result {
	r := w.res
	r.Breaks = append([]Break(nil), w.res.Breaks...)
	return r
}

func (w *Walker) addBreak(b Break) {
	if w.res.FirstBreak == -1 {
		w.res.FirstBreak = b.Position
	}
	w.res.Verdict = VerdictBroken
	if w.opts.MaxBreaks == 0 || len(w.res.Breaks) < w.opts.MaxBreaks {
		w.res.Breaks = append(w.res.Breaks, b)
	}
}

// Add walks one entry. Every failure is recorded as a Break; there is no error.
func (w *Walker) Add(e Entry) {
	i := w.res.EntriesVerified
	w.res.EntriesVerified++
	if i == 0 {
		w.first = e
		w.checkStart(e)
	}
	w.last = e

	// Never back from v4 (format-spec §2.5) goes by the declared format, so a
	// v4 entry counts as seen even if a check below breaks it.
	if e.FormatVersion == chainformat.FormatV4 {
		defer func() { w.sawV4 = true }()
	}

	if i > 0 && e.GlobalSeq != w.previousSeq+1 {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakSequenceGap,
			Detail: fmt.Sprintf("expected global_seq %d, got %d", w.previousSeq+1, e.GlobalSeq),
		})
	}
	w.previousSeq = e.GlobalSeq

	// Every entry's chain hash is a digest, whatever else the entry is. Checked
	// first because three paths below advance on the STORED hash.
	if !chainHashPattern.MatchString(e.ChainHash) {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakInvalidField,
			Detail: "chain_hash is not 128 lowercase hex characters",
		})
		w.previousHash = e.ChainHash
		return
	}

	// Never back from v4 (format-spec §2.5). Checked before the tombstone
	// rule, because a v3 tombstone here is exactly what this prevents.
	if e.FormatVersion == chainformat.FormatV4 {
		w.addV4(i, e)
		return
	}
	if w.sawV4 {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakFormatFieldMisuse,
			Detail: "a v2 or v3 entry follows a v4 entry; a chain never goes back from v4",
		})
		w.previousHash = e.ChainHash
		return
	}

	if e.has(memberSalt) || e.has(memberLeafHash) || e.has(memberErased) {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakFormatFieldMisuse,
			Detail: "salt, leaf_hash and erased are v4 members; a v2 or v3 entry carries none",
		})
		w.previousHash = e.ChainHash
		return
	}

	// Rule 2 — tombstones. Format only, then advance on the STORED hash.
	if chainformat.IsTombstone(e.EntryType, e.EntryID) {
		w.res.TombstonesFound++
		w.res.LastTombstone = i
		// Its hash is not recomputed, but what it declares is still checked:
		// a tombstone naming a format this build does not implement, or a v3
		// one carrying v2's fields, once passed because this branch returned
		// before the format dispatch below.
		switch chainformat.NormalizeFormatVersion(e.FormatVersion) {
		case chainformat.FormatV2:
		case chainformat.FormatV3:
			if e.RunID != "" || e.SequenceNum != 0 {
				w.addBreak(Break{
					Position: i, EntryID: e.EntryID, Type: BreakFormatFieldMisuse,
					Detail: "a v3 entry must not carry run_id or sequence_num; neither is bound into its hash",
				})
			}
		default:
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakUnknownFormat,
				Detail: fmt.Sprintf("chain hash format version %d is not implemented by this build", e.FormatVersion),
			})
		}
		if e.GlobalSeq < 0 {
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakInvalidField,
				Detail: fmt.Sprintf("globalSeq must be non-negative, got %d", e.GlobalSeq),
			})
		}
		if !chainformat.ValidateTombstoneContentHash(e.ContentHash) {
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakInvalidTombstone,
				Detail: "content hash is not a well-formed tombstone value",
			})
		}
		w.previousHash = e.ChainHash
		return
	}

	ts, ok := w.timestamp(i, e)
	if !ok {
		return
	}

	// The two formats cannot be told apart by looking at a digest, so the
	// entry has to say which preimage produced it. Absent means v2, which is
	// what every entry written before the field existed carries.
	//
	// The field shapes are checked before the hash is recomputed: the preimage
	// is '|'-delimited, so a hash over malformed fields proves nothing about
	// which fields produced it.
	var expected string
	var shapeErr error
	switch chainformat.NormalizeFormatVersion(e.FormatVersion) {
	case chainformat.FormatV2:
		shapeErr = chainformat.ValidateChainHashInputs(
			w.previousHash, e.RunID, e.SequenceNum, e.ContentHash)
		if shapeErr == nil && e.GlobalSeq < 0 {
			shapeErr = fmt.Errorf("globalSeq must be non-negative, got %d", e.GlobalSeq)
		}
		expected = chainformat.ComputeChainHashUnchecked(
			w.previousHash, e.RunID, e.SequenceNum, ts, e.ContentHash)
	case chainformat.FormatV3:
		if e.RunID != "" || e.SequenceNum != 0 {
			// v3 binds neither field. Carrying them anyway invites a reader
			// to treat them as attested when they are free to change.
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakFormatFieldMisuse,
				Detail: "a v3 entry must not carry run_id or sequence_num; neither is bound into its hash",
			})
			w.previousHash = e.ChainHash
			return
		}
		shapeErr = chainformat.ValidateChainHashInputsV3(w.previousHash, e.GlobalSeq, e.ContentHash)
		expected = chainformat.ComputeChainHashV3Unchecked(
			w.previousHash, e.GlobalSeq, ts, e.ContentHash)
	default:
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakUnknownFormat,
			Detail: fmt.Sprintf("chain hash format version %d is not implemented by this build", e.FormatVersion),
		})
		w.previousHash = e.ChainHash
		return
	}
	if shapeErr != nil {
		// The validators name the field and its length, never its value.
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakInvalidField,
			Detail: shapeErr.Error(),
		})
		w.previousHash = e.ChainHash
		return
	}

	if expected != e.ChainHash {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakHashMismatch,
			Expected: expected, Actual: e.ChainHash,
		})
	}
	w.previousHash = expected
}

// addV4 walks one v4 entry (format-spec §2.0, §5.0): every entry, erased or
// not, is recomputed. The chain hash shape and the sequence were checked by
// Add.
func (w *Walker) addV4(i int, e Entry) {
	brk := func(t BreakType, detail string) {
		w.addBreak(Break{Position: i, EntryID: e.EntryID, Type: t, Detail: detail})
		w.previousHash = e.ChainHash
	}
	// Counted whatever else is wrong with it, as a malformed tombstone is.
	if e.Erased {
		w.res.ErasedFound++
	}

	// Members that belong to another format, or to a tombstone, are misuse:
	// they look protected and are not, or they invite the tombstone rule.
	if e.has(memberRunID) || e.has(memberSequenceNum) {
		brk(BreakFormatFieldMisuse, "a v4 entry carries no run_id or sequence_num")
		return
	}
	if !e.Erased && (e.EntryType == chainformat.TombstoneEntryType ||
		strings.HasPrefix(e.EntryID, chainformat.TombstoneEntryIDPrefix) ||
		strings.HasPrefix(e.ContentHash, chainformat.TombstoneContentHashPrefix)) {
		brk(BreakFormatFieldMisuse, chainformat.ErrTombstoneInV4.Error())
		return
	}

	ts, ok := w.timestamp(i, e)
	if !ok {
		return
	}

	// The two shapes, then the field shapes within them.
	var shapeErr error
	switch {
	case e.Erased:
		if e.has(memberEntryID) || e.has(memberEntryType) || e.has(memberContentHash) || e.has(memberSalt) {
			shapeErr = errors.New("an erased v4 entry carries no entry_id, entry_type, content_hash or salt")
		} else if !chainHashPattern.MatchString(e.LeafHash) {
			shapeErr = errors.New("leaf_hash is not 128 lowercase hex characters")
		}
	case e.has(memberErased):
		shapeErr = errors.New("a live v4 entry carries no erased member")
	case !e.has(memberSalt) || !e.has(memberLeafHash):
		shapeErr = errors.New("a live v4 entry carries its salt and leaf_hash")
	default:
		shapeErr = chainformat.ValidateLeafInputsV4(e.EntryID, e.EntryType, e.ContentHash, e.Salt)
		if shapeErr == nil && !chainHashPattern.MatchString(e.LeafHash) {
			shapeErr = errors.New("leaf_hash is not 128 lowercase hex characters")
		}
	}
	if shapeErr == nil {
		shapeErr = chainformat.ValidateChainHashInputsV4(w.previousHash, e.GlobalSeq, e.LeafHash)
	}
	if shapeErr != nil {
		brk(BreakInvalidField, shapeErr.Error())
		return
	}

	leaf := e.LeafHash
	if !e.Erased {
		leaf = chainformat.ComputeLeafHashV4Unchecked(e.EntryID, e.EntryType, e.ContentHash, e.Salt)
		if leaf != e.LeafHash {
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakHashMismatch,
				Expected: leaf, Actual: e.LeafHash,
				Detail: "leaf_hash does not match the entry's id, type, content hash and salt",
			})
			// Advance on the chain hash the true leaf gives, as a v3 mismatch
			// advances on the expected hash.
			w.previousHash = chainformat.ComputeChainHashV4Unchecked(w.previousHash, e.GlobalSeq, ts, leaf)
			return
		}
	}

	expected := chainformat.ComputeChainHashV4Unchecked(w.previousHash, e.GlobalSeq, ts, leaf)
	if expected != e.ChainHash {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakHashMismatch,
			Expected: expected, Actual: e.ChainHash,
		})
	}
	w.previousHash = expected
}

// timestamp parses an entry's stored timestamp and checks it is in the one
// spelling the hash covers (format-spec §4). It reports false, having recorded
// the break and advanced on the stored hash, when the timestamp does not parse.
// A timestamp that parses in another spelling is recorded as a break and
// still returned, so the hash is checked too.
func (w *Walker) timestamp(i int, e Entry) (time.Time, bool) {
	ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakInvalidTimestamp,
			Detail: "timestamp is not RFC3339; the chain hash cannot be recomputed",
		})
		// Advance on the stored hash: the entry cannot be checked, but the
		// entries after it still can, and linking from a hash we could not
		// derive would report breaks for them too.
		w.previousHash = e.ChainHash
		return time.Time{}, false
	}
	if ts.UTC().Format(TimestampLayout) != e.Timestamp {
		// The hash covers the instant in one spelling. A stored string in any
		// other spelling (an offset, fewer or more digits) would hash the same
		// and read differently, so it is refused rather than normalised.
		w.addBreak(Break{
			Position: i, EntryID: e.EntryID, Type: BreakInvalidTimestamp,
			Detail: "timestamp is not in the form YYYY-MM-DDTHH:MM:SS.ffffffZ",
		})
	}
	return ts, true
}

// checkStart checks what the walk links from: nothing, or a well-formed
// predecessor hash.
func (w *Walker) checkStart(e Entry) {
	if w.opts.PreviousHash != "" && !chainHashPattern.MatchString(w.opts.PreviousHash) {
		w.addBreak(Break{
			Position: 0, EntryID: e.EntryID, Type: BreakInvalidField,
			Detail: "the supplied previous hash is not 128 lowercase hex characters",
		})
	}
}
