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
// # Two chain formats, and why the version is never guessed
//
// An entry names the preimage that produced its hash. v3 binds the chain-wide
// global_seq; v2 binds a run id and a batch-local sequence number. The two
// cannot be distinguished by looking at a digest, so this package dispatches on
// the DECLARED version and refuses what it does not recognise
// ([BreakUnknownFormat]) rather than trying the other one. Guessing would turn
// an unreadable entry into a reported forgery.
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
//   - Skips hash recomputation for tombstones and validates their format only.
//     A tombstone keeps the original entry's chain hash, which is not
//     reproducible from its remaining fields. THE CONSEQUENCE: a tombstone's
//     chain hash is taken as stored, so nothing links the entries BEFORE a
//     tombstone to the entries after it. Whoever can write the store can
//     replace every entry before a tombstone (or before an entry they turn
//     into one) and the walk still reports INTACT, under a signed anchor too.
//     [Result.TombstonesFound] and [Result.LastTombstone] say whether, and up
//     to where, a result is exposed to this. Closing it needs a format change.
//   - entry_id and entry_type are in no hash. Either can be changed without a
//     break; entry_type decides whether an entry is read as a tombstone.
//
// # Assumptions
//
//   - Entries arrive in ascending global_seq order, as every exporter in this
//     module produces them. Out-of-order input reports breaks on an intact chain.
//   - Timestamps are stored in the form they were hashed in, [TimestampLayout].
//     Any other spelling of the same instant is a break.
package verify

import (
	"fmt"
	"regexp"
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
type Entry struct {
	EntryID   string `json:"entry_id"`
	EntryType string `json:"entry_type"`
	Timestamp string `json:"timestamp"`

	// FormatVersion selects the preimage: 3 for v3, 2 or ABSENT for v2. It is
	// omitted from v2 output so that exports written before the field existed
	// remain byte-identical.
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

	// TombstonesFound counts erased entries. Their presence is normal and never
	// a break; see the note on Breaks.
	TombstonesFound int `json:"tombstones_found"`

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
	// chain, and the first must be at global_seq 0. Set it to verify a SEGMENT:
	// entries taken from the middle of a chain link from their predecessor, not
	// from nothing, and the first is at global_seq 1 or later.
	// [store.Reader.Predecessor] exists to supply it.
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
}

// NewWalker starts a walk. opts is as for Chain.
func NewWalker(opts Options) *Walker {
	return &Walker{opts: opts, res: Result{Verdict: VerdictIntact, FirstBreak: -1, LastTombstone: -1},
		previousHash: opts.PreviousHash}
}

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

	// Rule 2 — tombstones. Format only, then advance on the STORED hash.
	if chainformat.IsTombstone(e.EntryType, e.EntryID) {
		w.res.TombstonesFound++
		w.res.LastTombstone = i
		if !chainformat.ValidateTombstoneContentHash(e.ContentHash) {
			w.addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakInvalidTombstone,
				Detail: "content hash is not a well-formed tombstone value",
			})
		}
		w.previousHash = e.ChainHash
		return
	}

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
		return
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

// checkStart checks where the walk begins: a whole chain starts at global_seq 0
// and links from nothing; a segment starts later and links from a well-formed
// predecessor hash.
func (w *Walker) checkStart(e Entry) {
	if w.opts.PreviousHash == "" {
		if e.GlobalSeq != 0 {
			w.addBreak(Break{
				Position: 0, EntryID: e.EntryID, Type: BreakSequenceGap,
				Detail: fmt.Sprintf("a chain starts at global_seq 0, and the first entry is at %d; "+
					"to verify a segment, supply its predecessor's chain hash", e.GlobalSeq),
			})
		}
		return
	}
	if !chainHashPattern.MatchString(w.opts.PreviousHash) {
		w.addBreak(Break{
			Position: 0, EntryID: e.EntryID, Type: BreakInvalidField,
			Detail: "the supplied previous hash is not 128 lowercase hex characters",
		})
	}
	if e.GlobalSeq < 1 {
		w.addBreak(Break{
			Position: 0, EntryID: e.EntryID, Type: BreakSequenceGap,
			Detail: fmt.Sprintf("a segment has a predecessor, so its first entry is at global_seq 1 "+
				"or later; got %d", e.GlobalSeq),
		})
	}
}
