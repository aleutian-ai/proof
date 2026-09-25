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
//     reproducible from its remaining fields.
//
// # Assumptions
//
//   - Entries arrive in ascending global_seq order, as every exporter in this
//     module produces them. Out-of-order input reports breaks on an intact chain.
//   - Timestamps are in the exact form they were hashed in. A re-derived,
//     lower-precision timestamp breaks verification for sub-millisecond entries.
package verify

import (
	"fmt"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
)

// Verdict is the overall outcome of a verification.
type Verdict string

const (
	// VerdictIntact means the linkage holds: no entry was altered by anyone
	// unable to also rewrite everything after it. It does NOT mean this is the
	// same chain the caller saw previously — truncation is undetectable from
	// entries alone.
	VerdictIntact Verdict = "INTACT"

	// VerdictAnchored means the linkage holds AND an anchor bound it to a point
	// in time. Not yet reachable: anchor verification is unimplemented.
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

	// BreakInvalidTimestamp: the stored timestamp could not be parsed, so the
	// hash cannot be recomputed.
	BreakInvalidTimestamp BreakType = "invalid_timestamp"
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

	// FirstBreak is the index of the earliest failure, or -1.
	//
	// THIS is the signal. A single altered entry cascades — verification
	// advances on the expected hash, so every later entry mismatches too — which
	// means len(Breaks) describes the blast radius, not the number of problems.
	FirstBreak int `json:"first_break"`

	Breaks []Break `json:"breaks,omitempty"`

	// AnchorChecked records whether an anchor was verified. Always false today.
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

	res := Result{
		Verdict:         VerdictIntact,
		EntriesVerified: len(entries),
		FirstBreak:      -1,
	}
	addBreak := func(b Break) {
		if res.FirstBreak == -1 {
			res.FirstBreak = b.Position
		}
		res.Verdict = VerdictBroken
		if opts.MaxBreaks == 0 || len(res.Breaks) < opts.MaxBreaks {
			res.Breaks = append(res.Breaks, b)
		}
	}

	previousHash := ""
	previousSeq := int64(0)

	for i, e := range entries {
		if i > 0 && e.GlobalSeq != previousSeq+1 {
			addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakSequenceGap,
				Detail: fmt.Sprintf("expected global_seq %d, got %d", previousSeq+1, e.GlobalSeq),
			})
		}
		previousSeq = e.GlobalSeq

		// Rule 2 — tombstones. Format only, then advance on the STORED hash.
		if chainformat.IsTombstone(e.EntryType, e.EntryID) {
			res.TombstonesFound++
			if !chainformat.ValidateTombstoneContentHash(e.ContentHash) {
				addBreak(Break{
					Position: i, EntryID: e.EntryID, Type: BreakInvalidTombstone,
					Detail: "content hash is not a well-formed tombstone value",
				})
			}
			previousHash = e.ChainHash
			continue
		}

		ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakInvalidTimestamp,
				Detail: "timestamp is not RFC3339; the chain hash cannot be recomputed",
			})
			// Advance on the stored hash: the entry cannot be checked, but the
			// entries after it still can, and linking from a hash we could not
			// derive would report breaks for them too.
			previousHash = e.ChainHash
			continue
		}

		// The two formats cannot be told apart by looking at a digest, so the
		// entry has to say which preimage produced it. Absent means v2, which is
		// what every entry written before the field existed carries.
		var expected string
		switch chainformat.NormalizeFormatVersion(e.FormatVersion) {
		case chainformat.FormatV2:
			expected = chainformat.ComputeChainHashUnchecked(
				previousHash, e.RunID, e.SequenceNum, ts, e.ContentHash)
		case chainformat.FormatV3:
			if e.RunID != "" || e.SequenceNum != 0 {
				// v3 binds neither field. Carrying them anyway invites a reader
				// to treat them as attested when they are free to change.
				addBreak(Break{
					Position: i, EntryID: e.EntryID, Type: BreakFormatFieldMisuse,
					Detail: "a v3 entry must not carry run_id or sequence_num; neither is bound into its hash",
				})
				previousHash = e.ChainHash
				continue
			}
			expected = chainformat.ComputeChainHashV3Unchecked(
				previousHash, e.GlobalSeq, ts, e.ContentHash)
		default:
			addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakUnknownFormat,
				Detail: fmt.Sprintf("chain hash format version %d is not implemented by this build", e.FormatVersion),
			})
			previousHash = e.ChainHash
			continue
		}

		if expected != e.ChainHash {
			addBreak(Break{
				Position: i, EntryID: e.EntryID, Type: BreakHashMismatch,
				Expected: expected, Actual: e.ChainHash,
			})
		}
		previousHash = expected
	}

	return res, nil
}
