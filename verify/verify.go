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
	EntryID     string `json:"entry_id"`
	EntryType   string `json:"entry_type"`
	Timestamp   string `json:"timestamp"`
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

		expected := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, ts, e.ContentHash)
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
