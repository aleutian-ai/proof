// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
)

// BindOutcome is why an anchor did or did not describe a chain.
type BindOutcome string

const (
	// BindOK: the chain matches what the anchor committed to, except the
	// entries up to and including its last tombstone (BindResult.EntriesNotBound).
	BindOK BindOutcome = "bound"

	// BindChainBroken: linkage failed before the anchor could be considered.
	BindChainBroken BindOutcome = "chain_broken"

	// BindRangeStartMismatch: the anchor's committed first entry is not this
	// chain's first entry. THIS IS THE TRUNCATION SIGNAL — entries were removed
	// from the front and the remainder re-linked.
	BindRangeStartMismatch BindOutcome = "range_start_mismatch"

	// BindRangeEndMismatch: the anchor's committed last entry is not this
	// chain's last entry.
	BindRangeEndMismatch BindOutcome = "range_end_mismatch"

	// BindHeightMismatch: the chain's length disagrees with the height the
	// anchor committed to — entries were added or removed within the range.
	BindHeightMismatch BindOutcome = "height_mismatch"

	// BindHeadMismatch: the recomputed head differs from the head the anchor
	// bound. Content changed somewhere inside the range.
	BindHeadMismatch BindOutcome = "head_mismatch"

	// BindTenantMismatch: the anchor is for a different tenant.
	BindTenantMismatch BindOutcome = "tenant_mismatch"

	// BindPredecessorMismatch: the anchor names the seed anchor as its
	// predecessor while a predecessor hash was supplied, or names a real
	// predecessor while the seed hash was. One of the two is wrong, and a
	// second anchor passing as the first is how a series is cut.
	BindPredecessorMismatch BindOutcome = "predecessor_mismatch"

	// BindSignatureInvalid: the anchor's signature did not verify (a bad
	// signature, an unknown key, an unsupported version). Bound is false
	// whatever the chain looked like: an anchor nobody signed describes
	// nothing. Detail says whether the chain matched it, so "genuine anchor,
	// different chain" and "forged anchor" stay distinguishable. Returned
	// together with the signature error.
	BindSignatureInvalid BindOutcome = "signature_invalid"
)

// errNoKeySource is returned by the VerifyAnchor functions when given no key
// source. It was a documented precondition, and a nil one panicked; use
// BindAnchor to bind without a signature.
var errNoKeySource = errors.New("verify: a key source is required to verify an anchor's signature; " +
	"use BindAnchor to bind without one")

// ErrNoEntries is returned when there is nothing to bind an anchor to.
var ErrNoEntries = errors.New("verify: no entries to bind")

// BindResult reports whether a chain matches an anchor, and what that proves.
type BindResult struct {
	// Outcome is the machine-readable result.
	Outcome BindOutcome `json:"outcome"`

	// Bound is true only when Outcome is BindOK.
	Bound bool `json:"bound"`

	// Detail is a human-readable explanation. Never contains entry content.
	Detail string `json:"detail,omitempty"`

	// EntriesCovered is how many entries the anchor commits to.
	EntriesCovered int64 `json:"entries_covered"`

	// Tombstones is how many erased entries the chain holds.
	Tombstones int `json:"tombstones"`

	// EntriesNotBound is how many entries, counted from the first, the anchor
	// does NOT bind: every entry up to and including the last tombstone. A
	// tombstone's chain hash is taken as stored, so the head the anchor signed
	// depends only on the entries after it. Zero when the chain has no
	// tombstone. Proven and NotProven say the same in words.
	EntriesNotBound int64 `json:"entries_not_bound"`

	// Trust is what a verified signature established, empty for a keyless bind.
	Trust anchor.Trust `json:"trust,omitempty"`

	// SignatureVerified distinguishes a keyless bind from a full verification.
	// A keyless bind proves the chain matches the anchor; it proves NOTHING
	// about where the anchor came from.
	SignatureVerified bool `json:"signature_verified"`

	// SubjectChecked is whether the anchor's subject was compared with one the
	// caller expected (Expect.Subject). When it was not, a bound result proves
	// the chain matches an anchor, not that the anchor is about the chain the
	// caller meant, and NotProven says so.
	SubjectChecked bool `json:"subject_checked"`

	// Proven and NotProven state the claim in plain language. They are part of
	// the payload, not the docs, because a caller relaying this result must have
	// to actively discard the caveat rather than remember to add it.
	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

// Expect is what the caller expects an anchor to be: the other half of a
// bind, which an anchor cannot supply about itself (format-spec §9.7).
type Expect struct {
	// Subject is the subject the anchor must be for. Empty means not checked,
	// and the result says so (BindResult.SubjectChecked). A genuine anchor for
	// another subject is BindTenantMismatch.
	Subject string

	// PreviousAnchorHash is the predecessor's ChainHash, or
	// anchor.SeedAnchorHash for a first anchor.
	//
	// REQUIRED for v1 to v6: their predecessor's hash is inside their chain hash
	// and nowhere in the anchor, so a verifier that assumed one could check no
	// anchor but the first. It was once defaulted to the seed, which made
	// binding silently genesis-only.
	//
	// Optional for v7, which signs its predecessor's hash: when given, the
	// anchor's previous_anchor_hash must equal it (BindPredecessorMismatch).
	PreviousAnchorHash string
}

// BindAnchor checks a chain against an anchor WITHOUT verifying the signature.
//
// # Description
//
// Recomputes the chain's head from the entries, then recomputes the anchor's own
// chain hash from what it committed to, and compares. It answers "is the chain
// in front of me the one this anchor described", and deliberately not "is this
// anchor genuine" — that needs a key, and is [VerifyAnchor].
//
// The checks, in order, the first that fails deciding the outcome
// (format-spec §9.7): the chain walks clean (BindChainBroken); the range starts
// at the chain's first entry (BindRangeStartMismatch); the range's end is
// there (v7: an entry at end_seq; v1 to v6: the last entry, with the right id
// and count); the predecessor is the one expected (BindPredecessorMismatch);
// the subject is the one expected (BindTenantMismatch); the head recomputes
// (BindHeadMismatch).
//
// A v7 anchor names its range by sequence, so erasing any entry of it changes
// nothing it binds, and its tip is the entry at end_seq: a chain that has grown
// since still binds. A v1 to v6 anchor names its first and last entry ids and
// must be given the chain as it was when it was signed, entries[:a.EntryCount].
//
// # Inputs
//
//   - a: the anchor to bind against
//   - entries: the chain from its first entry, in ascending sequence order
//   - expect: what the caller expects; see [Expect]. Validated, not trusted.
//
// # Outputs
//
//   - BindResult: outcome plus the explicit proven / not-proven claim
//   - error: ErrNoEntries, a malformed anchor, or a malformed or missing
//     expected predecessor hash
//
// # Example
//
//	res, err := verify.BindAnchor(a, entries, verify.Expect{Subject: "orders"})
//	if err != nil {
//	    return err
//	}
//	if !res.Bound {
//	    log.Printf("anchor does not describe this chain: %s", res.Detail)
//	}
//
// # Limitations
//
//   - Keyless by design. res.SignatureVerified is always false.
//   - Covers only the anchored range; entries after the anchor are unprotected.
//   - Checks that the anchor commits to THIS predecessor hash. It does not check
//     that the predecessor is genuine — walk the series with [Series] for that.
//
// # Assumptions
//
//   - entries are ordered ascending by sequence, as exported
func BindAnchor(a anchor.Anchor, entries []Entry, expect Expect) (BindResult, error) {
	if len(entries) == 0 {
		return BindResult{}, ErrNoEntries
	}
	// Validated up front, and as an ERROR rather than a mismatch. A malformed
	// previous hash would otherwise recompute to something that simply does not
	// match, and get reported as BindHeadMismatch — telling the caller their
	// chain was tampered with when in fact their argument was wrong.
	if err := validateExpect(a, expect); err != nil {
		return BindResult{}, err
	}
	if err := anchor.ValidateVersionInvariants(a); err != nil {
		return BindResult{}, fmt.Errorf("verify: malformed anchor: %w", err)
	}

	// The walk is Chain's own. BindAnchor once had a second walker, and the two
	// disagreed about what a tombstone is: this one took any entry whose content
	// hash began "TOMBSTONE:" as erased and adopted its stored chain hash.
	w := NewWalker(Options{MaxBreaks: 1})
	for _, e := range entries {
		w.Add(e)
	}
	if a.Version != anchor.SequenceRangeVersion {
		return w.bind(a, expect)
	}
	// v7: the tip is the entry at end_seq, wherever it is in what was given,
	// and only the tombstones at or before it limit what the anchor binds.
	return w.bindV7(a, expect, tipOf(entries, a.Range.EndSeq))
}

// tipOf is the entry at globalSeq and the tombstones up to it, or a tipState
// that was not found.
func tipOf(entries []Entry, globalSeq int64) tipState {
	t := tipState{lastTomb: -1}
	for i, e := range entries {
		if e.FormatVersion != chainformat.FormatV4 && chainformat.IsTombstone(e.EntryType, e.EntryID) {
			t.tombstones, t.lastTomb = t.tombstones+1, i
		}
		if e.GlobalSeq == globalSeq {
			t.found, t.hash = true, e.ChainHash
			return t
		}
	}
	return tipState{lastTomb: -1}
}

// bind is BindAnchor after the walk, for v1 to v6: it binds a to exactly the
// entries the walker has seen. Shared by BindAnchor and the Walker methods, so
// the paths cannot drift apart.
func (w *Walker) bind(a anchor.Anchor, expect Expect) (BindResult, error) {
	if a.Version == anchor.SequenceRangeVersion {
		// The tip is the last entry walked, or the one WatchTip recorded.
		tip := tipState{lastTomb: -1}
		switch {
		case w.last.GlobalSeq == a.Range.EndSeq:
			tip = tipState{found: true, hash: w.last.ChainHash,
				tombstones: w.res.TombstonesFound, lastTomb: w.res.LastTombstone}
		case w.watchSeq != nil && *w.watchSeq == a.Range.EndSeq:
			tip = w.watched
		}
		return w.bindV7(a, expect, tip)
	}
	if err := w.refuseSegment(); err != nil {
		return BindResult{}, err
	}
	previousAnchorHash := expect.PreviousAnchorHash
	firstID, lastID, count := w.first.EntryID, w.last.EntryID, int64(w.Count())
	res := w.unbound(a, expect, w.res.TombstonesFound, int64(w.res.LastTombstone+1))
	boundProven, boundNotProven := w.boundClaims(res, count)
	if broken, err := w.broken(&res); broken || err != nil {
		return res, err
	}
	head := w.last.ChainHash

	if firstID != a.Range.StartEntryID {
		res.Outcome = BindRangeStartMismatch
		res.Detail = "the anchor's committed first entry is not this chain's first entry; " +
			"entries were removed from the front"
		return res, nil
	}
	if lastID != a.Range.EndEntryID {
		res.Outcome = BindRangeEndMismatch
		res.Detail = "the anchor's committed last entry is not this chain's last entry"
		return res, nil
	}
	if count != a.EntryCount {
		res.Outcome = BindHeightMismatch
		res.Detail = fmt.Sprintf("chain has %d entries; the anchor committed to %d",
			count, a.EntryCount)
		return res, nil
	}

	// The predecessor is named twice, by id in the anchor and by hash in the
	// argument, and the two must agree about whether there is one: the seed
	// hash goes with the seed id and with no other. A second anchor passing as
	// the first is how a series is cut.
	if (previousAnchorHash == anchor.SeedAnchorHash) != (a.PreviousAnchorID == anchor.SeedAnchorID) {
		res.Outcome = BindPredecessorMismatch
		res.Detail = "the anchor's previous_anchor_id and the predecessor hash supplied disagree about " +
			"whether this is the first anchor of its series"
		return res, nil
	}
	if expect.Subject != "" && a.Subject != expect.Subject {
		res.Outcome = BindTenantMismatch
		res.Detail = "the anchor is for another subject than the one expected"
		return res, nil
	}

	// Recompute the anchor's own chain hash from what it committed to.
	//
	// Delimiter guard only, never strict shape validation: this path evaluates
	// anchors signed long ago, and tightening it would flip historical anchors
	// from passing to broken.
	recomputed, err := anchor.ChainHash(
		previousAnchorHash, a.Subject, firstID, lastID, head)
	if err != nil {
		return BindResult{}, fmt.Errorf("verify: %w", err)
	}
	if recomputed != a.ChainHash {
		res.Outcome = BindHeadMismatch
		res.Detail = "the recomputed head does not match the head the anchor bound"
		return res, nil
	}

	res.Outcome, res.Bound = BindOK, true
	res.Proven, res.NotProven = boundProven, boundNotProven
	return res, nil
}

// bindV7 binds a v7 anchor after the walk (format-spec §9.7). tip is the
// index, in walk order, of the entry at end_seq, or -1. entries, when given,
// are what was walked, and decide which tombstones lie at or before the tip;
// otherwise the tip is the walker's last entry and its counts apply.
func (w *Walker) bindV7(a anchor.Anchor, expect Expect, tip tipState) (BindResult, error) {
	if err := w.refuseSegment(); err != nil {
		return BindResult{}, err
	}
	tombstones, lastTomb := w.res.TombstonesFound, w.res.LastTombstone
	if tip.found {
		tombstones, lastTomb = tip.tombstones, tip.lastTomb
	}
	res := w.unbound(a, expect, tombstones, int64(lastTomb+1))
	boundProven, boundNotProven := w.boundClaims(res, a.EntryCount)
	if broken, err := w.broken(&res); broken || err != nil {
		return res, err
	}
	if w.first.GlobalSeq != a.Range.StartSeq {
		res.Outcome = BindRangeStartMismatch
		res.Detail = fmt.Sprintf("the anchor's range starts at global_seq %d and this chain at %d",
			a.Range.StartSeq, w.first.GlobalSeq)
		return res, nil
	}
	if !tip.found {
		res.Outcome = BindHeightMismatch
		res.Detail = fmt.Sprintf("the anchor covers entries up to global_seq %d, and this chain has none there",
			a.Range.EndSeq)
		return res, nil
	}
	head := tip.hash
	if expect.PreviousAnchorHash != "" && a.PreviousAnchorHash != expect.PreviousAnchorHash {
		res.Outcome = BindPredecessorMismatch
		res.Detail = "the anchor's previous_anchor_hash is not the predecessor expected"
		return res, nil
	}
	if expect.Subject != "" && a.Subject != expect.Subject {
		res.Outcome = BindTenantMismatch
		res.Detail = "the anchor is for another subject than the one expected"
		return res, nil
	}
	if anchor.ChainHashV7(a.PreviousAnchorHash, a.Subject, a.Range.StartSeq, a.Range.EndSeq, head) != a.ChainHash {
		res.Outcome = BindHeadMismatch
		res.Detail = "the recomputed head does not match the head the anchor bound"
		return res, nil
	}
	res.Outcome, res.Bound = BindOK, true
	res.Proven, res.NotProven = boundProven, boundNotProven
	return res, nil
}

// refuseSegment refuses a walk that started from a predecessor hash. An
// anchor's range is counted from the chain's first entry (format-spec §9.1,
// §9.8), and an anchor bound to a segment would read as covering a chain.
func (w *Walker) refuseSegment() error {
	if w.opts.PreviousHash != "" {
		return errors.New("verify: an anchor covers a chain from its first entry; " +
			"this walk started from a predecessor hash, so it saw a segment")
	}
	return nil
}

// unbound is the result every outcome but a bind carries. The wording for a
// bind is set only where the bind succeeds: every other outcome once carried
// "the chain in front of you is the one this anchor committed to" beside an
// outcome that said it was not.
func (w *Walker) unbound(a anchor.Anchor, expect Expect, tombstones int, notBound int64) BindResult {
	return BindResult{
		EntriesCovered:  a.EntryCount,
		Tombstones:      tombstones,
		EntriesNotBound: notBound,
		SubjectChecked:  expect.Subject != "",
		Proven:          "nothing: this anchor does not describe the chain in front of you",
		NotProven:       "that the chain is the one this anchor committed to",
	}
}

// boundClaims is what a bind proves, and what it leaves unproven.
func (w *Walker) boundClaims(res BindResult, count int64) (string, string) {
	proven := "the chain in front of you is the one this anchor committed to"
	notProven := "that the anchor is genuine — no signature was checked, so an " +
		"adversary able to rewrite the chain could also have minted this anchor"
	if res.Tombstones > 0 {
		proven = boundAfterTombstone(res.EntriesNotBound, count)
		notProven = notBoundBeforeTombstone(res.EntriesNotBound) + "; or " + notProven
	}
	if !res.SubjectChecked {
		notProven += "; " + subjectNotChecked
	}
	return proven, notProven
}

// subjectNotChecked is what a bound result leaves open when no subject was
// expected (format-spec §9.7).
const subjectNotChecked = "that the anchor is about the chain you meant: no expected subject was " +
	"given, so its subject was not checked"

// broken reports a chain that did not walk clean as res's outcome. An entry
// this build cannot recompute is not evidence of tampering, and is an error,
// not a broken chain.
func (w *Walker) broken(res *BindResult) (bool, error) {
	brk := w.res.FirstBreak
	if brk < 0 {
		return false, nil
	}
	if len(w.res.Breaks) > 0 {
		switch first := w.res.Breaks[0]; first.Type {
		case BreakUnknownFormat, BreakFormatFieldMisuse:
			return true, fmt.Errorf("verify: entry %d: %s", brk, first.Detail)
		}
	}
	res.Outcome, res.Detail = BindChainBroken, fmt.Sprintf("linkage breaks at entry %d", brk)
	return true, nil
}

// VerifyAnchor binds a chain to an anchor AND verifies the anchor's signature.
//
// # Description
//
// The full check. Runs BindAnchor, then verifies the ML-DSA-65 signature via the
// supplied key source, and reports what that key establishes.
//
// Kept separate from BindAnchor on purpose. The keyless claim is genuinely
// weaker, and an API where the caller can accidentally get the weak answer while
// believing they asked for the strong one is a bad API for a compliance tool.
//
// A successful result still depends on WHERE the anchor came from. An anchor
// read back from the same store as the chain proves consistency; only a copy the
// chain's operator cannot rewrite proves external commitment. This function
// cannot tell the difference — the Trust level reports what the KEY establishes,
// not what the anchor's provenance does.
//
// # Inputs
//
//   - a: the anchor
//   - entries: the chain, ascending
//   - expect: as for BindAnchor
//   - src: key source; nil is an error
//
// # Outputs
//
//   - BindResult: SignatureVerified and Trust set when the signature verifies;
//     Outcome BindSignatureInvalid, nothing bound, when it does not
//   - error: binding errors, no key source, or anchor.ErrUnknownKeyID /
//     ErrInvalidSignature / ErrVerificationUnsupported
//
// # Example
//
//	res, err := verify.VerifyAnchor(a, entries, prev.ChainHash, ring)
//	if err != nil { return err }
//	fmt.Printf("%s — %s\n", res.Outcome, res.Trust.Establishes())
//
// # Limitations
//
//   - v5 is withdrawn and refused by name; see anchor.WithdrawnVersion
//   - Says nothing about anchor provenance (see above)
//   - The anchor is checked against the chain AS IT WAS WHEN SIGNED: entries must
//     end at the anchor's last entry. With several checkpoints, pass each one
//     entries[:a.EntryCount], not the whole current chain — entries added after
//     the anchor make it fail with "committed last entry is not this chain's
//     last entry", which is correct, not a break.
//
// # Assumptions
//
//   - src is safe for concurrent use
func VerifyAnchor(a anchor.Anchor, entries []Entry, expect Expect, src anchor.KeySource) (BindResult, error) {
	if src == nil {
		return BindResult{}, errNoKeySource
	}
	res, err := BindAnchor(a, entries, expect)
	if err != nil {
		return res, err
	}
	return withSignature(res, a, src)
}

// withSignature adds the signature check to a bind result. Shared by
// VerifyAnchor and Walker.VerifyAnchor.
func withSignature(res BindResult, a anchor.Anchor, src anchor.KeySource) (BindResult, error) {
	// Verify the signature even when the bind failed: "the anchor is genuine but
	// describes a different chain" and "the anchor is forged" are different
	// situations and the caller needs to tell them apart.
	trust, verr := anchor.VerifySignature(a, src)
	if verr != nil {
		// Nothing is reported as bound or proven beside a signature error: a
		// caller that reads the result and drops the error must not find
		// Bound=true in it. What the bind found is kept, in words.
		matched := "the chain did not match it either (" + string(res.Outcome) + ")"
		if res.Bound {
			matched = "the chain does match what it describes"
		}
		return BindResult{
			Outcome:        BindSignatureInvalid,
			Detail:         "the anchor's signature did not verify; " + matched,
			EntriesCovered: res.EntriesCovered,
			Proven:         "nothing: the anchor's signature did not verify",
			NotProven:      "that the anchor is genuine, or that the chain is the one a genuine anchor committed to",
		}, verr
	}

	res.SignatureVerified = true
	res.Trust = trust
	if res.Bound {
		res.Proven = "the chain matches this anchor, and " + trust.Establishes()
		res.NotProven = "that this is the whole chain beyond the anchored range, or that " +
			"the anchor reached you by a path its subject could not rewrite"
		if res.Tombstones > 0 {
			res.Proven = boundAfterTombstone(res.EntriesNotBound, res.EntriesCovered) +
				", and " + trust.Establishes()
			res.NotProven = notBoundBeforeTombstone(res.EntriesNotBound) + "; or " + res.NotProven
		}
		if !res.SubjectChecked {
			res.NotProven += "; " + subjectNotChecked
		}
	}
	return res, nil
}

// boundAfterTombstone and notBoundBeforeTombstone word a bind over a chain that
// holds an erased entry. notBound is how many leading entries the anchor does
// not bind (through the last tombstone); count is the chain's length.
func boundAfterTombstone(notBound, count int64) string {
	if notBound >= count {
		return "the chain ends in an erased entry whose stored chain hash is the head this " +
			"anchor committed to; no entry's content is bound by it"
	}
	return fmt.Sprintf("entries %d to %d, the ones after the last erased entry, are the ones "+
		"this anchor committed to", notBound, count-1)
}

func notBoundBeforeTombstone(notBound int64) string {
	return fmt.Sprintf("that the first %d entries, up to and including the last erased one, "+
		"are the ones the anchor was signed over: an erased entry's chain hash is taken as "+
		"stored, so whoever can write the store can replace everything before it", notBound)
}

// validatePreviousAnchorHash checks the shape of a caller-supplied predecessor hash.
//
// # Description
//
// Shape only: 128 lowercase hex characters, which [anchor.SeedAnchorHash] also
// satisfies. It exists so that a wrong ARGUMENT is reported as a wrong argument
// rather than as a broken chain — the two call for completely different
// responses and the distinction is invisible once it reaches BindHeadMismatch.
//
// # Inputs
//
//   - previousAnchorHash: the value to check
//
// # Outputs
//
//   - error: nil, or a description of what is wrong with it
//
// # Example
//
//	if err := validatePreviousAnchorHash(prev); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Shape only. It cannot know whether this is the RIGHT predecessor.
//
// # Assumptions
//
//   - Anchor chain hashes are SHA-512, rendered lowercase hex.
func validateExpect(a anchor.Anchor, expect Expect) error {
	if a.Version == anchor.SequenceRangeVersion && expect.PreviousAnchorHash == "" {
		return nil // optional for v7, which signs its own
	}
	return validatePreviousAnchorHash(expect.PreviousAnchorHash)
}

func validatePreviousAnchorHash(previousAnchorHash string) error {
	if previousAnchorHash == "" {
		return fmt.Errorf("verify: previousAnchorHash is required; pass "+
			"anchor.SeedAnchorHash (%s…) for a genesis anchor", anchor.SeedAnchorHash[:16])
	}
	if len(previousAnchorHash) != 128 {
		return fmt.Errorf("verify: previousAnchorHash must be 128 lowercase hex chars "+
			"(SHA-512), got %d", len(previousAnchorHash))
	}
	for i := 0; i < len(previousAnchorHash); i++ {
		c := previousAnchorHash[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("verify: previousAnchorHash contains non-lowercase-hex characters")
		}
	}
	return nil
}

// VerifyAnchor binds an anchor to exactly the entries this walker has seen, and
// verifies its signature: the same checks as the package-level VerifyAnchor over
// those entries, without holding them.
//
// # Description
//
// Feed entries with Add until Count equals a.EntryCount, then call this. That
// is how a series of checkpoints over one chain is verified in a single pass:
// each is bound as the walk reaches the end of the prefix it covers. The head is
// the walker's own, never one a caller supplies.
//
// # Inputs
//
//   - a: the anchor; it must end at the last entry walked (v7: end_seq is the
//     last entry's global_seq; v1 to v6: it covers exactly Count() entries)
//   - expect: what the caller expects; see [Expect]
//   - src: key source; must not be nil
//
// # Outputs
//
//   - BindResult: as VerifyAnchor's. Count() != a.EntryCount is
//     BindHeightMismatch; any break so far is BindChainBroken.
//   - error: as VerifyAnchor's
//
// # Example
//
//	w := verify.NewWalker(verify.Options{})
//	prev := anchor.SeedAnchorHash
//	for _, e := range entries {          // or a page at a time from a store
//	    w.Add(e)
//	    for next < len(series) && int64(w.Count()) == series[next].EntryCount {
//	        res, err := w.VerifyAnchor(series[next], verify.Expect{Subject: s, PreviousAnchorHash: prev}, keys)
//	        // …
//	        prev = series[next].ChainHash
//	        next++
//	    }
//	}
//
// # Limitations
//
//   - As [BindAnchor]'s: both bind through the same walk.
func (w *Walker) VerifyAnchor(a anchor.Anchor, expect Expect, src anchor.KeySource) (BindResult, error) {
	if w.Count() == 0 {
		return BindResult{}, ErrNoEntries
	}
	if src == nil {
		return BindResult{}, errNoKeySource
	}
	if err := validateExpect(a, expect); err != nil {
		return BindResult{}, err
	}
	if err := anchor.ValidateVersionInvariants(a); err != nil {
		return BindResult{}, fmt.Errorf("verify: malformed anchor: %w", err)
	}
	res, err := w.bind(a, expect)
	if err != nil {
		return res, err
	}
	return withSignature(res, a, src)
}
