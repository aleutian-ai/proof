// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
)

// BindOutcome is why an anchor did or did not describe a chain.
type BindOutcome string

const (
	// BindOK: the chain is exactly what the anchor committed to.
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
)

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

	// Trust is what a verified signature established, empty for a keyless bind.
	Trust anchor.Trust `json:"trust,omitempty"`

	// SignatureVerified distinguishes a keyless bind from a full verification.
	// A keyless bind proves the chain matches the anchor; it proves NOTHING
	// about where the anchor came from.
	SignatureVerified bool `json:"signature_verified"`

	// Proven and NotProven state the claim in plain language. They are part of
	// the payload, not the docs, because a caller relaying this result must have
	// to actively discard the caveat rather than remember to add it.
	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

// BindAnchor checks a chain against an anchor WITHOUT verifying the signature.
//
// # Description
//
// Recomputes the chain, then checks that the anchor's committed range, height
// and head still describe it. Needs no key, no trust store and no network —
// which is exactly why it is useful, and exactly why it proves less than it
// appears to.
//
// **What this catches that linkage alone cannot:** truncation. A chain with
// entries removed from the front and the remainder re-linked walks perfectly
// clean; only the anchor's committed range start reveals it.
//
// **What this does NOT establish:** that the anchor is genuine. An adversary who
// can rewrite the chain can also mint a matching unsigned anchor. Use
// VerifyAnchor when you have a key, and read the result's Trust field.
//
// # Inputs
//
//   - a: the anchor to bind against
//   - entries: the chain, in ascending sequence order
//
// # Outputs
//
//   - BindResult: outcome plus the explicit proven / not-proven claim
//   - error: ErrNoEntries, or a malformed anchor
//
// # Example
//
//	res, err := verify.BindAnchor(a, entries)
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
//
// # Assumptions
//
//   - entries are ordered ascending by sequence, as exported
func BindAnchor(a anchor.Anchor, entries []Entry) (BindResult, error) {
	if len(entries) == 0 {
		return BindResult{}, ErrNoEntries
	}
	if err := anchor.ValidateVersionInvariants(a); err != nil {
		return BindResult{}, fmt.Errorf("verify: malformed anchor: %w", err)
	}

	res := BindResult{
		EntriesCovered: a.EntryCount,
		Proven:         "the chain in front of you is the one this anchor committed to",
		NotProven: "that the anchor is genuine — no signature was checked, so an " +
			"adversary able to rewrite the chain could also have minted this anchor",
	}

	head, brk, err := walkForHead(entries)
	if err != nil {
		return BindResult{}, err
	}
	if brk >= 0 {
		res.Outcome, res.Detail = BindChainBroken, fmt.Sprintf("linkage breaks at entry %d", brk)
		return res, nil
	}

	if entries[0].EntryID != a.Range.StartEntryID {
		res.Outcome = BindRangeStartMismatch
		res.Detail = "the anchor's committed first entry is not this chain's first entry; " +
			"entries were removed from the front"
		return res, nil
	}
	if entries[len(entries)-1].EntryID != a.Range.EndEntryID {
		res.Outcome = BindRangeEndMismatch
		res.Detail = "the anchor's committed last entry is not this chain's last entry"
		return res, nil
	}
	if int64(len(entries)) != a.EntryCount {
		res.Outcome = BindHeightMismatch
		res.Detail = fmt.Sprintf("chain has %d entries; the anchor committed to %d",
			len(entries), a.EntryCount)
		return res, nil
	}

	// Recompute the anchor's own chain hash from what it committed to.
	//
	// Delimiter guard only, never strict shape validation: this path evaluates
	// anchors signed long ago, and tightening it would flip historical anchors
	// from passing to broken.
	recomputed, err := anchor.ChainHash(
		anchor.SeedAnchorHash, a.CompanyID, a.Range.StartEntryID, a.Range.EndEntryID, head)
	if err != nil {
		return BindResult{}, fmt.Errorf("verify: %w", err)
	}
	if recomputed != a.ChainHash {
		res.Outcome = BindHeadMismatch
		res.Detail = "the recomputed head does not match the head the anchor bound"
		return res, nil
	}

	res.Outcome, res.Bound = BindOK, true
	return res, nil
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
//   - src: key source; must not be nil
//
// # Outputs
//
//   - BindResult: with SignatureVerified set and Trust populated
//   - error: binding errors, or anchor.ErrUnknownKeyID / ErrInvalidSignature /
//     ErrVerificationUnsupported
//
// # Example
//
//	res, err := verify.VerifyAnchor(a, entries, ring)
//	if err != nil { return err }
//	fmt.Printf("%s — %s\n", res.Outcome, res.Trust.Establishes())
//
// # Limitations
//
//   - v5 anchors are refused: canonicalizable, but no cross-language vectors exist
//   - Says nothing about anchor provenance (see above)
//
// # Assumptions
//
//   - src is safe for concurrent use
func VerifyAnchor(a anchor.Anchor, entries []Entry, src anchor.KeySource) (BindResult, error) {
	res, err := BindAnchor(a, entries)
	if err != nil {
		return res, err
	}

	// Verify the signature even when the bind failed: "the anchor is genuine but
	// describes a different chain" and "the anchor is forged" are different
	// situations and the caller needs to tell them apart.
	trust, verr := anchor.VerifySignature(a, src)
	if verr != nil {
		return res, verr
	}

	res.SignatureVerified = true
	res.Trust = trust
	if res.Bound {
		res.Proven = "the chain matches this anchor, and " + trust.Establishes()
		res.NotProven = "that this is the whole chain beyond the anchored range, or that " +
			"the anchor reached you by a path its subject could not rewrite"
	}
	return res, nil
}

// walkForHead re-derives every chain hash and returns the head, or the index of
// the first break.
//
// A TOMBSTONE IS NOT RECOMPUTED. Its content hash is random, so nothing can
// derive it, and its chain hash is deliberately the original — the value anchors
// were signed over. A walker that recomputes tombstones reports a lawfully
// erased chain as tampered, which is the bug that shipped in three SDKs.
func walkForHead(entries []Entry) (head string, firstBreak int, err error) {
	previousHash := ""
	for i, e := range entries {
		if chainformat.IsTombstoneContentHash(e.ContentHash) {
			previousHash = e.ChainHash // erasure is not tampering
			continue
		}
		ts, perr := time.Parse(time.RFC3339Nano, e.Timestamp)
		if perr != nil {
			// Do not echo the value; report the position and the expected shape.
			return "", i, fmt.Errorf("verify: entry %d: timestamp is not RFC3339", i)
		}
		want := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, ts, e.ContentHash)
		if want != e.ChainHash {
			return "", i, nil
		}
		previousHash = want
	}
	return previousHash, -1, nil
}
