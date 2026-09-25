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
// Recomputes the chain's head from the entries, then recomputes the anchor's own
// chain hash from what it committed to, and compares. It answers "is the chain
// in front of me the one this anchor described", and deliberately not "is this
// anchor genuine" — that needs a key, and is [VerifyAnchor].
//
// # previousAnchorHash is not optional, on purpose
//
// The predecessor's hash is INSIDE the anchor's own chain hash, so a verifier
// that assumes it cannot check any anchor but the first:
//
//	first anchor      previousAnchorHash = anchor.SeedAnchorHash
//	every one after   previousAnchorHash = the previous anchor's ChainHash
//
// An anchor names its predecessor by id (PreviousAnchorID), never by hash, so
// the hash cannot be recovered from the anchor alone — the caller must hold the
// previous anchor or a record of its chain hash. That is inherent to the format.
//
// This argument was once defaulted to the seed sentinel, which made the function
// silently genesis-only: a correct chained anchor came back as BindHeadMismatch,
// reading as tamper evidence. Passing it explicitly costs a caller one named
// constant and removes a default that was wrong for every anchor but the first.
//
// # Inputs
//
//   - a: the anchor to bind against
//   - entries: the chain, in ascending sequence order
//   - previousAnchorHash: the predecessor's ChainHash, or [anchor.SeedAnchorHash]
//     for a genesis anchor. Validated, not trusted.
//
// # Outputs
//
//   - BindResult: outcome plus the explicit proven / not-proven claim
//   - error: ErrNoEntries, a malformed anchor, or a malformed previousAnchorHash
//
// # Example
//
//	res, err := verify.BindAnchor(a, entries, prev.ChainHash)
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
//     that the predecessor is genuine, or that PreviousAnchorID names it — walk
//     the anchor chain to its genesis for that.
//
// # Assumptions
//
//   - entries are ordered ascending by sequence, as exported
func BindAnchor(a anchor.Anchor, entries []Entry, previousAnchorHash string) (BindResult, error) {
	if len(entries) == 0 {
		return BindResult{}, ErrNoEntries
	}
	// Validated up front, and as an ERROR rather than a mismatch. A malformed
	// previous hash would otherwise recompute to something that simply does not
	// match, and get reported as BindHeadMismatch — telling the caller their
	// chain was tampered with when in fact their argument was wrong.
	if err := validatePreviousAnchorHash(previousAnchorHash); err != nil {
		return BindResult{}, err
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
		previousAnchorHash, a.Subject, a.Range.StartEntryID, a.Range.EndEntryID, head)
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
func VerifyAnchor(a anchor.Anchor, entries []Entry, previousAnchorHash string, src anchor.KeySource) (BindResult, error) {
	res, err := BindAnchor(a, entries, previousAnchorHash)
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
		want, herr := expectedChainHash(e, previousHash, ts)
		if herr != nil {
			// An entry this build cannot recompute is not evidence of tampering,
			// and must not be reported as a break. Say what it actually is.
			return "", i, fmt.Errorf("verify: entry %d: %w", i, herr)
		}
		if want != e.ChainHash {
			return "", i, nil
		}
		previousHash = want
	}
	return previousHash, -1, nil
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

// expectedChainHash recomputes an entry's chain hash under the format it declares.
//
// # Description
//
// The single dispatch shared by [Chain] and [walkForHead]. It exists because
// those two paths once disagreed: `_40` taught Chain about v3 and left the
// anchor binder recomputing every entry as v2, so from the moment v3 became the
// default, binding a new chain to its anchor reported "linkage breaks at entry
// 0" — a correct chain accused of tampering.
//
// Two verifiers in one package that answer differently is not a bug to fix once;
// it is a bug to make impossible.
//
// # Inputs
//
//   - e: the entry to recompute
//   - previousHash: the preceding entry's chain hash, empty for the first
//   - ts: e.Timestamp already parsed
//
// # Outputs
//
//   - string: the hash this entry should carry
//   - error: if the entry declares a format this build does not implement, or
//     misuses a field its format does not bind
//
// # Example
//
//	want, err := expectedChainHash(e, previousHash, ts)
//
// # Limitations
//
//   - Recomputes. It does not compare; callers decide what a mismatch means.
//
// # Assumptions
//
//   - Tombstones are handled by the caller: their chain hash is retained from
//     the original entry and cannot be recomputed from their own fields.
func expectedChainHash(e Entry, previousHash string, ts time.Time) (string, error) {
	switch chainformat.NormalizeFormatVersion(e.FormatVersion) {
	case chainformat.FormatV2:
		return chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, ts, e.ContentHash), nil
	case chainformat.FormatV3:
		if e.RunID != "" || e.SequenceNum != 0 {
			// v3 binds neither field. Carrying them anyway invites a reader to
			// treat them as attested when they are free to change.
			return "", fmt.Errorf("a v3 entry must not carry run_id or sequence_num; " +
				"neither is bound into its hash")
		}
		return chainformat.ComputeChainHashV3Unchecked(
			previousHash, e.GlobalSeq, ts, e.ContentHash), nil
	default:
		return "", fmt.Errorf("chain hash format version %d is not implemented by this build",
			e.FormatVersion)
	}
}
