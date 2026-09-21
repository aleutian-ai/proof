// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// ChainDomainV2 is the SHA-512 domain separator for the anchor-of-anchors chain.
//
// Distinct from the per-entry domain ("aleutian.chain.v2:") on purpose: an
// anchor hash and an entry hash must never be interchangeable, or an anchor
// could be presented as an entry link.
const ChainDomainV2 = "aleutian.anchor.v2:"

// SeedAnchorHash is the genesis previous-hash for the first anchor in a chain.
// It is SHA-512("aleutian.anchor.seed.v2").
const SeedAnchorHash = "03443d96d3b369839f63f98b712463efba04c00551822743108d60c5f291627859ff0b7dc29f99e3c847b07b0b18bb385426c744847c1b070563f8dd07271f27"

// SeedAnchorID is the sentinel PreviousAnchorID marking a genesis anchor.
const SeedAnchorID = "anchor_00000000-0000-0000-0000-000000000000"

var (
	// hash128Re matches a SHA-512 digest in lowercase hex.
	hash128Re = regexp.MustCompile(`^[0-9a-f]{128}$`)

	// entryIDRe matches an entry id as minted by the producer: a bare UUID, or
	// a tombstone's "tomb_" + UUID.
	entryIDRe = regexp.MustCompile(
		`^(tomb_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	// companyIDRe matches the canonical tenant id: "comp_" + 26-char ULID
	// (Crockford base32, uppercase).
	companyIDRe = regexp.MustCompile(`^comp_[0-9A-HJKMNP-TV-Z]{26}$`)
)

// chainHashFields names the five inputs in preimage order, for error reporting.
var chainHashFields = [5]string{
	"previousAnchorHash", "companyID", "startEntryID", "endEntryID", "tipChainHash",
}

// ValidateChainHashDelimiters rejects a '|' in any ChainHash input.
//
// # Description
//
// The preimage is '|'-delimited and NOT self-delimiting. Three of the five
// fields — companyID, startEntryID, endEntryID — are adjacent and
// variable-length, so a '|' inside any of them shifts a field boundary without
// changing the preimage. Two different tuples then produce the same digest:
//
//	start="entry_aaa|entry_bbb" end="entry_ccc"           ─┐ identical
//	start="entry_aaa"           end="entry_bbb|entry_ccc"  ─┘ SHA-512
//
// Two results worth stating because both are easy to get backwards:
//
//  1. Validating companyID does NOT close this. The collision above uses a
//     well-formed company id; the ambiguity is between the two entry IDs.
//  2. Banning '|' is NECESSARY AND SUFFICIENT. With no pipe in any field,
//     splitting the preimage on '|' recovers the tuple uniquely, so the encoding
//     is injective.
//
// # Why this is separate from ValidateChainHashInputs
//
// This is the VERIFICATION-side guard, and it is deliberately weaker. A verifier
// examines anchors signed long ago; applying strict shape validation to those
// would flip historical anchors from passing to broken — reporting a valid chain
// as invalid. Pipe rejection cannot do that, because no UUID and no canonical
// company id can contain a pipe.
//
// # Inputs
//
//   - previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash:
//     the five ChainHash inputs, in preimage order
//
// # Outputs
//
//   - error: non-nil naming the offending FIELD, never echoing its value
//
// # Example
//
//	if err := anchor.ValidateChainHashDelimiters(prev, cid, s, e, tip); err != nil {
//	    return fmt.Errorf("ambiguous anchor preimage: %w", err)
//	}
//
// # Limitations
//
//   - Delimiters only; says nothing about field shape
//
// # Assumptions
//
//   - The caller fails closed on a non-nil error
func ValidateChainHashDelimiters(
	previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash string,
) error {
	values := [5]string{previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash}
	for i, v := range values {
		if strings.ContainsRune(v, '|') {
			// Never echo the value: an error that repeats attacker-supplied
			// content back is a confirmation oracle. The field name is enough.
			return fmt.Errorf("anchor chain hash: %s must not contain '|'", chainHashFields[i])
		}
	}
	return nil
}

// ValidateChainHashInputs fully validates the shape of every ChainHash input.
//
// # Description
//
// The PRODUCER-side guard, for callers minting a new anchor over inputs they
// control. Strictly stronger than ValidateChainHashDelimiters: every accepted
// shape is pipe-free by construction.
//
// Verifiers should NOT use this — see ValidateChainHashDelimiters for why.
//
// # Inputs
//
//   - previousAnchorHash: 128 lowercase hex (SeedAnchorHash qualifies)
//   - companyID: "comp_" + 26-char ULID
//   - startEntryID, endEntryID: UUID, or "tomb_" + UUID
//   - tipChainHash: 128 lowercase hex
//
// # Outputs
//
//   - error: non-nil naming the first failing field, without echoing its value
//
// # Example
//
//	if err := anchor.ValidateChainHashInputs(prev, cid, s, e, tip); err != nil {
//	    return fmt.Errorf("refusing to anchor: %w", err)
//	}
//
// # Limitations
//
//   - Shape only; does not check that the entries exist or the hashes are correct
//
// # Assumptions
//
//   - Entry IDs are producer-minted UUIDs
func ValidateChainHashInputs(
	previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash string,
) error {
	if !hash128Re.MatchString(previousAnchorHash) {
		return fmt.Errorf("anchor chain hash: previousAnchorHash must be 128 lowercase hex chars")
	}
	if !hash128Re.MatchString(tipChainHash) {
		return fmt.Errorf("anchor chain hash: tipChainHash must be 128 lowercase hex chars")
	}
	if !companyIDRe.MatchString(companyID) {
		return fmt.Errorf("anchor chain hash: companyID must be \"comp_\" + 26-char ULID")
	}
	if !entryIDRe.MatchString(startEntryID) {
		return fmt.Errorf("anchor chain hash: startEntryID must be a UUID or \"tomb_\" + UUID")
	}
	if !entryIDRe.MatchString(endEntryID) {
		return fmt.Errorf("anchor chain hash: endEntryID must be a UUID or \"tomb_\" + UUID")
	}
	return nil
}

// ChainHash computes the anchor-of-anchors digest, validating its inputs first.
//
// # Description
//
// Binds an anchor BACKWARDS to the previous anchor and DOWNWARDS to a specific
// entry-chain head:
//
//	SHA-512( "aleutian.anchor.v2:"
//	         ‖ previousAnchorHash ‖ "|" ‖ companyID    ‖ "|"
//	         ‖ startEntryID       ‖ "|" ‖ endEntryID   ‖ "|"
//	         ‖ tipChainHash )
//
// This is NOT the tip entry's chain hash. Verifiers must recompute and compare,
// never byte-compare against the tip.
//
// Validation is on by default because the preimage is not self-delimiting (see
// ValidateChainHashDelimiters). A producer that controls its own inputs is safe
// by provenance; a library is handed whatever the caller has.
//
// # Inputs
//
//   - previousAnchorHash: prior anchor's chain hash, or SeedAnchorHash for genesis
//   - companyID: the anchor's tenant
//   - startEntryID, endEntryID: the anchor's inclusive range bounds
//   - tipChainHash: the entry chain's hash at endEntryID, as RECOMPUTED by
//     walking the chain — not the stored value, when verifying untrusted data
//
// # Outputs
//
//   - string: 128-char lowercase hex SHA-512
//   - error: if any input contains '|'
//
// # Example
//
//	h, err := anchor.ChainHash(prevHash, companyID, startID, endID, walkedHead)
//	if err != nil {
//	    return err
//	}
//	if h != a.ChainHash { /* the anchor does not describe this chain */ }
//
// # Limitations
//
//   - Applies the delimiter guard, not full shape validation, so it is safe for
//     historical anchors. Producers should additionally call
//     ValidateChainHashInputs.
//
// # Assumptions
//
//   - All inputs are valid UTF-8
func ChainHash(
	previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash string,
) (string, error) {
	if err := ValidateChainHashDelimiters(
		previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash); err != nil {
		return "", err
	}
	return ChainHashUnchecked(
		previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash), nil
}

// ChainHashUnchecked computes the digest with NO validation.
//
// # Description
//
// The raw primitive. Use it only to reproduce a historical digest whose inputs
// you already know to be well-formed, or in a benchmark. For anything that
// decides whether a chain is intact, use ChainHash.
//
// # Inputs
//
//   - Same as ChainHash
//
// # Outputs
//
//   - string: 128-char lowercase hex SHA-512
//
// # Example
//
//	h := anchor.ChainHashUnchecked(prev, cid, start, end, tip)
//
// # Limitations
//
//   - A '|' in any input makes the result AMBIGUOUS: a different tuple can
//     produce the same digest. That is the whole reason ChainHash exists.
//
// # Assumptions
//
//   - The caller has already established that the inputs are pipe-free
func ChainHashUnchecked(
	previousAnchorHash, companyID, startEntryID, endEntryID, tipChainHash string,
) string {
	h := sha512.New()
	h.Write([]byte(ChainDomainV2))
	h.Write([]byte(previousAnchorHash))
	h.Write([]byte("|"))
	h.Write([]byte(companyID))
	h.Write([]byte("|"))
	h.Write([]byte(startEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(endEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(tipChainHash))
	return hex.EncodeToString(h.Sum(nil))
}
