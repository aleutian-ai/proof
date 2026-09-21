// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/json"
	"fmt"
)

// MinVersion and MaxVersion bound the canonical forms this package implements.
const (
	// MinVersion is the oldest declared version accepted. Versions 1..3 all use
	// the v3 canonical layout, matching the producer and the published SDK.
	MinVersion = 1

	// MaxVersion is the newest canonical form implemented. See Canonicalize for
	// why v5 is implemented but not yet cross-language validated.
	MaxVersion = 5

	// MerkleVersion is the version at which an anchor commits to a Merkle root.
	MerkleVersion = 5
)

// canonicalRange is the range sub-object in canonical key order.
//
// Alphabetical: end before start. Counter-intuitive, and load-bearing.
type canonicalRange struct {
	EndEntryID   string `json:"end_entry_id"`
	StartEntryID string `json:"start_entry_id"`
}

// canonicalV3 is the 9-field layout used by versions 1 through 3.
type canonicalV3 struct {
	AnchorID         string         `json:"anchor_id"`
	ChainHash        string         `json:"chain_hash"`
	CompanyID        string         `json:"company_id"`
	CreatedAtMs      int64          `json:"created_at_ms"`
	EntryCount       int64          `json:"entry_count"`
	PreviousAnchorID string         `json:"previous_anchor_id"`
	Range            canonicalRange `json:"range"`
	SigningKeyID     string         `json:"signing_key_id"`
	Version          int            `json:"version"`
}

// canonicalV4 adds verified_through, which sorts between signing_key_id and
// version (s < v, then "ver" < "verified" is false — "verified_through" sorts
// before "version" because 'i' < 's' at index 4).
type canonicalV4 struct {
	AnchorID         string         `json:"anchor_id"`
	ChainHash        string         `json:"chain_hash"`
	CompanyID        string         `json:"company_id"`
	CreatedAtMs      int64          `json:"created_at_ms"`
	EntryCount       int64          `json:"entry_count"`
	PreviousAnchorID string         `json:"previous_anchor_id"`
	Range            canonicalRange `json:"range"`
	SigningKeyID     string         `json:"signing_key_id"`
	VerifiedThrough  int64          `json:"verified_through"`
	Version          int            `json:"version"`
}

// canonicalV5 adds root_hash and tree_size. Ordering is alphabetical but not
// adjacent: root_hash sorts between range and signing_key_id (ra < ro < s),
// tree_size between signing_key_id and verified_through (s < t < v).
type canonicalV5 struct {
	AnchorID         string         `json:"anchor_id"`
	ChainHash        string         `json:"chain_hash"`
	CompanyID        string         `json:"company_id"`
	CreatedAtMs      int64          `json:"created_at_ms"`
	EntryCount       int64          `json:"entry_count"`
	PreviousAnchorID string         `json:"previous_anchor_id"`
	Range            canonicalRange `json:"range"`
	RootHash         string         `json:"root_hash"`
	SigningKeyID     string         `json:"signing_key_id"`
	TreeSize         int64          `json:"tree_size"`
	VerifiedThrough  int64          `json:"verified_through"`
	Version          int            `json:"version"`
}

// Canonicalize returns the exact bytes an anchor's signature is computed over.
//
// # Description
//
// Compact JSON with keys in strict alphabetical order (RFC 8785 / JCS
// principles) and the signature field excluded. Any language producing
// sorted-key compact JSON yields identical bytes, which is what makes an anchor
// signed in Go verifiable in Python or JavaScript.
//
// Dispatch is on the DECLARED Version and never on which fields are populated.
// Inferring the version from field presence is a downgrade oracle: a v4 anchor
// whose verified_through happens to be zero would silently canonicalize as v3,
// and an attacker able to influence a field could choose the weaker form.
// Version is inside the signed bytes, so dispatching on it is safe; dispatching
// on anything else is not.
//
// # Version support
//
//	1, 2, 3  →  9-field layout (no verified_through)
//	4        →  10 fields, adds verified_through
//	5        →  12 fields, adds root_hash and tree_size
//
// v5 is implemented from the producer's layout but has NO cross-language
// fixture, because no SDK implements v5 and no producer emits it. Its bytes are
// pinned here by a golden test so drift is detectable, but "pinned" is weaker
// than "cross-language verified" and callers should treat v5 as provisional.
//
// # Inputs
//
//   - a: the anchor to canonicalize. Signature is ignored.
//
// # Outputs
//
//   - []byte: canonical bytes, safe to sign or verify against
//   - error: if Version is outside [MinVersion, MaxVersion], or encoding fails
//
// # Example
//
//	canonical, err := anchor.Canonicalize(a)
//	if err != nil {
//	    return err
//	}
//	ok := verifySignature(pubKey, canonical, sig)
//
// # Limitations
//
//   - Does not validate field values; it renders whatever it is given
//   - An unsupported version is an ERROR, never a best guess
//
// # Assumptions
//
//   - Uses encoding/json with HTML escaping ON (the default), matching both the
//     producer and the published SDK. Disabling it would silently change the
//     bytes for any field containing <, > or &, breaking signatures.
func Canonicalize(a Anchor) ([]byte, error) {
	r := canonicalRange{
		EndEntryID:   a.Range.EndEntryID,
		StartEntryID: a.Range.StartEntryID,
	}

	switch {
	case a.Version >= MinVersion && a.Version <= 3:
		return json.Marshal(canonicalV3{
			AnchorID:         a.AnchorID,
			ChainHash:        a.ChainHash,
			CompanyID:        a.CompanyID,
			CreatedAtMs:      a.CreatedAtMs,
			EntryCount:       a.EntryCount,
			PreviousAnchorID: a.PreviousAnchorID,
			Range:            r,
			SigningKeyID:     a.SigningKeyID,
			Version:          a.Version,
		})

	case a.Version == 4:
		return json.Marshal(canonicalV4{
			AnchorID:         a.AnchorID,
			ChainHash:        a.ChainHash,
			CompanyID:        a.CompanyID,
			CreatedAtMs:      a.CreatedAtMs,
			EntryCount:       a.EntryCount,
			PreviousAnchorID: a.PreviousAnchorID,
			Range:            r,
			SigningKeyID:     a.SigningKeyID,
			VerifiedThrough:  a.VerifiedThrough,
			Version:          a.Version,
		})

	case a.Version == 5:
		return json.Marshal(canonicalV5{
			AnchorID:         a.AnchorID,
			ChainHash:        a.ChainHash,
			CompanyID:        a.CompanyID,
			CreatedAtMs:      a.CreatedAtMs,
			EntryCount:       a.EntryCount,
			PreviousAnchorID: a.PreviousAnchorID,
			Range:            r,
			RootHash:         a.RootHash,
			SigningKeyID:     a.SigningKeyID,
			TreeSize:         a.TreeSize,
			VerifiedThrough:  a.VerifiedThrough,
			Version:          a.Version,
		})

	default:
		// Never guess. A version we do not implement means we do not know which
		// bytes were signed, and canonicalizing as "the closest one we know"
		// would produce a confident wrong answer.
		return nil, fmt.Errorf("anchor: unsupported version %d (implemented: %d..%d)",
			a.Version, MinVersion, MaxVersion)
	}
}

// ValidateVersionInvariants rejects anchors whose fields contradict their
// declared version.
//
// # Description
//
// Must run BEFORE Canonicalize in any verification flow. Version lives inside
// the signed bytes, so a mismatch between the declared version and the fields
// present is a valid signature over structurally invalid content — malformed,
// not merely old.
//
// The checks:
//
//   - v<=3 must have verified_through == 0 (it predates the field)
//   - v4 must have verified_through > 0 (a v4 that claims nothing is not a v4)
//   - v5 must additionally carry a non-empty root_hash and positive tree_size
//
// # Inputs
//
//   - a: the anchor to check
//
// # Outputs
//
//   - error: non-nil describing the contradiction
//
// # Example
//
//	if err := anchor.ValidateVersionInvariants(a); err != nil {
//	    return fmt.Errorf("malformed anchor: %w", err)
//	}
//
// # Limitations
//
//   - Structural only; says nothing about whether the values are correct
//
// # Assumptions
//
//   - The caller fails closed on a non-nil error
func ValidateVersionInvariants(a Anchor) error {
	switch {
	case a.Version >= MinVersion && a.Version <= 3:
		if a.VerifiedThrough != 0 {
			return fmt.Errorf("anchor: v%d predates verified_through but declares %d",
				a.Version, a.VerifiedThrough)
		}
	case a.Version == 4:
		if a.VerifiedThrough <= 0 {
			return fmt.Errorf("anchor: v4 must declare a positive verified_through")
		}
	case a.Version == 5:
		if a.VerifiedThrough <= 0 {
			return fmt.Errorf("anchor: v5 must declare a positive verified_through")
		}
		if a.RootHash == "" {
			return fmt.Errorf("anchor: v%d commits to a Merkle root but root_hash is empty", MerkleVersion)
		}
		if a.TreeSize <= 0 {
			return fmt.Errorf("anchor: v%d must declare a positive tree_size", MerkleVersion)
		}
	default:
		return fmt.Errorf("anchor: unsupported version %d (implemented: %d..%d)",
			a.Version, MinVersion, MaxVersion)
	}
	return nil
}
