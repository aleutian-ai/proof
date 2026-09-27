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

	// MaxVersion is the newest canonical form implemented.
	MaxVersion = 6

	// WithdrawnVersion is version 5, which is BURNED: it is inside
	// [MinVersion, MaxVersion] but no canonical form exists for it and none will
	// be added. The number is never reused.
	//
	// v5 was designed to commit to a Merkle root. It was given a canonical form
	// and a validation rule, and then refused by this package's own verifier,
	// because committing to a root that no implementation can check asserts a
	// guarantee nobody can test. No producer ever emitted one, and no SDK ever
	// implemented one — Python and JS went straight from v4 to v6.
	//
	// Keeping the number reserved rather than renumbering v6 down to 5 costs one
	// gap in a sequence and buys certainty: any artifact anywhere declaring v5 is
	// refused by name, and cannot be silently reinterpreted as something else.
	//
	// The former name, MerkleVersion, read as a FLOOR and was twice written as
	// ">= MerkleVersion" — which refused v6 and every version after it. The name
	// went with the capability.
	WithdrawnVersion = 5

	// SubjectVersion is the version at which company_id became subject.
	//
	// The rename changed a KEY inside the signed bytes — unlike the leaf, where
	// the canonical form carries values only — so it needed a version of its
	// own rather than being a refactor.
	SubjectVersion = 6
)

// errWithdrawn names v5 as withdrawn rather than unsupported.
//
// The default branch's wording — "unsupported version 5 (implemented: 1..6)" —
// reads as a contradiction, because 5 IS inside that range. Whoever holds an
// artifact declaring v5 should be told the version was withdrawn, not left to
// conclude their build is too old to read it.
// It wraps ErrVerificationUnsupported so callers that already branch on that
// sentinel keep working; v5 was previously refused with it at two later points.
func errWithdrawn() error {
	return fmt.Errorf("%w: v%d was withdrawn and has no canonical form — it "+
		"committed to a Merkle root that no implementation can verify. No producer "+
		"ever emitted one; the version number is reserved and will not be reused",
		ErrVerificationUnsupported, WithdrawnVersion)
}

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

// canonicalV6 is v4's layout with company_id renamed to subject.
//
// Alphabetical, as every version is: "signing_key_id" < "subject" (i < u at
// index 1) < "verified_through" < "version" (i < s at index 3). The renamed
// field MOVES as a result — it sorted third as company_id and sorts eighth as
// subject — which is precisely why this is a new version and not an edit.
//
// Built on v4, NOT on the withdrawn v5, which committed to a Merkle root no
// implementation could check.
type canonicalV6 struct {
	AnchorID         string         `json:"anchor_id"`
	ChainHash        string         `json:"chain_hash"`
	CreatedAtMs      int64          `json:"created_at_ms"`
	EntryCount       int64          `json:"entry_count"`
	PreviousAnchorID string         `json:"previous_anchor_id"`
	Range            canonicalRange `json:"range"`
	SigningKeyID     string         `json:"signing_key_id"`
	Subject          string         `json:"subject"`
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
//	5        →  WITHDRAWN. Refused by name; see WithdrawnVersion
//	6        →  10 fields, v4's layout with company_id renamed to subject
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
			CompanyID:        a.Subject,
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
			CompanyID:        a.Subject,
			CreatedAtMs:      a.CreatedAtMs,
			EntryCount:       a.EntryCount,
			PreviousAnchorID: a.PreviousAnchorID,
			Range:            r,
			SigningKeyID:     a.SigningKeyID,
			VerifiedThrough:  a.VerifiedThrough,
			Version:          a.Version,
		})

	case a.Version == WithdrawnVersion:
		// Refused HERE, at canonicalization, rather than later at signature
		// verification. There are no bytes to return: producing canonical bytes
		// for v5 would let a caller sign one.
		return nil, errWithdrawn()

	case a.Version == SubjectVersion:
		return json.Marshal(canonicalV6{
			AnchorID:         a.AnchorID,
			ChainHash:        a.ChainHash,
			CreatedAtMs:      a.CreatedAtMs,
			EntryCount:       a.EntryCount,
			PreviousAnchorID: a.PreviousAnchorID,
			Range:            r,
			SigningKeyID:     a.SigningKeyID,
			Subject:          a.Subject,
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
//   - v5 is refused outright; see WithdrawnVersion
//   - v6 must have verified_through > 0 and a non-empty subject
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
	case a.Version == WithdrawnVersion:
		return errWithdrawn()
	case a.Version == SubjectVersion:
		if a.VerifiedThrough <= 0 {
			return fmt.Errorf("anchor: v%d must declare a positive verified_through", SubjectVersion)
		}
		// The subject is in the signed bytes so an anchor cannot be replayed
		// onto another chain. An empty one removes that protection, so v6 makes
		// non-empty an invariant — which v3..v5 never did for company_id.
		if a.Subject == "" {
			return fmt.Errorf("anchor: v%d must declare a non-empty subject", SubjectVersion)
		}
	default:
		return fmt.Errorf("anchor: unsupported version %d (implemented: %d..%d)",
			a.Version, MinVersion, MaxVersion)
	}
	return nil
}
