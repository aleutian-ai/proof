// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"encoding/json"
	"fmt"
)

// legacySubjectKey is the JSON key this field carried before 2026-09-23.
//
// The field was named for a private platform's tenant identity. The name is
// gone from the API; the KEY is still read, because files and fixtures written
// under it exist and refusing them would break chains that are perfectly
// valid — the canonical bytes never contained the key name at all.
const legacySubjectKey = "company_id"

// UnmarshalJSON decodes a leaf, accepting either "subject" or the legacy
// "company_id" key.
//
// # Description
//
// The rename changed no hashed bytes: [CanonicalV3] appends VALUES
// positionally and never writes a field name. So a file written with the old
// key describes exactly the same entry, and reading it must produce exactly
// the same content hash. That is what this method preserves.
//
// # Inputs
//
//   - data: the JSON encoding of one leaf
//
// # Outputs
//
//   - error: if the JSON is malformed, or if both keys are present with
//     DIFFERENT values — which is not a file this package can interpret
//
// # Example
//
//	var e chainformat.CaptureRequestV3
//	err := json.Unmarshal(data, &e) // "subject" or "company_id"
//
// # Limitations
//
//   - Validates nothing beyond the key conflict; use [CanonicalV3] or
//     [EncodeAndHashV3] for the field rules.
//   - Marshalling always emits "subject". A consumer that requires the old key
//     must map it itself.
//
// # Assumptions
//
//   - An entry has ONE subject. Two different values under two spellings is a
//     corrupt or hand-edited file, not a case to resolve by precedence.
func (e *CaptureRequestV3) UnmarshalJSON(data []byte) error {
	// An alias type, so this method is not called recursively by the decoder.
	type leafAlias CaptureRequestV3
	var alias leafAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	var legacy struct {
		CompanyID *string `json:"company_id"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	if legacy.CompanyID != nil {
		switch {
		case alias.Subject == "":
			alias.Subject = *legacy.CompanyID
		case alias.Subject != *legacy.CompanyID:
			// Silently preferring one would produce a leaf whose content hash
			// matches neither of the two readings the file admits.
			return fmt.Errorf("chainformat: %w: the entry carries both \"subject\" (%q) and %q (%q) with different values",
				ErrInvalidEntryV3, alias.Subject, legacySubjectKey, *legacy.CompanyID)
		}
	}

	*e = CaptureRequestV3(alias)
	return nil
}
