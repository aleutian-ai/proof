// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/json"
	"fmt"
)

// legacySubjectKey is the wire key v3, v4 and v5 use for the subject.
const legacySubjectKey = "company_id"

// subjectKey is the wire key v6 uses.
const subjectKey = "subject"

// anchorWire is the Anchor's JSON shape with the subject left out, so the
// subject key can be chosen by version. Every other field is tagged on Anchor
// itself and marshals normally.
type anchorWire Anchor

// MarshalJSON writes the anchor, spelling the subject the way its version does.
//
// # Description
//
// v3–v5 carry "company_id" and v6 carries "subject". The key is part of the
// signed bytes for the version that declares it, so re-serializing an old
// anchor under the new key would produce a file no existing verifier — or SDK —
// could check. The version decides; the struct field name does not.
//
// # Inputs
//
//   - none beyond the receiver
//
// # Outputs
//
//   - []byte: the JSON encoding
//   - error: if the anchor cannot be encoded
//
// # Example
//
//	raw, err := json.Marshal(a) // "company_id" for v4, "subject" for v6
//
// # Limitations
//
//   - Marshalling does NOT validate the version. An anchor with an unknown
//     version is written with the legacy key, because that is what every
//     version below v6 used; [ValidateVersionInvariants] is where an unknown
//     version is refused.
//
// # Assumptions
//
//   - An anchor has exactly one subject.
func (a Anchor) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(anchorWire(a))
	if err != nil {
		return nil, fmt.Errorf("anchor: encode: %w", err)
	}

	key := legacySubjectKey
	if a.Version >= SubjectVersion {
		key = subjectKey
	}
	subject, err := json.Marshal(a.Subject)
	if err != nil {
		return nil, fmt.Errorf("anchor: encode subject: %w", err)
	}

	// Splice the subject in after the opening brace. Key ORDER does not matter
	// here: this is the transport shape, and what gets signed is produced by
	// Canonicalize, which sorts.
	out := make([]byte, 0, len(raw)+len(subject)+len(key)+4)
	out = append(out, '{')
	out = append(out, '"')
	out = append(out, key...)
	out = append(out, '"', ':')
	out = append(out, subject...)
	if len(raw) > 2 {
		out = append(out, ',')
		out = append(out, raw[1:]...)
	} else {
		out = append(out, '}')
	}
	return out, nil
}

// UnmarshalJSON reads an anchor, accepting either subject spelling.
//
// # Description
//
// A reader must handle both: v3–v5 files say "company_id", v6 files say
// "subject", and both will be in circulation for as long as any v4 anchor
// exists — which is forever, since anchors are not rewritten.
//
// # Inputs
//
//   - data: the JSON encoding of one anchor
//
// # Outputs
//
//   - error: if the JSON is malformed, or if both keys are present with
//     DIFFERENT values
//
// # Example
//
//	var a anchor.Anchor
//	err := json.Unmarshal(data, &a)
//
// # Limitations
//
//   - Validates nothing else. An anchor whose version and fields contradict
//     each other still decodes; [ValidateVersionInvariants] is the check.
//
// # Assumptions
//
//   - Two different values under the two spellings is a corrupt or hand-edited
//     file, not a case to resolve by precedence: canonicalizing either reading
//     would produce bytes the signature does not cover.
func (a *Anchor) UnmarshalJSON(data []byte) error {
	var wire anchorWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	var keys struct {
		Subject   *string `json:"subject"`
		CompanyID *string `json:"company_id"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}

	switch {
	case keys.Subject != nil && keys.CompanyID != nil:
		if *keys.Subject != *keys.CompanyID {
			return fmt.Errorf("anchor: the anchor carries both %q (%q) and %q (%q) with different values",
				subjectKey, *keys.Subject, legacySubjectKey, *keys.CompanyID)
		}
		wire.Subject = *keys.Subject
	case keys.Subject != nil:
		wire.Subject = *keys.Subject
	case keys.CompanyID != nil:
		wire.Subject = *keys.CompanyID
	}

	*a = Anchor(wire)
	return nil
}
