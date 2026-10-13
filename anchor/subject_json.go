// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"encoding/json"
	"errors"
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

// UnmarshalJSON reads an anchor, strictly.
//
// # Description
//
// What is parsed must be what was signed, so the parse admits nothing the
// signed bytes do not carry:
//
//   - every member name is one this version has, spelled exactly (encoding/json
//     alone matches names without regard to case);
//   - no member appears twice (encoding/json alone keeps the last);
//   - no unknown member: a field nobody reads is a field a caller can set and
//     believe was signed;
//   - the subject is under the name its version uses: "subject" from v6,
//     "company_id" before. An anchor carrying both, or the other one, is refused.
//
// # Inputs
//
//   - data: one JSON object
//
// # Outputs
//
//   - error: what was wrong, naming members and never their values
//
// # Example
//
//	var a anchor.Anchor
//	if err := json.Unmarshal(raw, &a); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Member values are decoded by encoding/json: a string holding invalid
//     UTF-8 is repaired, not refused.
//
// # Assumptions
//
//   - The caller runs ValidateVersionInvariants (every verifier here does).
func (a *Anchor) UnmarshalJSON(data []byte) error {
	names, err := objectMembers(data, anchorMembers, "the anchor")
	if err != nil {
		return err
	}
	var wire anchorWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return errors.New("anchor: a member has the wrong JSON type")
	}

	var keys struct {
		Subject   *string         `json:"subject"`
		CompanyID *string         `json:"company_id"`
		Range     json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return errors.New("anchor: a member has the wrong JSON type")
	}
	if names["range"] {
		if _, err := objectMembers(keys.Range, rangeMembers, "the anchor's range"); err != nil {
			return err
		}
	}

	want, other := legacySubjectKey, subjectKey
	if wire.Version >= SubjectVersion {
		want, other = subjectKey, legacySubjectKey
	}
	if names[other] {
		return fmt.Errorf("anchor: a v%d anchor names its subject %q, not %q", wire.Version, want, other)
	}
	switch {
	case keys.Subject != nil:
		wire.Subject = *keys.Subject
	case keys.CompanyID != nil:
		wire.Subject = *keys.CompanyID
	}

	*a = Anchor(wire)
	return nil
}

// anchorMembers and rangeMembers are every member name an anchor may carry.
var (
	anchorMembers = map[string]bool{
		subjectKey: true, legacySubjectKey: true, "version": true, "anchor_id": true,
		"chain_hash": true, "range": true, "entry_count": true, "signature": true,
		"signing_key_id": true, "created_at_ms": true, "previous_anchor_id": true,
		"verified_through": true,
	}
	rangeMembers = map[string]bool{"start_entry_id": true, "end_entry_id": true}
)

// objectMembers reads one JSON object's member names and refuses a name that is
// not in allowed (spelled exactly) or that appears twice. what names the object
// in errors. It returns the names present.
func objectMembers(data []byte, allowed map[string]bool, what string) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("anchor: %s is not a JSON object", what)
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("anchor: %s is not valid JSON", what)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("anchor: %s is not valid JSON", what)
		}
		if !allowed[name] {
			if len(name) > 40 {
				name = name[:40]
			}
			return nil, fmt.Errorf("anchor: %s has a member this format does not define: %q", what, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("anchor: %s has the member %q twice", what, name)
		}
		seen[name] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("anchor: %s is not valid JSON", what)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("anchor: %s is not valid JSON", what)
	}
	if dec.More() {
		return nil, fmt.Errorf("anchor: %s is followed by more data", what)
	}
	return seen, nil
}
