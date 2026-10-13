// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// entryMembers are the members of an exported entry, by their exact names.
// Lower-cased, they are how a member spelled in another case is recognised.
var entryMembers = map[string]bool{
	"entry_id": true, "entry_type": true, "timestamp": true, "format_version": true,
	"run_id": true, "sequence_num": true, "global_seq": true, "content_hash": true,
	"chain_hash": true,
}

// requiredEntryMembers are the members every entry of every format carries.
var requiredEntryMembers = []string{"entry_id", "timestamp", "content_hash", "chain_hash"}

// DecodeEntries reads exported entries: a JSON array of entry objects, or one
// entry object per line (JSONL).
//
// # Description
//
// The shape is sniffed, so a caller verifying a file someone handed them need
// not know which it is. What is read must be entries: a file that is some other
// JSON (an anchor, an export bundle, `{}`, `null`) is an ERROR, not a chain to
// verify. Read leniently, such a file became one entry with every field empty,
// and the verdict was BROKEN: a tamper finding about a file that was never a
// chain.
//
// Each entry is an object that carries entry_id, timestamp, content_hash and
// chain_hash, has no member twice, and has no member whose name is one of the
// format's in another case. encoding/json alone would take the last of a
// repeated member and match names without regard to case, so two readers could
// see two different entries in one file. Members the format does not define
// are ignored: none of them is hashed, and exports from other producers carry
// some.
//
// # Inputs
//
//   - raw: the file's bytes
//
// # Outputs
//
//   - []Entry: the entries, in file order; never empty when err is nil
//   - error: why the input is not entries. It names positions and member names
//     and never quotes a value.
//
// # Example
//
//	entries, err := verify.DecodeEntries(raw)
//	if err != nil {
//	    return err // not a chain: nothing to verify
//	}
//	res, err := verify.Chain(entries, verify.Options{})
//
// # Limitations
//
//   - Holds the whole input and every entry in memory.
//   - Member values are decoded by encoding/json: invalid UTF-8 in a string is
//     repaired, not refused.
//
// # Assumptions
//
//   - None.
func DecodeEntries(raw []byte) ([]Entry, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("the input is empty")
	}
	var docs []json.RawMessage
	where := func(i int) string { return fmt.Sprintf("entry %d", i) }
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &docs); err != nil {
			return nil, errors.New("the input is not a valid JSON array of entries")
		}
	} else {
		where = func(i int) string { return fmt.Sprintf("line %d", i+1) }
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			docs = append(docs, bytes.TrimSpace(line))
		}
	}
	entries := make([]Entry, 0, len(docs))
	for i, doc := range docs {
		if len(doc) == 0 && trimmed[0] != '[' {
			continue // a blank line in JSONL
		}
		e, err := decodeEntry(doc)
		if err != nil {
			return nil, fmt.Errorf("%s is not an entry: %w", where(i), err)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, errors.New("the input holds no entries")
	}
	return entries, nil
}

// decodeEntry reads one entry object, refusing repeated and wrong-case members
// and an object that lacks what every entry has.
func decodeEntry(doc []byte) (Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return Entry{}, errors.New("it is not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return Entry{}, errors.New("it is not valid JSON")
		}
		if !entryMembers[name] && entryMembers[strings.ToLower(name)] {
			return Entry{}, fmt.Errorf("the member %q is spelled in another case", strings.ToLower(name))
		}
		if entryMembers[name] {
			if seen[name] {
				return Entry{}, fmt.Errorf("the member %q appears twice", name)
			}
			seen[name] = true
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return Entry{}, errors.New("it is not valid JSON")
		}
	}
	if _, err := dec.Token(); err != nil {
		return Entry{}, errors.New("it is not valid JSON")
	}
	if dec.More() {
		return Entry{}, errors.New("it is followed by more data")
	}
	for _, name := range requiredEntryMembers {
		if !seen[name] {
			return Entry{}, fmt.Errorf("it has no %q", name)
		}
	}
	var e Entry
	if err := json.Unmarshal(doc, &e); err != nil {
		return Entry{}, errors.New("a member has the wrong JSON type")
	}
	return e, nil
}
