// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidKey is returned for a routing key that is not a valid chain id.
var ErrInvalidKey = errors.New("sink: key is not a valid chain id: lowercase letters, " +
	"digits, . _ - (max 64), starting with a letter or digit. Keys must already be " +
	"pseudonyms (a topic or an opaque id); this check cannot tell a name from one")

// idPattern is the chain-id rule the MCP commit tool uses, so a chain written
// here can also be written through proof-mcp.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// entryIDPattern is the only entry id this sink assigns. Ids read back from the
// evidence file are checked against it before any path is built from them: the
// file can be shared, so its contents are input, not trusted state.
var entryIDPattern = regexp.MustCompile(`^sink-[0-9a-f]{32}$`)

// ValidChainID reports whether id is a valid chain id (docs/sink-format.md §1).
// It checks characters only; it cannot tell a pseudonym from a name.
func ValidChainID(id string) bool { return idPattern.MatchString(id) }

// Validate reports whether a record can be committed at all.
//
// # Description
//
// The one validation authority: Commit calls it for every record, and a
// consumer should call it before handing a message to Commit, so that a message
// that can never be committed is terminated upstream instead of failing (and
// being redelivered with) its whole batch.
//
// # Outputs
//
//   - error: nil, or an error wrapping ErrInvalidRecord (and ErrInvalidKey when
//     the key is the problem). Never echoes the key.
//
// # Example
//
//	if err := rec.Validate(); err != nil {
//	    msg.Term() // never committable: do not redeliver
//	}
func (r Record) Validate() error {
	if !ValidChainID(r.Key) {
		return fmt.Errorf("%w: %w", ErrInvalidRecord, ErrInvalidKey)
	}
	switch n := len(r.Content); {
	case n == 0:
		return fmt.Errorf("%w: content is empty; there is nothing to commit", ErrInvalidRecord)
	case n > MaxContentBytes:
		return fmt.Errorf("%w: content is %d bytes, over the %d byte limit", ErrInvalidRecord, n, MaxContentBytes)
	}
	if n := len(r.Source); n > MaxSourceBytes {
		return fmt.Errorf("%w: source is %d bytes, over the %d byte limit", ErrInvalidRecord, n, MaxSourceBytes)
	}
	return nil
}

// ChainFor turns a routing key into a chain id, or refuses it.
//
// # Description
//
// This is the router the service examples share. A key is used as the chain id
// unchanged, and only if it is already a valid one. Nothing is lowercased,
// trimmed or hashed: a key that needs transforming is a key that has not been
// pseudonymised yet, and that belongs upstream.
//
// # Outputs
//
//   - string: the chain id
//   - error: ErrInvalidKey. The key is never echoed into the error, because a
//     refused key is often exactly the personal data this rule keeps out.
//
// # Example
//
//	chain, err := sink.ChainFor(msg.Key)
//	if err != nil {
//	    // refuse the message upstream; do not lowercase, trim or hash it here
//	}
func ChainFor(key string) (string, error) {
	if !ValidChainID(key) {
		return "", ErrInvalidKey
	}
	return key, nil
}

// RecordFromJSON makes a Record from one JSON object, keyed by one of its fields.
//
// # Description
//
// The field must hold a JSON string. The record's content is the line exactly as
// given — no trimming, no re-encoding — so what is committed is what arrived.
//
// # Outputs
//
//   - Record: the record, with Key not yet validated (Commit does that)
//   - error: the line is not a JSON object, or the field is absent or not a string
//
// # Example
//
//	r, err := sink.RecordFromJSON([]byte(`{"user":"u-81","event":"login"}`), "user")
//	// r.Key == "u-81"; r.Content is the whole line
//
// # Limitations
//
//   - Reads one top-level field; nested paths are not supported.
func RecordFromJSON(line []byte, field string) (Record, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return Record{}, fmt.Errorf("not a JSON object: %w", err)
	}
	raw, ok := obj[field]
	if !ok {
		return Record{}, fmt.Errorf("no %q field to route by", field)
	}
	// Checked explicitly: null decodes into a string without error, as "".
	var key string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &key) != nil {
		return Record{}, fmt.Errorf("field %q is not a string", field)
	}
	return Record{Key: key, Content: append([]byte(nil), line...)}, nil
}
