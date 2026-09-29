// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidClass is returned for an evidence class that breaks the class rule.
var ErrInvalidClass = errors.New("sink: class is not valid: lowercase letters, digits, _ - " +
	"(max 31), starting with a letter or digit, no dots. A class names a kind of evidence " +
	"(payments, auth), never a person")

// ErrInvalidSubject is returned for a subject that breaks the subject rule. The
// subject is never echoed into an error: a refused one is often exactly the
// personal data the rule keeps out.
var ErrInvalidSubject = errors.New("sink: subject is not valid: lowercase letters, digits, . _ - " +
	"(max 128), starting with a letter or digit. Subjects must already be pseudonyms " +
	"(an opaque id); this check cannot tell a name from one")

var (
	// classPattern: a kind of evidence. No dots, so a chain id splits one way.
	classPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)
	// subjectPattern: who the evidence is about. Characters only; it refuses an
	// email address or anything upper-case, but cannot tell a name from a
	// pseudonym.
	subjectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	// chainIDPattern: the only chain id this sink mints, "<class>.<32 hex>".
	chainIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}$`)
)

// entryIDPattern is the only entry id this sink assigns. Ids read back from the
// evidence file are checked against it before any path is built from them: the
// file can be shared, so its contents are input, not trusted state.
var entryIDPattern = regexp.MustCompile(`^sink-[0-9a-f]{32}$`)

// ValidClass reports whether class is a valid evidence class.
func ValidClass(class string) bool { return classPattern.MatchString(class) }

// ValidSubject reports whether subject passes the subject rule. It checks
// characters only.
func ValidSubject(subject string) bool { return subjectPattern.MatchString(subject) }

// ValidChainID reports whether id is a chain id this sink mints:
// "<class>.<32 hex>". Chain ids are the sink's own; callers name a class and a
// subject, never a chain.
func ValidChainID(id string) bool { return chainIDPattern.MatchString(id) }

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
//   - error: nil, or an error wrapping ErrInvalidRecord, and ErrInvalidClass or
//     ErrInvalidSubject when one of those is the problem. Never echoes the
//     subject.
//
// # Example
//
//	if err := rec.Validate(); err != nil {
//	    msg.Term() // never committable: do not redeliver
//	}
func (r Record) Validate() error {
	if !ValidClass(r.Class) {
		return fmt.Errorf("%w: %w", ErrInvalidRecord, ErrInvalidClass)
	}
	if !ValidSubject(r.Subject) {
		return fmt.Errorf("%w: %w", ErrInvalidRecord, ErrInvalidSubject)
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

// newChainID mints a chain id for a class: the class, a dot, and 128 random
// bits. NEVER derived from the subject, a source, the content or the time:
// anything derived would be a correlator in the shareable artifacts.
func newChainID(class string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sink: draw chain id: %w", err)
	}
	return class + "." + hex.EncodeToString(b), nil
}

// RecordFromJSON makes a Record from one JSON object, whose subject is one of
// its fields. The caller sets the Record's Class.
//
// # Description
//
// The field must hold a JSON string. The record's content is the line exactly as
// given — no trimming, no re-encoding — so what is committed is what arrived.
//
// # Outputs
//
//   - Record: the record with Subject and Content set; Class is the caller's to
//     set, and nothing is validated yet (Validate or Commit does that)
//   - error: the line is not a JSON object, or the field is absent or not a string
//
// # Example
//
//	r, err := sink.RecordFromJSON([]byte(`{"user":"u-81","event":"login"}`), "user")
//	// r.Subject == "u-81"; r.Content is the whole line; set r.Class
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
	return Record{Subject: key, Content: append([]byte(nil), line...)}, nil
}
