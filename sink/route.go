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
	"slices"
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
	if r.Class == r.Subject {
		// The class is public and permanent (it is the chain id's prefix); a class
		// equal to the subject would publish the subject forever.
		return fmt.Errorf("%w: %w: the class equals the subject", ErrInvalidRecord, ErrInvalidClass)
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

// JSONFields says where a JSON line's class and subject come from: exactly one
// of Class and ClassField (with Classes), and SubjectField.
//
// A class is public and permanent: it is the prefix of the chain id, in the
// shareable evidence file and every checkpoint, and no erasure removes it. A
// class read from the data is therefore limited to Classes, so a producer can
// never put an identifier there.
type JSONFields struct {
	// Class is the class of every line.
	Class string
	// ClassField is the top-level field holding each line's class. It must
	// differ from SubjectField.
	ClassField string
	// Classes lists the only classes ClassField may hold. Required with
	// ClassField; a line with any other class is refused.
	Classes []string
	// SubjectField is the top-level field holding each line's subject.
	SubjectField string
}

// RecordFromJSON makes a Record from one JSON object: its subject from one of
// its fields, its class fixed or from another field.
//
// # Description
//
// Each field read must hold a JSON string. The record's content is the line
// exactly as given (no trimming, no re-encoding), so what is committed is what
// arrived. Errors name fields, never their values: a refused value is often the
// personal data the rules keep out.
//
// # Inputs
//
//   - line: one JSON object
//   - f: where the class and subject come from
//
// # Outputs
//
//   - Record: Class, Subject and Content set. Nothing is validated yet
//     (Validate or Commit does that).
//   - error: f does not give exactly one of Class and ClassField, gives
//     ClassField without Classes or equal to SubjectField, or no SubjectField;
//     the line is not a JSON object; a field is absent or not a string; the
//     class read is not one of Classes
//
// # Example
//
//	r, err := sink.RecordFromJSON([]byte(`{"kind":"auth","user":"u-81"}`),
//	    sink.JSONFields{ClassField: "kind", Classes: []string{"auth", "payments"}, SubjectField: "user"})
//	// r.Class == "auth", r.Subject == "u-81", r.Content is the whole line
//
// # Limitations
//
//   - Reads top-level fields only; nested paths are not supported.
//   - Checks f on every call (cheap); a bad f fails on the first line.
//
// # Assumptions
//
//   - The subject is already a pseudonym upstream; this reads it, it does not
//     pseudonymize it.
func RecordFromJSON(line []byte, f JSONFields) (Record, error) {
	switch {
	case (f.Class == "") == (f.ClassField == "") || f.SubjectField == "":
		return Record{}, errors.New("sink: give a subject field, and exactly one of a class and a class field")
	case f.ClassField != "" && f.ClassField == f.SubjectField:
		return Record{}, errors.New("sink: the class field and the subject field must differ " +
			"(a class is public and never erased)")
	case f.ClassField != "" && len(f.Classes) == 0:
		return Record{}, errors.New("sink: a class field needs the list of classes it may hold")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return Record{}, fmt.Errorf("sink: not a JSON object: %w", err)
	}
	subject, err := stringField(obj, f.SubjectField)
	if err != nil {
		return Record{}, err
	}
	class := f.Class
	if f.ClassField != "" {
		if class, err = stringField(obj, f.ClassField); err != nil {
			return Record{}, err
		}
		if !slices.Contains(f.Classes, class) {
			return Record{}, fmt.Errorf("%w: %w: field %q holds a class not in the allowed list",
				ErrInvalidRecord, ErrInvalidClass, f.ClassField)
		}
	}
	return Record{Class: class, Subject: subject, Content: append([]byte(nil), line...)}, nil
}

// stringField reads a top-level field that must hold a JSON string.
func stringField(obj map[string]json.RawMessage, field string) (string, error) {
	raw, ok := obj[field]
	// Checked explicitly: null decodes into a string without error, as "".
	var v string
	if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &v) != nil {
		return "", fmt.Errorf("sink: field %q is missing or not a string", field)
	}
	return v, nil
}
