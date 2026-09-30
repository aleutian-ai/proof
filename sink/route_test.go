// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSubjectRule: the subject rule refuses what it can see (an email, upper
// case, path characters, overlong) and never echoes a refused subject.
func TestSubjectRule(t *testing.T) {
	cases := []struct {
		subject string
		ok      bool
	}{
		{"u-81", true},
		{"a", true},
		{"orders.eu_west-1", true}, // dots are fine in a subject: it is never in a chain id
		{strings.Repeat("a", 128), true},
		{"", false},
		{strings.Repeat("a", 129), false},
		{"U-81", false},           // not lowercased for you
		{" u-81", false},          // not trimmed for you
		{"jo@example.com", false}, // the case the rule exists for
		{"-a", false},
		{".a", false},
		{"a/b", false},
		{"a b", false},
		{"a\x00b", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.subject), func(t *testing.T) {
			if got := ValidSubject(c.subject); got != c.ok {
				t.Fatalf("ValidSubject(%q) = %v, want %v", c.subject, got, c.ok)
			}
			err := Record{Class: testClass, Subject: c.subject, Content: []byte("{}")}.Validate()
			if c.ok {
				if err != nil {
					t.Fatalf("a valid subject refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidSubject) || !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Validate = %v; want ErrInvalidSubject", err)
			}
			if c.subject != "" && strings.Contains(err.Error(), c.subject) {
				t.Fatalf("the error echoes the refused subject: %v", err)
			}
		})
	}
}

// TestClassRule: a class has no dots (a chain id must split one way), is short
// enough that "<class>.<32 hex>" stays within 64 characters, and is required.
func TestClassRule(t *testing.T) {
	for class, ok := range map[string]bool{
		"payments": true, "auth": true, "a_b-c": true, strings.Repeat("a", 31): true,
		"": false, strings.Repeat("a", 32): false, "pay.ments": false, "Payments": false, "-a": false,
	} {
		err := Record{Class: class, Subject: "u-1", Content: []byte("{}")}.Validate()
		if ValidClass(class) != ok || (err == nil) != ok || (!ok && !errors.Is(err, ErrInvalidClass)) {
			t.Errorf("class %q: ValidClass=%v, Validate=%v; want ok=%v", class, ValidClass(class), err, ok)
		}
	}
}

// TestChainIDs: minted ids are "<class>.<32 hex>", within 64 characters, and
// random: identical input never yields the same id, and nothing of the subject
// is in it.
func TestChainIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := newChainID(strings.Repeat("c", 31))
		if err != nil {
			t.Fatal(err)
		}
		if !ValidChainID(id) || len(id) > 64 {
			t.Fatalf("minted %q: not a valid chain id", id)
		}
		if seen[id] {
			t.Fatalf("minted %q twice", id)
		}
		seen[id] = true
	}
	for _, bad := range []string{"u-81", "events.u-81", "events.XYZ", "events." + strings.Repeat("a", 31),
		"pay.ments." + strings.Repeat("a", 32), "../escape"} {
		if ValidChainID(bad) {
			t.Errorf("ValidChainID(%q) = true", bad)
		}
	}
}

func TestRecordFromJSON(t *testing.T) {
	fixed := JSONFields{Class: "events", SubjectField: "user"}
	line := []byte(`{"user":"u-81","kind":"auth","event":"login","n":1}`)
	r, err := RecordFromJSON(line, fixed)
	if err != nil || r.Class != "events" || r.Subject != "u-81" || string(r.Content) != string(line) {
		t.Fatalf("got %+v, %v", r, err)
	}
	allowed := []string{"auth", "payments"}
	r2, err := RecordFromJSON(line, JSONFields{ClassField: "kind", Classes: allowed, SubjectField: "user"})
	if err != nil || r2.Class != "auth" || r2.Subject != "u-81" {
		t.Fatalf("class from a field: %+v, %v", r2, err)
	}
	line[2] = 'X' // the record must not alias the caller's buffer
	if r.Content[2] == 'X' {
		t.Fatal("Record.Content aliases the input line")
	}

	byField := JSONFields{ClassField: "kind", Classes: allowed, SubjectField: "user"}
	for name, c := range map[string]struct {
		in string
		f  JSONFields
	}{
		"missing field":         {`{"topic":"a"}`, fixed},
		"number field":          {`{"user":81}`, fixed},
		"null field":            {`{"user":null}`, fixed},
		"not an object":         {`["u-81"]`, fixed},
		"not JSON":              {`user=u-81`, fixed},
		"trailing garbage":      {`{"user":"u-81"} x`, fixed},
		"class field missing":   {`{"user":"u-81"}`, byField},
		"class field null":      {`{"user":"u-81","kind":null}`, byField},
		"class and class field": {`{"user":"u-81","kind":"auth"}`, JSONFields{Class: "events", ClassField: "kind", SubjectField: "user"}},
		"no class at all":       {`{"user":"u-81"}`, JSONFields{SubjectField: "user"}},
		"no subject field":      {`{"user":"u-81"}`, JSONFields{Class: "events"}},
		"class not allowed":     {`{"user":"u-81","kind":"u-81"}`, byField},
		"class field, no list":  {`{"user":"u-81","kind":"auth"}`, JSONFields{ClassField: "kind", SubjectField: "user"}},
		"class field = subject": {`{"user":"auth"}`, JSONFields{ClassField: "user", Classes: []string{"auth"}, SubjectField: "user"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RecordFromJSON([]byte(c.in), c.f); err == nil {
				t.Fatalf("RecordFromJSON(%s, %+v) succeeded", c.in, c.f)
			}
		})
	}
	// A record whose class equals its subject is refused: the class is public
	// and never erased.
	if err := (Record{Class: "u-81", Subject: "u-81", Content: []byte("x")}).Validate(); !errors.Is(err, ErrInvalidClass) {
		t.Fatalf("class == subject: %v", err)
	}
	// Errors name fields, never values.
	_, err = RecordFromJSON([]byte(`{"user":"jo@example.com","kind":7}`), byField)
	if err == nil || strings.Contains(err.Error(), "jo@example.com") {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
