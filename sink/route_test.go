// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestChainFor(t *testing.T) {
	cases := []struct {
		key string
		ok  bool
	}{
		{"u-81", true},
		{"a", true},
		{"orders.eu_west-1", true},
		{"0", true},
		{strings.Repeat("a", 64), true},
		{"", false},
		{strings.Repeat("a", 65), false},
		{"U-81", false},           // not lowercased for you
		{" u-81", false},          // not trimmed for you
		{"jo@example.com", false}, // the case the rule exists for
		{"-a", false},
		{".a", false},
		{"..", false},
		{"a/b", false}, // would escape the content folder
		{"a b", false},
		{"a\x00b", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.key), func(t *testing.T) {
			got, err := ChainFor(c.key)
			if c.ok {
				if err != nil || got != c.key {
					t.Fatalf("ChainFor(%q) = %q, %v; want the key unchanged", c.key, got, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ChainFor(%q) = %q, %v; want ErrInvalidKey", c.key, got, err)
			}
			if c.key != "" && strings.Contains(err.Error(), c.key) {
				t.Fatalf("the error echoes the refused key: %v", err)
			}
		})
	}
}

func TestRecordFromJSON(t *testing.T) {
	line := []byte(`{"user":"u-81","event":"login","n":1}`)
	r, err := RecordFromJSON(line, "user")
	if err != nil || r.Key != "u-81" || string(r.Content) != string(line) {
		t.Fatalf("got %+v, %v", r, err)
	}
	line[2] = 'X' // the record must not alias the caller's buffer
	if r.Content[2] == 'X' {
		t.Fatal("Record.Content aliases the input line")
	}

	for name, in := range map[string]string{
		"missing field":    `{"topic":"a"}`,
		"number field":     `{"user":81}`,
		"null field":       `{"user":null}`,
		"not an object":    `["u-81"]`,
		"not JSON":         `user=u-81`,
		"trailing garbage": `{"user":"u-81"} x`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RecordFromJSON([]byte(in), "user"); err == nil {
				t.Fatalf("RecordFromJSON(%s) succeeded", in)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
