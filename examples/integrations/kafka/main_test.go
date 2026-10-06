// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// A class the sink would refuse is a usage error at startup, before any
// connection, never a stream of silently refused records.
func TestRun_RefusesInvalidClass(t *testing.T) {
	for _, class := range []string{"", "Payments", "pay.ments", "-x", strings.Repeat("a", 32)} {
		var out, errs bytes.Buffer
		if code := run([]string{"consume", "-class", class, "-dir", t.TempDir()}, strings.NewReader(""), &out, &errs); code != exitUsage {
			t.Fatalf("-class %q: exit %d, want %d (%s)", class, code, exitUsage, errs.String())
		}
		if !strings.Contains(errs.String(), "-class") {
			t.Fatalf("-class %q: the error does not name the flag: %s", class, errs.String())
		}
	}
}

func TestRun_RefusesLongTopic(t *testing.T) {
	var out, errs bytes.Buffer
	args := []string{"consume", "-class", "actions", "-topic", strings.Repeat("t", 240), "-dir", t.TempDir()}
	if code := run(args, strings.NewReader(""), &out, &errs); code != exitUsage || !strings.Contains(errs.String(), "too long") {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
}

func TestRun_Usage(t *testing.T) {
	for _, args := range [][]string{nil, {"pending"}, {"produce"}} {
		var out, errs bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errs); code != exitUsage {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}

func TestKeyOf(t *testing.T) {
	cases := []struct {
		line, want string
		null, bad  bool
	}{
		{line: `{"user":"u-81"}`, want: "u-81"},
		{line: `{"other":1}`, null: true},
		{line: `{"user":null}`, null: true},
		{line: `{"user":7}`, bad: true},
		{line: `[1]`, bad: true},
	}
	for _, tc := range cases {
		k, err := keyOf([]byte(tc.line), "user")
		switch {
		case tc.bad:
			if err == nil {
				t.Fatalf("%s: accepted", tc.line)
			}
			if strings.Contains(err.Error(), "7") {
				t.Fatalf("%s: the error names the value: %v", tc.line, err)
			}
		case tc.null:
			if err != nil || k != nil {
				t.Fatalf("%s: key %q, err %v; want no key", tc.line, k, err)
			}
		default:
			if err != nil || string(k) != tc.want {
				t.Fatalf("%s: key %q, err %v", tc.line, k, err)
			}
		}
	}
}

func TestRun_RefusesNonPositiveIdle(t *testing.T) {
	for _, idle := range []string{"0s", "-1s"} {
		var out, errs bytes.Buffer
		args := []string{"consume", "-class", "actions", "-idle", idle, "-dir", t.TempDir()}
		if code := run(args, strings.NewReader(""), &out, &errs); code != exitUsage || !strings.Contains(errs.String(), "-idle") {
			t.Fatalf("-idle %s: exit %d: %s", idle, code, errs.String())
		}
	}
}
