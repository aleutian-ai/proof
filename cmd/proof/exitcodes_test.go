// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// TestExitCodesArePinned: a script branches on these, so they are part of the
// CLI's API. They are pinned here, and the package documentation and the
// README must state each one.
func TestExitCodesArePinned(t *testing.T) {
	codes := map[int]int{exitOK: 0, exitBroken: 1, exitUsage: 2, exitIOError: 3, exitBusy: 4}
	for got, want := range codes {
		if got != want {
			t.Errorf("exit code %d moved to %d", want, got)
		}
	}
	if len(codes) != 5 {
		t.Fatal("two exit codes share a value")
	}
	doc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"//\t0  verification passed / command succeeded",
		"//\t1  verification FAILED — the chain is broken",
		"//\t2  usage error",
		"//\t3  I/O or parse error",
		"//\t4  the chain or its database is busy",
	} {
		if !strings.Contains(string(doc), line) {
			t.Errorf("the package documentation does not state %q", strings.TrimPrefix(line, "//\t"))
		}
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "`0` ok · `1` chain broken · `2` usage ·") ||
		!strings.Contains(string(readme), "`4` the database is busy") {
		t.Error("the README's exit code list does not match")
	}
}
