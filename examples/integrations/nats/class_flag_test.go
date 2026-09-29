// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// A class the sink would refuse is a usage error at startup, before any
// connection, never a stream of silently refused messages.
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
