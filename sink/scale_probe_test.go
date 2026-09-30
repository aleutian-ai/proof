// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestScaleProbe splits Commit's cost by shape (ticket _74). Skipped unless
// SINK_PROBE is set.
func TestScaleProbe(t *testing.T) {
	if os.Getenv("SINK_PROBE") == "" {
		t.Skip("set SINK_PROBE=1")
	}
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	batch := func(n int, subject func(i int) string, tag string) []Record {
		recs := make([]Record, n)
		for i := range recs {
			recs[i] = Record{Class: "events", Subject: subject(i), Content: []byte(fmt.Sprintf(`{"%s":%d}`, tag, i))}
		}
		return recs
	}
	const n = 200
	for _, c := range []struct {
		name string
		recs []Record
	}{
		{"200 records, 1 NEW subject", batch(n, func(int) string { return "one" }, "a")},
		{"200 records, 200 NEW subjects", batch(n, func(i int) string { return fmt.Sprintf("s-%d", i) }, "b")},
		{"200 records, the same 200 EXISTING subjects", batch(n, func(i int) string { return fmt.Sprintf("s-%d", i) }, "c")},
		{"200 records, 1 EXISTING subject", batch(n, func(int) string { return "one" }, "d")},
	} {
		start := time.Now()
		if _, err := s.Commit(ctx, c.recs); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		t.Logf("%-45s %8s  (%6.2f ms/record)", c.name, d.Round(time.Millisecond), float64(d.Microseconds())/1000/n)
	}
}
