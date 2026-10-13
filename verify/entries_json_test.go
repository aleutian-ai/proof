// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodeEntries_ReadsBothShapes: what Chain's own entries marshal to is
// read back, as an array and as JSONL.
func TestDecodeEntries_ReadsBothShapes(t *testing.T) {
	entries, _ := buildChain(t, 3)
	array, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, e := range entries {
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	for name, raw := range map[string]string{
		"array":                  string(array),
		"jsonl":                  strings.Join(lines, "\n"),
		"jsonl with blank lines": "\n" + strings.Join(lines, "\n\n") + "\n",
		"an unknown member":      `[` + strings.Replace(lines[0], `{`, `{"company":"x",`, 1) + `]`,
	} {
		got, err := DecodeEntries([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got[0] != entries[0] {
			t.Errorf("%s: entry 0 = %+v, want %+v", name, got[0], entries[0])
		}
	}
}

// TestDecodeEntries_RefusesWhatIsNotEntries: a file that is not entries is an
// error. Each of these once decoded to entries with empty fields, and
// `proof verify` then reported BROKEN, a tamper verdict about a file that was
// never a chain; the repeated and wrong-case members decoded to whichever
// value encoding/json happened to keep.
func TestDecodeEntries_RefusesWhatIsNotEntries(t *testing.T) {
	entries, _ := buildChain(t, 1)
	good, _ := json.Marshal(entries[0])
	g := string(good)
	for name, raw := range map[string]string{
		"empty":                     "  \n",
		"an empty object":           `{}`,
		"null":                      `null`,
		"an empty array":            `[]`,
		"an array of null":          `[null]`,
		"an export bundle":          `{"format":"aleutian.proof.bundle.v1","chains":[]}`,
		"an anchor":                 `{"version":6,"subject":"s","chain_hash":"aa","entry_count":1}`,
		"a member twice":            strings.Replace(g, `"global_seq":`, `"global_seq":7,"global_seq":`, 1),
		"a member in another case":  strings.Replace(g, `"chain_hash":`, `"CHAIN_HASH":`, 1),
		"no chain_hash":             strings.Replace(g, `"chain_hash":`, `"other":`, 1),
		"a member of another type":  strings.Replace(g, `"global_seq":0`, `"global_seq":"0"`, 1),
		"two objects on one line":   g + g,
		"an array that is not JSON": `[` + g,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeEntries([]byte(raw))
			if err == nil {
				t.Fatalf("decoded %d entries", len(got))
			}
			if strings.Contains(err.Error(), entries[0].ChainHash) {
				t.Error("the error quotes a value from the input")
			}
		})
	}
}
