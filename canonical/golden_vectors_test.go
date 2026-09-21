// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package canonical_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/proof/canonical"
)

// TestGoldenVectors pins the Go-side canonical encoder output against
// the testdata/ corpus. The same corpus is consumed by Python + JS
// SDK parity tests in their respective workstreams; byte-identical
// output across all three is the cross-language stability gate.
//
// Per `canonical_cross_emitter_golden_vectors`: regenerate with
// `go test -run TestGoldenVectors -update` if a legitimate encoder
// change requires updating the pins.
func TestGoldenVectors(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") == "1"

	cases := []struct {
		name  string
		input any
	}{
		{"ascii_basic", map[string]any{"b": 2, "a": 1, "z": "last"}},
		{"html_chars", map[string]any{
			"url":  "https://verify.aleutian.ai/?bundle=abc&token=xyz",
			"less": "1<2",
			"amp":  "a&b",
			"gt":   "2>1",
		}},
		{"line_separators", map[string]any{
			"u2028": "before after",
			"u2029": "before after",
		}},
		{"emoji_supplementary", map[string]any{
			"smile": "before \U0001F600 after",
		}},
		{"int64_extremes", map[string]any{
			"max": json.Number("9223372036854775807"),
			"min": json.Number("-9223372036854775808"),
		}},
		{"empty_collections", map[string]any{
			"empty_obj":  map[string]any{},
			"empty_arr":  []any{},
			"empty_str":  "",
			"null_value": nil,
		}},
		{"nested_3_levels", map[string]any{
			"a": map[string]any{
				"b": map[string]any{
					"c": "deepest",
				},
			},
		}},
		{"array_order_preserved", []any{
			"zebra", "apple", "mango",
		}},
		{"mixed_array", []any{
			1, "two", true, nil, map[string]any{"k": "v"},
		}},
		// Batch A (L14) — ASCII-edge cases the crypto review flagged as
		// behaving consistently across Go/Python/JS but not yet pinned.
		{"forward_slash", map[string]any{
			"path": "a/b/c",
		}},
		{"control_chars", map[string]any{
			"esc": "\x01\x02\x1f",
			"tab": "a\tb",
			"nl":  "a\nb",
			"cr":  "a\rb",
		}},
		{"del_unescaped", map[string]any{
			"k": "a\x7fb", // DEL (U+007F) is NOT escaped per Go's default
		}},
		{"non_bmp_key_sort", map[string]any{
			"\U0001F600": 1, // 😀 — UTF-8 prefix 0xF0 sorts AFTER…
			"￿":          2, // U+FFFF — UTF-8 prefix 0xEF.
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonical.MarshalJSON(tc.input)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			path := filepath.Join("testdata", tc.name+".json")
			if update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatalf("update golden %s: %v", path, err)
				}
				t.Logf("updated golden: %s", path)
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (rerun with UPDATE_GOLDEN=1 to seed)", path, err)
			}
			if string(got) != string(want) {
				t.Errorf("golden mismatch for %s\nwant: %s\ngot:  %s", tc.name, want, got)
			}
		})
	}
}

// TestGoldenVectors_Rejects pins the rejection cases (floats, deep
// nesting). These are corpus members but their expected output is
// an error, not a byte string.
func TestGoldenVectors_Rejects(t *testing.T) {
	t.Run("float_rejected", func(t *testing.T) {
		type S struct {
			F float64 `json:"f"`
		}
		_, err := canonical.MarshalJSON(S{F: 0.1})
		if err == nil {
			t.Fatal("expected float rejection, got nil")
		}
	})

	t.Run("max_depth_exceeded", func(t *testing.T) {
		deep := any(map[string]any{"x": 1})
		for i := 0; i < canonical.MaxDepth+5; i++ {
			deep = map[string]any{"n": deep}
		}
		_, err := canonical.MarshalJSON(deep)
		if err == nil {
			t.Fatal("expected depth rejection, got nil")
		}
	})
}

// TestRejects_FailClosedString pins the new fail-closed checks added in
// response to the 4-agent review batch A (2026-06-02): lone surrogates
// (C2) and non-NFC strings (H7) MUST be rejected by all three encoder
// ports. Tests Go side here; Python + JS run the parallel suite.
func TestRejects_FailClosedString(t *testing.T) {
	t.Run("lone_surrogate_in_value", func(t *testing.T) {
		// U+D800 expressed as a 3-byte UTF-8 sequence (ed a0 80) which Go
		// strings hold verbatim — the encoder must catch it before the
		// json.Marshal step (which would silently produce U+FFFD).
		s := string([]byte{0xed, 0xa0, 0x80})
		_, err := canonical.MarshalJSON(map[string]any{"k": s})
		if err == nil {
			t.Fatal("expected lone-surrogate rejection, got nil")
		}
	})
	t.Run("lone_surrogate_in_key", func(t *testing.T) {
		k := string([]byte{0xed, 0xa0, 0x80})
		_, err := canonical.MarshalJSON(map[string]any{k: 1})
		if err == nil {
			t.Fatal("expected lone-surrogate-in-key rejection, got nil")
		}
	})
	t.Run("non_nfc_value", func(t *testing.T) {
		// "café" in NFD: c-a-f-e + U+0301 (combining acute).
		nfd := "café"
		_, err := canonical.MarshalJSON(map[string]any{"k": nfd})
		if err == nil {
			t.Fatal("expected NFC rejection, got nil")
		}
	})
	t.Run("non_nfc_key", func(t *testing.T) {
		nfd := "café"
		_, err := canonical.MarshalJSON(map[string]any{nfd: 1})
		if err == nil {
			t.Fatal("expected NFC-key rejection, got nil")
		}
	})
	t.Run("nfc_value_accepted", func(t *testing.T) {
		// "café" in NFC: c-a-f-é (precomposed) — must succeed.
		nfc := "café"
		_, err := canonical.MarshalJSON(map[string]any{"k": nfc})
		if err != nil {
			t.Fatalf("NFC must be accepted: %v", err)
		}
	})
}

// TestGoldenVectors_NonBMPKeySort pins the UTF-8 byte-order key sort
// (C1 fix). Object with keys spanning the BMP boundary MUST sort by
// UTF-8 bytes in all three ports — emoji (U+1F600, UTF-8 prefix 0xF0)
// sorts AFTER U+FFFF (UTF-8 prefix 0xEF), NOT before it (which is what
// JS default UTF-16 sort would produce).
func TestGoldenVectors_NonBMPKeySort(t *testing.T) {
	got, err := canonical.MarshalJSON(map[string]any{
		"\U0001F600": 1, // 😀
		"￿":          2,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Expected: U+FFFF (ef bf bf) sorts BEFORE U+1F600 (f0 9f 98 80).
	want := "{\"￿\":2,\"\U0001F600\":1}"
	if string(got) != want {
		t.Errorf("non-BMP key sort mismatch\nwant: %s\ngot:  %s", want, got)
	}
}
