// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package canonical_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/canonical"
)

func TestMarshalJSON_SortsTopLevelKeys(t *testing.T) {
	type S struct {
		Zebra string `json:"zebra"`
		Apple string `json:"apple"`
		Mango string `json:"mango"`
	}
	got, err := canonical.MarshalJSON(S{Zebra: "z", Apple: "a", Mango: "m"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"apple":"a","mango":"m","zebra":"z"}`
	if string(got) != want {
		t.Errorf("want %q, got %q", want, string(got))
	}
}

func TestMarshalJSON_SortsNestedKeys(t *testing.T) {
	type Inner struct {
		Z string `json:"z"`
		A string `json:"a"`
	}
	type Outer struct {
		B Inner `json:"b"`
		A Inner `json:"a"`
	}
	got, err := canonical.MarshalJSON(Outer{B: Inner{Z: "z", A: "a"}, A: Inner{Z: "z2", A: "a2"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"a":"a2","z":"z2"},"b":{"a":"a","z":"z"}}`
	if string(got) != want {
		t.Errorf("want %q, got %q", want, string(got))
	}
}

func TestMarshalJSON_PreservesArrayOrder(t *testing.T) {
	got, err := canonical.MarshalJSON([]int{3, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `[3,1,2]` {
		t.Errorf("array order not preserved: got %q", got)
	}
}

func TestMarshalJSON_HonorsOmitempty(t *testing.T) {
	type S struct {
		A string `json:"a,omitempty"`
		B string `json:"b"`
	}
	got, err := canonical.MarshalJSON(S{A: "", B: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"b":"hello"}` {
		t.Errorf("omitempty not honored: %q", got)
	}
}

func TestMarshalJSON_Determinism(t *testing.T) {
	type S struct {
		M map[string]int `json:"m"`
		L []string       `json:"l"`
	}
	s := S{
		M: map[string]int{"z": 1, "a": 2, "m": 3},
		L: []string{"x", "y", "z"},
	}
	a, err := canonical.MarshalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonical.MarshalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("non-deterministic:\na=%s\nb=%s", a, b)
	}
}

func TestMarshalJSON_IntegerPreservation(t *testing.T) {
	type S struct {
		N int64 `json:"n"`
	}
	got, err := canonical.MarshalJSON(S{N: 1717200000000})
	if err != nil {
		t.Fatal(err)
	}
	// Must NOT be turned into "1.7172e+12" or similar.
	if string(got) != `{"n":1717200000000}` {
		t.Errorf("int64 mangled: %q", got)
	}
}

func TestMarshalJSON_NullsAndBools(t *testing.T) {
	type S struct {
		B bool   `json:"b"`
		P *int   `json:"p"`
		S string `json:"s"`
	}
	got, err := canonical.MarshalJSON(S{B: true, P: nil, S: ""})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"b":true,"p":null,"s":""}` {
		t.Errorf("nulls/bools mangled: %q", got)
	}
}

func TestMarshalJSON_DoesNotHTMLEscape(t *testing.T) {
	type S struct {
		URL  string `json:"url"`
		Less string `json:"less"`
		Amp  string `json:"amp"`
	}
	got, err := canonical.MarshalJSON(S{
		URL:  "https://verify.aleutian.ai/?bundle=abc&token=xyz",
		Less: "1<2",
		Amp:  "a&b",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	// Bytes that Go's default json.Marshal would HTML-escape but
	// Python json.dumps default would NOT. We must produce the
	// non-escaped form for cross-language byte stability.
	for _, want := range []string{"bundle=abc&token=xyz", "1<2", "a&b"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing literal %q (got HTML-escaped?):\n%s", want, s)
		}
	}
	// The HTML-escape sequences Go's default encoder would emit are
	// the literal six-character byte sequences &, <, >.
	// We must NOT see those in the output.
	for _, forbidden := range []string{"\\u0026", "\\u003c", "\\u003e"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("output contains HTML-escape sequence %q:\n%s", forbidden, s)
		}
	}
}

// E1 H2 — recursion depth limit.
func TestMarshalJSON_DepthLimitExceeded(t *testing.T) {
	// Build a JSON tree deeper than MaxDepth via nested maps.
	deep := any(map[string]any{"x": 1})
	for i := 0; i < canonical.MaxDepth+5; i++ {
		deep = map[string]any{"nest": deep}
	}
	_, err := canonical.MarshalJSON(deep)
	if !errors.Is(err, canonical.ErrMaxDepthExceeded) {
		t.Fatalf("expected ErrMaxDepthExceeded, got %v", err)
	}
}

// E1 L4 — float rejection.
func TestMarshalJSON_FloatRejected(t *testing.T) {
	type S struct {
		F float64 `json:"f"`
	}
	_, err := canonical.MarshalJSON(S{F: 1.5})
	if !errors.Is(err, canonical.ErrFloatNotAllowed) {
		t.Fatalf("expected ErrFloatNotAllowed, got %v", err)
	}
}

func TestMarshalJSON_MapKeysSortedRecursively(t *testing.T) {
	in := map[string]any{
		"z": map[string]any{"b": 2, "a": 1},
		"a": map[string]any{"z": 1, "b": 2, "a": 3},
	}
	got, err := canonical.MarshalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"a":3,"b":2,"z":1},"z":{"a":1,"b":2}}`
	if string(got) != want {
		t.Errorf("nested map sort failed:\nwant %s\ngot  %s", want, got)
	}
}
