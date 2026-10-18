// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package jsontext

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"plain", `{"a":"b"}`, nil},
		{"raw multibyte", `{"a":"é😀"}`, nil},
		{"real U+FFFD", "{\"a\":\"�\"}", nil},
		{"BMP escape", `{"a":"é"}`, nil},
		{"surrogate pair", `{"a":"😀"}`, nil},
		{"surrogate pair upper case", `{"a":"😀"}`, nil},
		{"escaped backslash then u", `{"a":"\\ud800"}`, nil},
		{"three backslashes then u", `{"a":"\\\ud800"}`, ErrLoneSurrogate},
		{"lone high", `{"a":"\ud800"}`, ErrLoneSurrogate},
		{"lone high at end", `"\ud800`, ErrLoneSurrogate},
		{"lone low", `{"a":"\udfff"}`, ErrLoneSurrogate},
		{"high then BMP", `{"a":"\ud800A"}`, ErrLoneSurrogate},
		{"high then high", `{"a":"\ud800\ud800"}`, ErrLoneSurrogate},
		{"low then high", `{"a":"\ude00\ud83d"}`, ErrLoneSurrogate},
		{"invalid byte", "{\"a\":\"\xff\"}", ErrInvalidUTF8},
		{"encoded surrogate bytes", "{\"a\":\"\xed\xa0\x80\"}", ErrInvalidUTF8},
		{"truncated escape", `{"a":"\u12`, nil},
		{"trailing backslash", `\`, nil},
	}
	for _, c := range cases {
		if got := Check([]byte(c.in)); !errors.Is(got, c.want) {
			t.Errorf("%s: Check = %v, want %v", c.name, got, c.want)
		}
	}
}

func FuzzCheck(f *testing.F) {
	f.Add([]byte(`{"a":"😀"}`))
	f.Add([]byte(`{"a":"\ud800"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Check(b)
	})
}
