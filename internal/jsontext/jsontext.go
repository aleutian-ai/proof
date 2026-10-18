// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package jsontext checks that JSON text holds every string in one spelling.
//
// encoding/json repairs what it cannot decode: invalid UTF-8 and a `\u` escape
// naming a lone surrogate both become U+FFFD. A file that spells an id with
// `\xff`, `\ud800` or a real U+FFFD would then hash the same and read
// differently, which is the second spelling format-spec §2.0 forbids, and other
// implementations refuse such a file. The readers of entries and anchors call
// [Check] on their input first, so a file is refused instead of repaired.
package jsontext

import (
	"errors"
	"unicode/utf8"
)

// ErrInvalidUTF8 and ErrLoneSurrogate are returned by [Check].
var (
	ErrInvalidUTF8   = errors.New("the text is not valid UTF-8")
	ErrLoneSurrogate = errors.New("a string escape names a lone UTF-16 surrogate")
)

// Check reports whether data is valid UTF-8 and no `\u` escape in it names a
// surrogate outside a high-low pair.
//
// # Description
//
// It scans the bytes and does not parse JSON: a `\u` escape is recognised
// after an odd run of backslashes, which is where JSON allows one. A pair
// `😀` is one character and allowed; a high half not followed by a
// low half, or a low half alone, is refused. What is not valid JSON is left to
// the decoder that runs next.
//
// # Inputs
//
//   - data: the JSON text, whole
//
// # Outputs
//
//   - error: nil, ErrInvalidUTF8 or ErrLoneSurrogate. Never quotes the input.
//
// # Example
//
//	if err := jsontext.Check(raw); err != nil {
//	    return fmt.Errorf("the input is not entries: %w", err)
//	}
//
// # Limitations
//
//   - Does not check that data is JSON.
//
// # Assumptions
//
//   - None.
func Check(data []byte) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		if i+1 >= len(data) {
			return nil
		}
		if data[i+1] != 'u' {
			i++ // the escaped character, a backslash included
			continue
		}
		u, ok := hex4(data, i+2)
		if !ok {
			i++
			continue
		}
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			if i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
				if lo, ok := hex4(data, i+8); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 11
					continue
				}
			}
			return ErrLoneSurrogate
		case u >= 0xDC00 && u <= 0xDFFF:
			return ErrLoneSurrogate
		}
		i += 5
	}
	return nil
}

// hex4 reads four hex digits at data[at:], in either case.
func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[at : at+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}
