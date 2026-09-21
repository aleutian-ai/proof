// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxDepth caps recursion depth inside writeSorted. Per E1 crypto
// review finding H2: an unbounded recursion blows the goroutine stack
// on adversarial-depth input. Manifest nesting is typically 4–5
// levels deep; 64 is comfortable headroom that still cuts off any
// stack-blow vector.
const MaxDepth = 64

// ErrMaxDepthExceeded is returned when input nesting exceeds MaxDepth.
var ErrMaxDepthExceeded = errors.New("canonical: input nesting exceeds MaxDepth")

// ErrFloatNotAllowed is returned when a float value reaches
// writeSorted. The manifest schema deliberately avoids floats per
// Phase 0 spec §1.3 — float canonicalization is under-specified
// across Go / Python / JS (Go emits "1" for 1.0, Python emits
// "1.0"). Rather than relying on producer-side discipline, we fail
// loudly here so a future field can't silently break cross-language
// byte stability.
var ErrFloatNotAllowed = errors.New("canonical: float values are not supported (use string or int64)")

// ErrNotNFC is returned when a string value is not in Unicode Normalization
// Form C. Per the 4-agent review (H7): different host filesystems / input
// methods can deliver the same logical text in NFC or NFD form, producing
// divergent canonical bytes — a silent verification failure. Like
// ErrFloatNotAllowed this is a fail-closed discipline: the encoder refuses
// to canonicalize ambiguous input rather than silently rewriting (which
// would change bytes the producer didn't intend to sign).
var ErrNotNFC = errors.New("canonical: string is not in Unicode NFC form")

// ErrLoneSurrogate is returned when a string contains an unpaired UTF-16
// surrogate (U+D800–U+DFFF). Per the 4-agent review (C2): Go, Python, and
// JS encoders produce three different outputs for the same lone-surrogate
// input — fail-closed before that divergence reaches the signature path.
var ErrLoneSurrogate = errors.New("canonical: string contains unpaired UTF-16 surrogate")

// MarshalJSON encodes v as compact JSON with all object keys sorted
// alphabetically (recursively, including nested objects).
//
// # Description
//
// The encoding strategy is two-pass:
//
//  1. encoding/json.Marshal produces a working JSON tree honoring
//     all struct tags (including omitempty).
//  2. Decode into a generic any tree; recursively re-emit with
//     keys sorted, HTML escaping DISABLED (SetEscapeHTML(false)),
//     and compact separators.
//
// HTML escaping is the cross-language-stability risk: Go's
// encoding/json default escapes `<`, `>`, `&`, ` `, ` `
// inside string values, but Python's `json.dumps(sort_keys=True,
// separators=(",", ":"))` does NOT. Any field that legitimately
// contains those characters (e.g., a `report_endpoint` URL with
// `?a=1&b=2`) would produce divergent bytes between Go producer
// and Python verifier — breaking signature verification. We
// suppress HTML escaping on every scalar so the byte output matches
// what other-language encoders produce by default.
//
// The second pass uses json.Decoder.UseNumber so integer fields
// don't get coerced to float64 (which would change "0" to "0").
//
// # Inputs
//
//   - v: any encoding/json-compatible value (struct, map, slice).
//
// # Outputs
//
//   - []byte: compact UTF-8 JSON with sorted keys.
//   - error: wrapping any encoding/json error from either pass.
func MarshalJSON(v any) ([]byte, error) {
	// Pre-pass: walk the input reflectively and validate every string
	// (keys and values) BEFORE the first-pass marshal corrupts invalid
	// UTF-8. encoding/json silently rewrites invalid sequences to U+FFFD,
	// which would mask the kind of producer-side bug this gate exists
	// to surface (lone surrogates from misconfigured upstream sources,
	// NFD bytes from macOS filesystem reads, etc.).
	if err := validateInputStrings(v, 0); err != nil {
		return nil, err
	}
	// First-pass marshal also uses an Encoder with SetEscapeHTML(false)
	// so the intermediate bytes that get re-decoded carry the same
	// escape policy as the final output. (encoding/json.Marshal would
	// HTML-escape; we strip that by using the Encoder path.)
	first, err := compactMarshalNoHTMLEscape(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: first-pass marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(first))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: decode for sort: %w", err)
	}
	var out bytes.Buffer
	if err := writeSorted(&out, generic, 0); err != nil {
		return nil, fmt.Errorf("canonical: emit sorted: %w", err)
	}
	return out.Bytes(), nil
}

// compactMarshalNoHTMLEscape is json.Marshal with SetEscapeHTML(false)
// and the trailing newline that json.Encoder appends stripped.
func compactMarshalNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder appends a newline; strip it for our compact form.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// writeSorted emits v into buf in compact, key-sorted form.
//
// Maps are emitted with keys sorted ascending by byte-wise UTF-8
// ordering. Slices preserve declaration order. Scalars round-trip
// through encoding/json.Marshal to inherit its escaping rules
// (consistent with what other-language encoders produce).
func writeSorted(buf *bytes.Buffer, v any, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: depth %d > MaxDepth %d", ErrMaxDepthExceeded, depth, MaxDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if err := validateCanonicalString(k); err != nil {
				return fmt.Errorf("object key: %w", err)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := compactMarshalNoHTMLEscape(k)
			if err != nil {
				return fmt.Errorf("marshal key %q: %w", k, err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeSorted(buf, t[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeSorted(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case float32, float64:
		// Direct float input — the first pass would have converted
		// these to a numeric JSON token; reach here only if a caller
		// passed a raw float through a non-struct path.
		return fmt.Errorf("%w: type %T value %v", ErrFloatNotAllowed, t, t)
	case json.Number:
		// After UseNumber, JSON numbers arrive as json.Number strings.
		// Reject any that carry a decimal point or scientific notation
		// — these are floats whose cross-language canonicalization is
		// under-specified (Go: "1.5", Python could emit "1.500000",
		// etc.). Integers pass through fine.
		s := t.String()
		for _, c := range s {
			if c == '.' || c == 'e' || c == 'E' {
				return fmt.Errorf("%w: number %q", ErrFloatNotAllowed, s)
			}
		}
		buf.WriteString(s)
	case string:
		// Fail-closed on non-NFC or lone-surrogate input. The Python
		// and JS encoder ports apply the same checks at the same
		// boundary so all three reject identically before any byte
		// difference can reach the signature path.
		if err := validateCanonicalString(t); err != nil {
			return err
		}
		b, err := compactMarshalNoHTMLEscape(t)
		if err != nil {
			return fmt.Errorf("marshal scalar %v: %w", t, err)
		}
		buf.Write(b)
	default:
		// json.Number, bool, nil — emit via the no-HTML-escape encoder
		// so `&`, `<`, `>` survive verbatim. Numbers and booleans
		// have no Unicode normalization concern.
		b, err := compactMarshalNoHTMLEscape(t)
		if err != nil {
			return fmt.Errorf("marshal scalar %v: %w", t, err)
		}
		buf.Write(b)
	}
	return nil
}

// validateCanonicalString rejects strings that would produce divergent
// canonical bytes across Go / Python / JS encoder ports. Two failure modes
// are checked:
//
//  1. Lone UTF-16 surrogate (U+D800–U+DFFF). Go round-trips the codepoint
//     into U+FFFD; Python preserves it then crashes on UTF-8 encode; JS
//     escapes it as \uD8XX. Three different outputs for the same input —
//     bundle verify breaks across SDKs.
//  2. Non-NFC normalization. A producer typing "café" (NFC, 4 codepoints)
//     and a verifier receiving "café" (NFD, 5 codepoints) re-canonicalize
//     to different bytes. macOS filesystems / some browsers silently NFD;
//     the encoder fails-closed instead of silently rewriting (which would
//     change the bytes the producer thought they were signing).
//
// # Why fail-closed over silent normalization
//
// Auto-normalizing would change the byte sequence the producer signs from
// what they passed in. If a future schema field carried bytewise-sensitive
// data (paths, tokens, base64), silent rewriting would corrupt it. Refusing
// to canonicalize ambiguous input surfaces the bug at producer time, where
// the upstream pipeline can fix it deliberately.
// validateInputStrings recursively walks v and applies validateCanonicalString
// to every string encountered as a map key or value. Mirrors the structural
// shape MarshalJSON eventually produces: scalar pass-through, map iteration
// with key + value checks, slice element recursion. struct fields are walked
// via reflection so a producer passing a typed struct (the common case)
// gets the same fail-closed discipline as a producer passing a generic
// map[string]any.
//
// Depth-capped at MaxDepth like writeSorted to prevent stack abuse on
// adversarial input.
func validateInputStrings(v any, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: depth %d > MaxDepth %d during input validation", ErrMaxDepthExceeded, depth, MaxDepth)
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return validateCanonicalString(t)
	case bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		// Scalar non-strings have no Unicode concern. Floats are
		// independently rejected by writeSorted; the pre-pass doesn't
		// duplicate that check (it'd just produce a different error
		// path for the same input).
		return nil
	case map[string]any:
		for k, val := range t {
			if err := validateCanonicalString(k); err != nil {
				return fmt.Errorf("object key: %w", err)
			}
			if err := validateInputStrings(val, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, e := range t {
			if err := validateInputStrings(e, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		// Reflective walk for typed structs / slices / maps. The encoding/json
		// MarshalJSON-honoring path is what the second pass uses; here we
		// just need to find embedded strings before they get rewritten.
		return validateInputStringsReflect(v, depth)
	}
}

// validateInputStringsReflect handles typed values via reflection. Uses
// json.Marshal-then-Decode as a fallback: produces an `any` tree honoring
// json struct tags (so omitempty and json:"-" fields are skipped — they
// can't reach the signed bytes anyway), then re-uses validateInputStrings
// on the decoded tree. The trade-off: one extra marshal-pass for typed
// inputs. The signature path already does this so the cost is symmetric.
func validateInputStringsReflect(v any, depth int) error {
	b, err := compactMarshalNoHTMLEscape(v)
	if err != nil {
		return fmt.Errorf("canonical: validation marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return fmt.Errorf("canonical: validation decode: %w", err)
	}
	return validateInputStrings(generic, depth+1)
}

func validateCanonicalString(s string) error {
	// Go's range-over-string silently maps invalid UTF-8 bytes (including
	// the 3-byte encoding of lone surrogates U+D800–U+DFFF) to U+FFFD
	// before we ever see them. utf8.ValidString catches lone surrogates
	// AND every other malformed sequence — both classes cause cross-
	// language encoder divergence, so a single fail-closed gate is the
	// right shape. The error sentinel is ErrLoneSurrogate because that's
	// the most common cross-language divergence trigger in practice; the
	// wrapped message clarifies if the bytes are otherwise malformed.
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: string contains invalid UTF-8 (lone surrogate or malformed sequence)", ErrLoneSurrogate)
	}
	if !norm.NFC.IsNormalString(s) {
		return fmt.Errorf("%w: producer must normalize to NFC before canonicalization", ErrNotNFC)
	}
	return nil
}
