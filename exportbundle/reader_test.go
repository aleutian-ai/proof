// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// u begins a JSON unicode escape. It is spelled apart so that no tool that
// handles this file can read the escape and replace it with its character.
const u = `\` + `u`

const (
	okHead = `{"format":"aleutian.proof.bundle.v1","chains":[]`
	okDoc  = okHead + `}`
)

// The §3 grammar and the §4 structure, each as the one §9.1 reason it gives.
// "" is a readable bundle.
func TestReader_GrammarAndStructure(t *testing.T) {
	chain := func(members string) string {
		return `{"format":"aleutian.proof.bundle.v1","chains":[{` + members + `}]}`
	}
	entry := func(extra string) string {
		return chain(`"chain_id":"c","entries":[` + strings.TrimSuffix(bareEntry, "}") + extra + `}],"checkpoints":[]`)
	}
	nest := func(depth int) string {
		// depth counts the top-level object as 1.
		return okHead + `,"x":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`
	}
	cases := []struct {
		name, in, want string
	}{
		{"empty input", ``, ReasonJSON},
		{"whitespace only", " \n\t\r", ReasonJSON},
		{"minimal", okDoc, ""},
		{"whitespace everywhere", " \t{ \"format\" :\r\n\"aleutian.proof.bundle.v1\" , \"chains\" : [ ] } \n", ""},
		{"members in any order", `{"chains":[],"format":"aleutian.proof.bundle.v1"}`, ""},
		{"chain members in any order", chain(`"checkpoints":[],"entries":[` + bareEntry + `],"chain_id":"c"`), ""},
		{"trailing value", okDoc + `x`, ReasonJSON},
		{"two documents", okDoc + okDoc, ReasonJSON},
		{"truncated", okHead, ReasonJSON},
		{"trailing comma in an object", okHead + `,}`, ReasonJSON},
		{"trailing comma in an array", `{"format":"aleutian.proof.bundle.v1","chains":[{},]}`, ReasonJSON},
		{"missing colon", `{"format" "x"}`, ReasonJSON},
		{"unquoted name", `{format:"x"}`, ReasonJSON},
		{"single quotes", `{'format':"x"}`, ReasonJSON},
		{"form feed is not whitespace", "\f" + okDoc, ReasonJSON},
		{"byte-order mark", "\xef\xbb\xbf" + okDoc, ReasonJSON},

		{"top-level array", `[]`, ReasonStructure},
		{"top-level string", `"x"`, ReasonStructure},
		{"top-level null", `null`, ReasonStructure},
		{"top-level number", `0`, ReasonStructure},
		{"top-level numbers", `0,0,0`, ReasonJSON},
		{"cut literal", `nul`, ReasonJSON},
		{"literal of another case", `{"format":"aleutian.proof.bundle.v1","chains":True}`, ReasonJSON},

		{"empty object", `{}`, ReasonFormat},
		{"format of another value", `{"format":"aleutian.proof.bundle.v0","chains":[]}`, ReasonFormat},
		{"format v2 is a format", `{"format":"aleutian.proof.bundle.v2","chains":[]}`, ""},
		{"format longer by one", `{"format":"aleutian.proof.bundle.v1 ","chains":[]}`, ReasonFormat},
		{"format of another type", `{"format":1,"chains":[]}`, ReasonFormat},
		{"format null", `{"format":null,"chains":[]}`, ReasonFormat},
		{"format written with escapes", `{"format":"aleutian.proof.bundle.v` + u + `0031","chains":[]}`, ""},
		{"format name written with escapes", `{"f` + u + `006frmat":"aleutian.proof.bundle.v1","chains":[]}`, ""},
		{"format name of another case", `{"Format":"aleutian.proof.bundle.v1","chains":[]}`, ReasonFormat},
		{"format before a structure violation", `{"format":"no","chains":{}}`, ReasonFormat},

		{"chains missing", `{"format":"aleutian.proof.bundle.v1"}`, ReasonStructure},
		{"chains an object", `{"format":"aleutian.proof.bundle.v1","chains":{}}`, ReasonStructure},
		{"chains true", `{"format":"aleutian.proof.bundle.v1","chains":true}`, ReasonStructure},
		{"unknown member", okHead + `,"x":1}`, ReasonStructure},
		{"chain not an object", `{"format":"aleutian.proof.bundle.v1","chains":["c"]}`, ReasonStructure},
		{"chain without members", chain(``), ReasonStructure},
		{"entries empty", chain(`"chain_id":"c","entries":[],"checkpoints":[]`), ReasonStructure},
		{"entries missing", chain(`"chain_id":"c","checkpoints":[]`), ReasonStructure},
		{"checkpoints missing", chain(`"chain_id":"c","entries":[` + bareEntry + `]`), ReasonStructure},
		{"chain_id a number", chain(`"chain_id":1,"entries":[` + bareEntry + `],"checkpoints":[]`), ReasonStructure},
		{"checkpoint an object", chain(`"chain_id":"c","entries":[` + bareEntry + `],"checkpoints":[{}]`), ReasonStructure},
		{"entry missing a member", chain(`"chain_id":"c","entries":[{"entry_id":""}],"checkpoints":[]`), ReasonStructure},
		{"entry a string", chain(`"chain_id":"c","entries":[""],"checkpoints":[]`), ReasonStructure},
		{"entry member null", entry(`,"disclosed":null`), ReasonStructure},
		{"entry with an unknown member", entry(`,"run_id":""`), ReasonStructure},
		{"record_signature whole", entry(`,"record_signature":{"key_id":"","signature":""}`), ""},
		{"record_signature short", entry(`,"record_signature":{"key_id":""}`), ReasonStructure},
		{"record_signature long", entry(`,"record_signature":{"key_id":"","signature":"","x":""}`), ReasonStructure},
		{"record_signature member a number", entry(`,"record_signature":{"key_id":1,"signature":""}`), ReasonStructure},
		{"record_signature an array", entry(`,"record_signature":[]`), ReasonStructure},
		{"disclosed whole", entry(`,"disclosed":{"nonce":"","content":""}`), ""},
		{"disclosed short", entry(`,"disclosed":{"content":""}`), ReasonStructure},
		{"disclosed long", entry(`,"disclosed":{"content":"","nonce":"","x":1}`), ReasonStructure},

		{"duplicate defined name", `{"format":"aleutian.proof.bundle.v1","chains":[],"chains":[]}`, ReasonDuplicateKey},
		{"duplicate after unescaping", `{"format":"aleutian.proof.bundle.v1","f` + u + `006frmat":"x","chains":[]}`, ReasonDuplicateKey},
		{"duplicate unknown name", okHead + `,"x":1,"x":2}`, ReasonDuplicateKey},
		{"duplicate unknown name, one escaped", okHead + `,"x":1,"` + u + `0078":2}`, ReasonDuplicateKey},
		{"duplicate unknown name, escaped and raw non-ASCII", okHead + `,"` + u + `00e9":1,"é":2}`, ReasonDuplicateKey},
		{"duplicate unknown name, a surrogate pair and raw", okHead + `,"` + u + `d83d` + u + `de00":1,"😀":2}`, ReasonDuplicateKey},
		{"distinct unknown names", okHead + `,"x":1,"y":2}`, ReasonStructure},
		{"names differing in case are distinct", okHead + `,"x":1,"X":2}`, ReasonStructure},
		{"duplicate inside a value of the wrong type", `{"format":"aleutian.proof.bundle.v1","chains":{"a":1,"a":2}}`, ReasonDuplicateKey},
		{"duplicate at depth 8", okHead + `,"x":[[[[[[{"a":1,"a":2}]]]]]]}`, ReasonDuplicateKey},
		{"the same name in two objects", `{"format":"aleutian.proof.bundle.v1","chains":[{"a":1},{"a":1}]}`, ReasonStructure},
		{"duplicate in an entry", entry(`,"entry_id":""`), ReasonDuplicateKey},
		{"duplicate before a wrong format", `{"format":"no","chains":[],"chains":[]}`, ReasonDuplicateKey},
		{"grammar error after a duplicate", `{"format":"no","chains":[],"chains":[]`, ReasonJSON},

		{"number: integer", okHead + `,"x":12}`, ReasonStructure},
		{"number: negative", okHead + `,"x":-1}`, ReasonStructure},
		{"number: negative zero", okHead + `,"x":-0}`, ReasonStructure},
		{"number: fraction", okHead + `,"x":1.5}`, ReasonStructure},
		{"number: exponent", okHead + `,"x":1e3}`, ReasonStructure},
		{"number: signed exponent", okHead + `,"x":0.0E-10}`, ReasonStructure},
		{"number: leading zero", okHead + `,"x":01}`, ReasonJSON},
		{"number: plus sign", okHead + `,"x":+1}`, ReasonJSON},
		{"number: no integer part", okHead + `,"x":.5}`, ReasonJSON},
		{"number: no fraction digits", okHead + `,"x":1.}`, ReasonJSON},
		{"number: no exponent digits", okHead + `,"x":1e}`, ReasonJSON},
		{"number: sign without exponent digits", okHead + `,"x":1e+}`, ReasonJSON},
		{"number: lone minus", okHead + `,"x":-}`, ReasonJSON},
		{"number: hex", okHead + `,"x":0x1}`, ReasonJSON},
		{"number: NaN", okHead + `,"x":NaN}`, ReasonJSON},

		{"string: raw control character", okHead + ",\"x\":\"a\nb\"}", ReasonJSON},
		{"string: unknown escape", okHead + `,"x":"\x41"}`, ReasonJSON},
		{"string: short unicode escape", okHead + `,"x":"\u12"}`, ReasonJSON},
		{"string: unterminated", okHead + `,"x":"abc`, ReasonJSON},
		{"string: every escape", okHead + `,"x":"\"\\\/\b\f\n\r\t` + u + `00E9` + u + `00e9"}`, ReasonStructure},
		{"string: lone high surrogate escape", okHead + `,"x":"\ud800"}`, ReasonJSON},
		{"string: lone low surrogate escape", okHead + `,"x":"\udc00"}`, ReasonJSON},
		{"string: surrogates reversed", okHead + `,"x":"\udc00\ud800"}`, ReasonJSON},
		{"string: high surrogate, then a character", okHead + `,"x":"\ud800a"}`, ReasonJSON},
		{"string: high surrogate twice", okHead + `,"x":"\ud800\ud800"}`, ReasonJSON},
		{"string: surrogate pair", okHead + `,"x":"` + u + `d83d` + u + `de00"}`, ReasonStructure},
		{"string: lone surrogate in a name", okHead + `,"\ud800":1}`, ReasonJSON},
		{"string: invalid UTF-8", okHead + ",\"x\":\"\xff\"}", ReasonJSON},
		{"string: cut UTF-8 sequence", okHead + ",\"x\":\"\xe2\x82\"}", ReasonJSON},
		{"string: overlong UTF-8", okHead + ",\"x\":\"\xc0\x80\"}", ReasonJSON},
		{"string: raw surrogate bytes", okHead + ",\"x\":\"\xed\xa0\x80\"}", ReasonJSON},
		{"string: past U+10FFFF", okHead + ",\"x\":\"\xf4\x90\x80\x80\"}", ReasonJSON},
		{"string: invalid UTF-8 in a kept value", "{\"format\":\"aleutian.proof.bundle.v1\xff\",\"chains\":[]}", ReasonJSON},
		{"string: raw non-ASCII", okHead + `,"x":"é😀"}`, ReasonStructure},

		{"depth 8", nest(8), ReasonStructure},
		{"depth 9", nest(9), ReasonJSON},
		{"depth 9 of objects", okHead + `,"x":` + strings.Repeat(`{"a":`, 8) + `0` + strings.Repeat(`}`, 8) + `}`, ReasonJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustVerify(t, []byte(c.in), Trust{}, Limits{})
			if got := reasonOf(res); got != c.want {
				t.Fatalf("reason %q, want %q", got, c.want)
			}
		})
	}
}

// Values are compared after unescaping, wherever they are kept.
func TestReader_ValuesAreUnescaped(t *testing.T) {
	entries := eventEntries(2)
	plain := encodeBundle(t, rawChain{id: testChainID(1), entries: entries})
	// Spell the first letter of every hash, id and type as an escape.
	escaped := bytes.ReplaceAll(plain, []byte(`":"s`), []byte(`":"`+u+`0073`))
	if bytes.Equal(plain, escaped) {
		t.Fatal("nothing was escaped")
	}
	for name, data := range map[string][]byte{"plain": plain, "escaped": escaped} {
		res := mustVerify(t, data, Trust{}, Limits{})
		if !res.Readable || res.Verdict != VerdictUnauthenticated || len(res.Chains) != 1 ||
			len(res.Chains[0].Problems) != 0 || res.Chains[0].Counts.Committed != 2 {
			t.Fatalf("%s: %+v", name, res)
		}
	}
}

// Every §5 limit, each one below, at and above its value (bundle-format §15,
// note 1), with limits lowered so that the inputs are small.
func TestLimits_Each(t *testing.T) {
	lim := Limits{Chains: 3, Entries: 5, Checkpoints: 4}
	two := bareBundle(2, 2, 2)
	cases := []struct {
		name string
		in   []byte
		lim  Limits
		want string
	}{
		{"size: at the limit", two, Limits{BundleBytes: len(two)}, ""},
		{"size: one byte over", two, Limits{BundleBytes: len(two) - 1}, ReasonTooLarge},
		{"chains: at the limit", bareBundle(3, 1, 0), lim, ""},
		{"chains: one over", bareBundle(4, 1, 0), lim, ReasonTooLarge},
		{"entries: at the limit, over two chains", bareBundle(2, 2, 0), Limits{Entries: 4}, ""},
		{"entries: one over, over three chains", bareBundle(3, 2, 0), lim, ReasonTooLarge},
		{"entries: one over, in one chain", bareBundle(1, 6, 0), lim, ReasonTooLarge},
		{"checkpoints: at the limit, over two chains", bareBundle(2, 1, 2), lim, ""},
		{"checkpoints: one over, in one chain", bareBundle(1, 1, 5), lim, ReasonTooLarge},
		{"checkpoints: one over, over three chains", bareBundle(3, 1, 2), lim, ReasonTooLarge},
		// 3 + 4 per chain + 8 per bare entry + 1 per checkpoint (§5).
		{"values: at the limit", bareBundle(2, 2, 2), Limits{Values: 3 + 2*4 + 4*8 + 4}, ""},
		{"values: one over", bareBundle(2, 2, 2), Limits{Values: 3 + 2*4 + 4*8 + 3}, ReasonTooLarge},
		{"values: member names are not values", []byte(okHead + `,"a":0,"b":0}`), Limits{Values: 5}, ReasonStructure},
		{"values: every depth counts", []byte(okHead + `,"a":[[0],"s",true,null]}`), Limits{Values: 9}, ReasonStructure},
		{"values: every depth counts, one over", []byte(okHead + `,"a":[[0],"s",true,null]}`), Limits{Values: 8}, ReasonTooLarge},
		{"depth: lowered", []byte(okHead + `,"a":[[]]}`), Limits{Depth: 2}, ReasonJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reasonOf(mustVerify(t, c.in, Trust{}, c.lim)); got != c.want {
				t.Fatalf("reason %q, want %q", got, c.want)
			}
		})
	}
}

// The value limit at its real value: 15,000,000 values are read in a v1
// bundle, one more is not; 17,000,000 in a v2 bundle (§16). The inputs are
// arrays of small numbers, about 30 MB each.
func TestLimits_ValueLimitAtFifteenMillion(t *testing.T) {
	if testing.Short() {
		t.Skip("reads several 30 MB inputs")
	}
	buildAs := func(format string, values int) []byte {
		// The object, format's string, the array, and the numbers in it.
		in := []byte(`{"format":"` + format + `","x":[`)
		in = append(in, bytes.Repeat([]byte("0,"), values-3)...)
		return append(in[:len(in)-1], `]}`...)
	}
	build := func(values int) []byte { return buildAs(FormatV1, values) }
	for format, limit := range map[string]int{FormatV2: valuesV2} {
		if got := reasonOf(mustVerify(t, buildAs(format, limit), Trust{}, Limits{})); got != ReasonStructure {
			t.Fatalf("%s at its limit: %q, want structure", format, got)
		}
		if got := reasonOf(mustVerify(t, buildAs(format, limit+1), Trust{}, Limits{})); got != ReasonTooLarge {
			t.Fatalf("%s one over: %q, want too-large", format, got)
		}
	}
	limit := valuesV1
	if got := reasonOf(mustVerify(t, build(limit), Trust{}, Limits{})); got != ReasonStructure {
		t.Fatalf("at the limit: %q, want structure", got)
	}
	var res Result
	over := build(limit + 1)
	allocated, peak, elapsed := measure(func() { res = mustVerify(t, over, Trust{}, Limits{}) })
	if got := reasonOf(res); got != ReasonTooLarge {
		t.Fatalf("one over the limit: %q, want too-large", got)
	}
	t.Logf("15,000,001 values in %d MB: allocated %d KiB in total, peak %d KiB, in %v",
		len(over)/1e6, allocated>>10, peak>>10, elapsed.Round(time.Millisecond))
}

// One checkpoint's text: 1 MiB is read, one byte more is
// `checkpoint-malformed`, and the bundle stays readable.
func TestLimits_CheckpointText(t *testing.T) {
	entries := eventEntries(2)
	id := testChainID(7)
	text, _, _ := testCheckpoint(t, id, entries, 2, 0, seedAnchorID, seedAnchorHash, nil)
	pad := func(size int) []byte { return []byte(text + strings.Repeat(" ", size-len(text))) }
	limit := DefaultLimits().CheckpointBytes
	for _, c := range []struct {
		name string
		size int
		want string
	}{
		{"as written", len(text), ""},
		{"padded to 1 MiB", limit, ""},
		{"one byte over 1 MiB", limit + 1, "checkpoint-malformed:1:0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := encodeBundle(t, rawChain{id: id, entries: entries, checkpoints: [][]byte{pad(c.size)}})
			res := mustVerify(t, data, Trust{}, Limits{})
			if !res.Readable || len(res.Chains) != 1 {
				t.Fatalf("unreadable: %+v", res)
			}
			if got := problemCodes(res.Chains[0].Problems); got != c.want {
				t.Fatalf("problems %q, want %q", got, c.want)
			}
		})
	}
	// The limit counts the text's UTF-8 bytes, not the bytes that spell it:
	// a text of escapes is six times longer in the bundle than it is.
	escaped := `"` + strings.Repeat(u+`0020`, 40) + `"`
	data := []byte(`{"format":"aleutian.proof.bundle.v1","chains":[{"chain_id":"` + id + `","entries":[` + bareEntry +
		`],"checkpoints":[` + escaped + `]}]}`)
	r := newReader(data, Limits{CheckpointBytes: 40}.withDefaults())
	r.build = true
	if !r.document() || len(r.chains) != 1 || len(r.chains[0].checkpoints[0]) != 40 {
		t.Fatalf("a 40-byte text spelled in 240 bytes was not kept under a 40-byte limit")
	}
	r = newReader(data, Limits{CheckpointBytes: 39}.withDefaults())
	r.build = true
	if !r.document() || r.chains[0].checkpoints[0] != nil {
		t.Fatalf("a 40-byte text was kept under a 39-byte limit")
	}
}

// §9.1: every reason that applies is found, and the lowest-numbered one is
// reported, whatever order the reader met them in. Each case holds two or
// more reasons.
func TestLimits_Precedence(t *testing.T) {
	// Five values, then a value past a limit of 5.
	overValues := `{"format":"aleutian.proof.bundle.v1","chains":[],"a":0,"b":0,"c":0`
	valueLimit := Limits{Values: 5}
	countLimit := Limits{Chains: 1}
	twoChains := string(bareBundle(2, 1, 0))
	cases := []struct {
		name string
		in   string
		lim  Limits
		want string
	}{
		{"1 size over 2 json", `{"format":`, Limits{BundleBytes: 4}, ReasonTooLarge},
		{"1 size over 4 duplicate", `{"a":1,"a":2}`, Limits{BundleBytes: 4}, ReasonTooLarge},
		{"2 json over 3 values, json last", overValues, valueLimit, ReasonJSON},
		{"2 json over 3 values, json far behind", overValues + `,"d":[0,0,0,0,0,0,0,0],"e":tru}`, valueLimit, ReasonJSON},
		{"2 json over 4 duplicate", `{"a":1,"a":2`, Limits{}, ReasonJSON},
		{"2 json over 5 format", `{"format":"no"`, Limits{}, ReasonJSON},
		{"2 json over 6 structure", `[1,2,]`, Limits{}, ReasonJSON},
		{"2 json over 7 count", twoChains + `]`, countLimit, ReasonJSON},
		{"2 json (depth) over 6 structure", `[[[[[[[[[]]]]]]]]]`, Limits{}, ReasonJSON},
		{"3 values over 4 duplicate, duplicate first", `{"a":0,"a":0,"b":[0,0,0,0,0]}`, valueLimit, ReasonTooLarge},
		{"3 values over 4 duplicate, duplicate last", overValues + `,"c":0}`, valueLimit, ReasonTooLarge},
		{"3 values over 5 format", `{"format":"no","chains":[],"a":0,"b":0,"c":0}`, valueLimit, ReasonTooLarge},
		{"3 values over 6 structure", overValues + `}`, valueLimit, ReasonTooLarge},
		{"4 duplicate over 5 format", `{"format":"no","format":"no","chains":[]}`, Limits{}, ReasonDuplicateKey},
		{"4 duplicate over 5 format, format missing", `{"chains":[],"chains":[]}`, Limits{}, ReasonDuplicateKey},
		{"4 duplicate over 6 structure", `[{"a":1,"a":2}]`, Limits{}, ReasonDuplicateKey},
		{"4 duplicate over 7 count", strings.TrimSuffix(twoChains, "}") + `,"chains":[]}`, countLimit, ReasonDuplicateKey},
		{"4 duplicate (in the last chain) over 7 count", strings.Replace(twoChains, `"checkpoints":[]}]}`, `"checkpoints":[],"checkpoints":[]}]}`, 1), countLimit, ReasonDuplicateKey},
		{"5 format over 6 structure", `{"format":"no","chains":[{}],"x":1}`, Limits{}, ReasonFormat},
		{"5 format (missing) over 6 structure", `{"chains":[{}]}`, Limits{}, ReasonFormat},
		{"5 format over 7 count", strings.Replace(twoChains, FormatV1, "no", 1), countLimit, ReasonFormat},
		{"5 format (after the chains) over 7 count", `{"chains":` + twoChains[len(`{"format":"`+FormatV1+`","chains":`):len(twoChains)-1] + `,"format":"no"}`, countLimit, ReasonFormat},
		{"6 structure over 7 count, structure last", strings.TrimSuffix(twoChains, "}") + `,"x":1}`, countLimit, ReasonStructure},
		{"6 structure over 7 count, structure first", strings.Replace(twoChains, `"entries":[`+bareEntry+`]`, `"entries":[]`, 1), countLimit, ReasonStructure},
		{"7 count alone", twoChains, countLimit, ReasonTooLarge},
		{"7 entry count alone", string(bareBundle(1, 3, 0)), Limits{Entries: 2}, ReasonTooLarge},
		{"7 checkpoint count alone", string(bareBundle(1, 1, 3)), Limits{Checkpoints: 2}, ReasonTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reasonOf(mustVerify(t, []byte(c.in), Trust{}, c.lim)); got != c.want {
				t.Fatalf("reason %q, want %q", got, c.want)
			}
		})
	}
}

// A hostile input inside the size limit costs memory in proportion to the
// input at worst, and nearly none once a structure violation is known: after
// it nothing is built. Each input is 16 MiB.
func TestReader_HostileInputMemory(t *testing.T) {
	const size = 16 << 20
	fill := func(head, unit, tail string) []byte {
		out := make([]byte, 0, size)
		out = append(out, head...)
		for len(out)+len(unit)+len(tail) <= size {
			out = append(out, unit...)
		}
		out = out[:len(out)-1] // the last unit's comma
		return append(out, tail...)
	}
	numbered := func() []byte {
		out := make([]byte, 0, size)
		out = append(out, '{')
		for i := 0; len(out)+16 <= size; i++ {
			out = fmt.Appendf(out, `"k%07d":0,`, i)
		}
		out[len(out)-1] = '}'
		return out
	}
	cases := []struct {
		name string
		in   []byte
		want string
		// most is the most the reader may allocate, in total, in bytes.
		most uint64
	}{
		{"chains of empty objects", fill(`{"format":"`+FormatV1+`","chains":[`, `{},`, `]}`), ReasonStructure, 64 << 10},
		{"top-level array of empty objects", fill(`[`, `{},`, `]`), ReasonStructure, 64 << 10},
		{"top-level numbers", fill(``, `0,`, ``), ReasonJSON, 64 << 10},
		{"array of numbers", fill(`[`, `0,`, `]`), ReasonStructure, 64 << 10},
		{"array of empty arrays", fill(`[`, `[],`, `]`), ReasonStructure, 64 << 10},
		{"one name repeated", fill(`{`, `"a":0,`, `}`), ReasonDuplicateKey, 1 << 20},
		{"entries of empty objects", fill(`{"format":"`+FormatV1+`","chains":[{"chain_id":"c","entries":[`, `{},`, `],"checkpoints":[]}]}`), ReasonStructure, 64 << 10},
		// Built up to the checkpoint limit, then dropped.
		{"checkpoints of empty strings", fill(`{"format":"`+FormatV1+`","chains":[{"chain_id":"c","entries":[`+bareEntry+`],"checkpoints":[`, `"",`, `]}]}`), ReasonTooLarge, size},
		// Distinct unknown names must be remembered until the object closes:
		// 4 bytes each, a quarter of the input here, in a slice that grows:
		// the total counts every size it went through, about six times what
		// is held at the end.
		{"distinct unknown names", numbered(), ReasonFormat, 2 * size},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var res Result
			allocated, peak, elapsed := measure(func() { res = mustVerify(t, c.in, Trust{}, Limits{}) })
			if got := reasonOf(res); got != c.want {
				t.Fatalf("reason %q, want %q", got, c.want)
			}
			t.Logf("%d-byte input: allocated %d KiB in total, peak %d KiB, in %v",
				len(c.in), allocated>>10, peak>>10, elapsed.Round(time.Millisecond))
			if allocated > c.most {
				t.Fatalf("allocated %d bytes for a %d-byte input, want at most %d", allocated, len(c.in), c.most)
			}
		})
	}
}

// A chain id far longer than any valid one is not held: it is compared by
// digest, and two chains with the same long id are still duplicates (§8).
func TestReader_LongChainID(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	chainWith := func(id string) string {
		return `{"chain_id":"` + id + `","entries":[` + bareEntry + `],"checkpoints":[]}`
	}
	data := []byte(`{"format":"` + FormatV1 + `","chains":[` + chainWith(long) + `,` + chainWith(long+"b") + `,` +
		chainWith(u+`0061`+long[1:]) + `]}`)
	var res Result
	allocated, _, _ := measure(func() { res = mustVerify(t, data, Trust{}, Limits{}) })
	if !res.Readable || problemCodes(res.BundleProblems) != "duplicate-chain:1:2" {
		t.Fatalf("bundle problems %q, want the third chain a duplicate of the first", problemCodes(res.BundleProblems))
	}
	for i, c := range res.Chains {
		if c.Key != fmt.Sprintf("#%d", i) {
			t.Fatalf("chain %d keyed %q", i, c.Key)
		}
	}
	if allocated > 256<<10 {
		t.Fatalf("allocated %d bytes for three 1 MiB chain ids", allocated)
	}
}
