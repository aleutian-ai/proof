// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/fixtures"
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

// readAll drains an EntryReader.
func readAll(r io.Reader) ([]Entry, error) {
	rd := NewEntryReader(r)
	var out []Entry
	for {
		e, err := rd.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
}

// TestEntryReader_AgreesWithDecodeEntries: the streaming reader is held to
// DecodeEntries on every input this package has an opinion about: the
// conformance vectors' text cases and the cases above. The same entries, or an
// error for the same inputs; for JSONL, the same error text. Read a byte at a
// time as well, so nothing depends on where a read happens to end.
func TestEntryReader_AgreesWithDecodeEntries(t *testing.T) {
	entries, _ := buildChain(t, 3)
	var lines []string
	for _, e := range entries {
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	g := lines[0]
	array, _ := json.Marshal(entries)
	inputs := map[string]string{
		"array":                         string(array),
		"array, indented":               mustIndent(t, entries),
		"array, white space around":     " \n\t" + string(array) + "\n \n",
		"jsonl":                         strings.Join(lines, "\n"),
		"jsonl, final newline":          strings.Join(lines, "\n") + "\n",
		"jsonl, CRLF":                   strings.Join(lines, "\r\n") + "\r\n",
		"jsonl with blank lines":        "\n" + strings.Join(lines, "\n\n") + "\n",
		"jsonl, leading blank lines":    "\n  \n\t\n" + strings.Join(lines, "\n"),
		"an unknown member":             `[` + strings.Replace(g, `{`, `{"company":"x",`, 1) + `]`,
		"empty":                         "",
		"white space":                   "  \n",
		"an empty object":               `{}`,
		"null":                          `null`,
		"an empty array":                `[]`,
		"an empty array, spaced":        "[ ]\n",
		"an array of null":              `[null]`,
		"an array of numbers":           `[1,2]`,
		"an export bundle":              `{"format":"aleutian.proof.bundle.v1","chains":[]}`,
		"an anchor":                     `{"version":6,"subject":"s","chain_hash":"aa","entry_count":1}`,
		"a member twice":                strings.Replace(g, `"global_seq":`, `"global_seq":7,"global_seq":`, 1),
		"a member in another case":      strings.Replace(g, `"chain_hash":`, `"CHAIN_HASH":`, 1),
		"no chain_hash":                 strings.Replace(g, `"chain_hash":`, `"other":`, 1),
		"a member of another type":      strings.Replace(g, `"global_seq":0`, `"global_seq":"0"`, 1),
		"two objects on one line":       g + g,
		"a bad second line":             g + "\n\n{}\n" + lines[1],
		"a bad line after blank lines":  "\n\n" + g + "\n\nnull\n",
		"an array that is not JSON":     `[` + g,
		"an array with no comma":        `[` + g + ` ` + lines[1] + `]`,
		"an array with a trailing one":  `[` + g + `,]`,
		"an array followed by more":     `[` + g + `] x`,
		"an array followed by an array": `[` + g + `][` + g + `]`,
		"an array with a bad entry":     `[` + g + `,{}]`,
		"an array on a JSONL line":      g + "\n[" + g + "]",
	}
	var v struct {
		EntriesTextCases []struct {
			Name string `json:"name"`
			Text string `json:"text"`
		} `json:"entries_text_cases"`
	}
	if err := json.Unmarshal(fixtures.VerifyVerdictVectors(), &v); err != nil {
		t.Fatalf("decode the verdict vectors: %v", err)
	}
	if len(v.EntriesTextCases) == 0 {
		t.Fatal("the verdict vectors hold no entries text cases")
	}
	for _, c := range v.EntriesTextCases {
		inputs["vector/"+c.Name] = c.Text
	}

	for name, raw := range inputs {
		t.Run(name, func(t *testing.T) {
			want, wantErr := DecodeEntries([]byte(raw))
			for how, r := range map[string]io.Reader{
				"whole":            strings.NewReader(raw),
				"a byte at a time": iotest.OneByteReader(strings.NewReader(raw)),
			} {
				got, err := readAll(r)
				if (err == nil) != (wantErr == nil) {
					t.Fatalf("%s: EntryReader error = %v, DecodeEntries error = %v", how, err, wantErr)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s: EntryReader read %d entries that differ from DecodeEntries' %d", how, len(got), len(want))
				}
				jsonl := !strings.HasPrefix(strings.TrimSpace(raw), "[")
				if err != nil && jsonl && err.Error() != wantErr.Error() {
					t.Errorf("%s: EntryReader said %q, DecodeEntries said %q", how, err, wantErr)
				}
				if err != nil && strings.Contains(err.Error(), entries[0].ChainHash) {
					t.Errorf("%s: the error quotes a value from the input", how)
				}
			}
		})
	}
}

func mustIndent(t *testing.T, v []Entry) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEntryReader_ErrorsAreFinal: after an error, Next keeps returning it, so
// a caller that loops cannot read past a fault into what follows it. A read
// failure is reported as one, not as a file that is not entries.
func TestEntryReader_ErrorsAreFinal(t *testing.T) {
	entries, _ := buildChain(t, 2)
	a, _ := json.Marshal(entries[0])
	b, _ := json.Marshal(entries[1])

	rd := NewEntryReader(strings.NewReader(string(a) + "\n{}\n" + string(b) + "\n"))
	if _, err := rd.Next(); err != nil {
		t.Fatalf("first entry: %v", err)
	}
	_, first := rd.Next()
	if first == nil || !strings.Contains(first.Error(), "line 2") {
		t.Fatalf("second line: error = %v, want one naming line 2", first)
	}
	if e, again := rd.Next(); again != first {
		t.Errorf("after an error Next returned %+v, %v", e, again)
	}

	broken := errors.New("the disk went away")
	for name, head := range map[string]string{"jsonl": string(a) + "\n", "array": "[" + string(a) + ","} {
		rd := NewEntryReader(io.MultiReader(strings.NewReader(head), iotest.ErrReader(broken)))
		if _, err := rd.Next(); err != nil {
			t.Fatalf("%s: first entry: %v", name, err)
		}
		if _, err := rd.Next(); !errors.Is(err, broken) {
			t.Errorf("%s: error = %v, want the read error", name, err)
		}
	}
}

// TestEntryReader_BoundsALine: one line with no end is not read into memory.
func TestEntryReader_BoundsALine(t *testing.T) {
	entries, _ := buildChain(t, 1)
	good, _ := json.Marshal(entries[0])

	long := strings.Replace(string(good), `{`, `{"pad":"`+strings.Repeat("x", MaxEntryLineBytes)+`",`, 1)
	_, err := readAll(strings.NewReader(string(good) + "\n" + long + "\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2 is longer than") {
		t.Fatalf("error = %v, want one naming line 2 as too long", err)
	}
	if len(err.Error()) > 200 {
		t.Errorf("the error is %d bytes: it carries the line", len(err.Error()))
	}

	// Just under the cap is read.
	pad := MaxEntryLineBytes - len(good) - len(`"pad":"",`)
	fits := strings.Replace(string(good), `{`, `{"pad":"`+strings.Repeat("x", pad)+`",`, 1)
	if got, err := readAll(strings.NewReader(fits + "\n")); err != nil || len(got) != 1 {
		t.Errorf("a line of %d bytes: %d entries, %v", len(fits), len(got), err)
	}
}

// TestEntryReader_WalksALongChainInBoundedMemory: a chain read through an
// EntryReader into a Walker is verified, and bound to its anchor, without
// holding it. The input is generated as it is read, so the only memory that
// could grow with the chain is the reader's and the walker's.
func TestEntryReader_WalksALongChainInBoundedMemory(t *testing.T) {
	const n = 200_000
	pr, pw := io.Pipe()
	type made struct {
		first, last Entry
		bytes       int64
	}
	done := make(chan made, 1)
	go func() {
		var m made
		prev := ""
		enc := json.NewEncoder(&countingWriter{w: pw, n: &m.bytes})
		for i := 0; i < n; i++ {
			ts := base().Add(time.Duration(i) * time.Millisecond)
			e := Entry{
				EntryID:       fmt.Sprintf("ent_%07d", i),
				EntryType:     "capture.request.v3",
				Timestamp:     ts.Format(TimestampLayout),
				GlobalSeq:     int64(i),
				FormatVersion: chainformat.FormatV3,
				ContentHash:   strings.Repeat("0123456789abcdef", 8),
			}
			e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, e.ContentHash)
			prev = e.ChainHash
			if i == 0 {
				m.first = e
			}
			m.last = e
			if err := enc.Encode(e); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.Close()
		done <- m
	}()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	rd := NewEntryReader(pr)
	w := NewWalker(Options{})
	for {
		e, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("entry %d: %v", w.Count(), err)
		}
		w.Add(e)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	m := <-done

	res := w.Result()
	if res.Verdict != VerdictIntact || res.EntriesVerified != n {
		t.Fatalf("verdict %s over %d entries, want INTACT over %d", res.Verdict, res.EntriesVerified, n)
	}
	a := anchorOver(t, []Entry{m.first, m.last}, m.last.ChainHash, anchor.SeedAnchorHash)
	a.EntryCount, a.VerifiedThrough = n, n
	bound, err := w.BindAnchor(a, Expect{PreviousAnchorHash: anchor.SeedAnchorHash})
	if err != nil || !bound.Bound {
		t.Fatalf("bind: %+v, %v", bound, err)
	}

	// Held after the walk, against the size of what was read.
	var held int64
	if after.HeapAlloc > before.HeapAlloc {
		held = int64(after.HeapAlloc - before.HeapAlloc)
	}
	if limit := m.bytes / 50; held > limit {
		t.Errorf("the walk holds %d bytes after reading %d; want under %d", held, m.bytes, limit)
	}
	t.Logf("read %d bytes in %d entries; heap grew by %d bytes", m.bytes, n, held)
}

// countingWriter counts what passes through it.
type countingWriter struct {
	w io.Writer
	n *int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	*c.n += int64(n)
	return n, err
}

// TestWalkerBindAnchor_AgreesWithBindAnchor: binding through a walker that was
// fed the entries one at a time gives the result BindAnchor gives for the
// slice, on every bind case of the conformance vectors.
func TestWalkerBindAnchor_AgreesWithBindAnchor(t *testing.T) {
	var v struct {
		BindCases []struct {
			Name               string          `json:"name"`
			Entries            []Entry         `json:"entries"`
			Anchor             json.RawMessage `json:"anchor"`
			PreviousAnchorHash string          `json:"previous_anchor_hash"`
		} `json:"bind_cases"`
	}
	if err := json.Unmarshal(fixtures.VerifyVerdictVectors(), &v); err != nil {
		t.Fatalf("decode the verdict vectors: %v", err)
	}
	if len(v.BindCases) == 0 {
		t.Fatal("the verdict vectors hold no bind cases")
	}
	for _, c := range v.BindCases {
		t.Run(c.Name, func(t *testing.T) {
			var a anchor.Anchor
			if err := json.Unmarshal(c.Anchor, &a); err != nil {
				t.Fatalf("the case's anchor does not parse: %v", err)
			}
			want, wantErr := BindAnchor(a, c.Entries, Expect{PreviousAnchorHash: c.PreviousAnchorHash})
			// Any break limit that keeps the first break binds alike.
			for _, max := range []int{0, 1, 5} {
				w := NewWalker(Options{MaxBreaks: max})
				for _, e := range c.Entries {
					w.Add(e)
				}
				got, err := w.BindAnchor(a, Expect{PreviousAnchorHash: c.PreviousAnchorHash})
				if (err == nil) != (wantErr == nil) || (err != nil && err.Error() != wantErr.Error()) {
					t.Fatalf("MaxBreaks %d: error = %v, BindAnchor's = %v", max, err, wantErr)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("MaxBreaks %d: got %+v\nBindAnchor gave %+v", max, got, want)
				}
			}
		})
	}
	if _, err := NewWalker(Options{}).BindAnchor(anchor.Anchor{}, Expect{PreviousAnchorHash: anchor.SeedAnchorHash}); !errors.Is(err, ErrNoEntries) {
		t.Errorf("a walker with no entries: error = %v, want ErrNoEntries", err)
	}
}

// TestDecodeEntries_NoSecondSpellingThroughUnicodeFolding: a member whose name
// folds to one of the format's (U+017F "ſ" folds to "s")
// is refused, and no value ever reaches a field through encoding/json's own
// folding name match. The decoder once checked names with strings.ToLower and
// then decoded the whole object: {"timestamp": A, "timeſtamp": B} was accepted
// and the entry carried B.
func TestDecodeEntries_NoSecondSpellingThroughUnicodeFolding(t *testing.T) {
	entries, _ := buildChain(t, 1)
	good, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	g := string(good)
	for name, raw := range map[string]string{
		"long s beside the real name": strings.Replace(g, `"timestamp":`, `"timestamp":"2026-01-01T00:00:00.000000Z","timeſtamp":`, 1),
		"long s in place of the name": strings.Replace(g, `"timestamp":`, `"timeſtamp":`, 1),
		"long s in another member":    strings.Replace(g, `"content_hash":`, `"content_hash":"`+entries[0].ContentHash+`","content_ha\u017fh":`, 1),
		"upper case beside the name":  strings.Replace(g, `"entry_id":`, `"entry_id":"x","ENTRY_ID":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			for _, text := range []string{raw, "[" + raw + "]"} {
				if got, err := DecodeEntries([]byte(text)); err == nil {
					t.Fatalf("decoded %+v", got)
				}
				r := NewEntryReader(strings.NewReader(text))
				if _, err := r.Next(); err == nil {
					t.Fatal("the streaming reader accepted it")
				}
			}
		})
	}
	// Control: the exact names decode, and to the values under those names.
	got, err := DecodeEntries(good)
	if err != nil || got[0] != entries[0] {
		t.Fatalf("control: %+v, %v", got, err)
	}
}
