// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/aleutian-ai/proof/chainformat"
)

// entryMembers are the members of an exported entry, by their exact names.
// Under Unicode case folding, they are how another spelling of a member is
// recognised.
var entryMembers = map[string]bool{
	"entry_id": true, "entry_type": true, "timestamp": true, "format_version": true,
	"run_id": true, "sequence_num": true, "global_seq": true, "content_hash": true,
	"chain_hash": true, "salt": true, "leaf_hash": true, "erased": true,
}

// requiredEntryMembers are the members every v2 and v3 entry carries. A v4
// entry is required to carry only timestamp and chain_hash here: which other
// members it has depends on whether it is erased, and a v4 entry of the wrong
// shape is a break the walker reports (format-spec §2.0), not a file that is
// not entries.
var requiredEntryMembers = []string{"entry_id", "timestamp", "content_hash", "chain_hash"}
var requiredEntryMembersV4 = []string{"timestamp", "chain_hash"}

// memberBits maps the members whose presence the walker judges to their bit.
var memberBits = map[string]memberSet{
	"entry_id": memberEntryID, "entry_type": memberEntryType, "run_id": memberRunID,
	"sequence_num": memberSequenceNum, "content_hash": memberContentHash, "salt": memberSalt,
	"leaf_hash": memberLeafHash, "erased": memberErased,
}

// DecodeEntries reads exported entries: a JSON array of entry objects, or one
// entry object per line (JSONL).
//
// # Description
//
// The shape is sniffed, so a caller verifying a file someone handed them need
// not know which it is. What is read must be entries: a file that is some other
// JSON (an anchor, an export bundle, `{}`, `null`) is an ERROR, not a chain to
// verify. Read leniently, such a file became one entry with every field empty,
// and the verdict was BROKEN: a tamper finding about a file that was never a
// chain.
//
// Each entry is an object that carries entry_id, timestamp, content_hash and
// chain_hash (a v4 entry: timestamp and chain_hash; format-spec §2.0), has no
// member twice, and has no member whose name folds (Unicode
// case folding) to one of the format's without being it. encoding/json alone would take the last of a
// repeated member and match names without regard to case, so two readers could
// see two different entries in one file. Members the format does not define
// are ignored: none of them is hashed, and exports from other producers carry
// some.
//
// # Inputs
//
//   - raw: the file's bytes
//
// # Outputs
//
//   - []Entry: the entries, in file order; never empty when err is nil
//   - error: why the input is not entries. It names positions and member names
//     and never quotes a value.
//
// # Example
//
//	entries, err := verify.DecodeEntries(raw)
//	if err != nil {
//	    return err // not a chain: nothing to verify
//	}
//	res, err := verify.Chain(entries, verify.Options{})
//
// # Limitations
//
//   - Holds the whole input and every entry in memory. [EntryReader] reads the
//     same input one entry at a time.
//   - Member values are decoded by encoding/json: invalid UTF-8 in a string is
//     repaired, not refused.
//
// # Assumptions
//
//   - None.
func DecodeEntries(raw []byte) ([]Entry, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("the input is empty")
	}
	var docs []json.RawMessage
	where := func(i int) string { return fmt.Sprintf("entry %d", i) }
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &docs); err != nil {
			return nil, errors.New("the input is not a valid JSON array of entries")
		}
	} else {
		where = func(i int) string { return fmt.Sprintf("line %d", i+1) }
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			docs = append(docs, bytes.TrimSpace(line))
		}
	}
	entries := make([]Entry, 0, len(docs))
	for i, doc := range docs {
		if len(doc) == 0 && trimmed[0] != '[' {
			continue // a blank line in JSONL
		}
		e, err := decodeEntry(doc)
		if err != nil {
			return nil, fmt.Errorf("%s is not an entry: %w", where(i), err)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, errors.New("the input holds no entries")
	}
	return entries, nil
}

// decodeEntry reads one entry object, refusing repeated members, a member
// that is another spelling of one of the format's, and an object that lacks
// what every entry has.
//
// Values are taken by EXACT member name and never through encoding/json's own
// name matching, which folds case and Unicode (it reads "timeſtamp", with
// U+017F, as "timestamp"). Checking names with strings.ToLower and then
// decoding the whole object let such a second spelling through, and its value
// won. A member whose name folds to one of the format's without being it is
// now refused, and the fields are filled from the exact names alone.
func decodeEntry(doc []byte) (Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return Entry{}, errors.New("it is not a JSON object")
	}
	values := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return Entry{}, errors.New("it is not valid JSON")
		}
		if !entryMembers[name] {
			if known, folds := foldsToMember(name); folds {
				return Entry{}, fmt.Errorf("a member is another spelling of %q", known)
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return Entry{}, errors.New("it is not valid JSON")
		}
		if entryMembers[name] {
			if _, dup := values[name]; dup {
				return Entry{}, fmt.Errorf("the member %q appears twice", name)
			}
			values[name] = value
		}
	}
	if _, err := dec.Token(); err != nil {
		return Entry{}, errors.New("it is not valid JSON")
	}
	if dec.More() {
		return Entry{}, errors.New("it is followed by more data")
	}
	for _, name := range requiredEntryMembersV4 {
		if _, ok := values[name]; !ok {
			return Entry{}, fmt.Errorf("it has no %q", name)
		}
	}
	var e Entry
	for name, value := range values {
		if err := unmarshalMember(&e, name, value); err != nil {
			return Entry{}, fmt.Errorf("the member %q has the wrong JSON type", name)
		}
	}
	// Record the members that are present with their zero value, where that
	// is a break in this entry's format and the value alone cannot show it.
	// Every other entry decodes with no record, equal to one built in Go.
	zeroBreaks := memberSalt | memberLeafHash | memberErased
	if e.FormatVersion == chainformat.FormatV4 {
		zeroBreaks = memberRunID | memberSequenceNum | memberEntryID | memberEntryType |
			memberContentHash | memberSalt | memberErased
	}
	for name := range values {
		if bit := memberBits[name]; bit&zeroBreaks != 0 && !e.has(bit) {
			e.members |= bit
		}
	}
	if e.FormatVersion == chainformat.FormatV4 {
		return e, nil
	}
	for _, name := range requiredEntryMembers {
		if _, ok := values[name]; !ok {
			return Entry{}, fmt.Errorf("it has no %q", name)
		}
	}
	return e, nil
}

// unmarshalMember decodes one member's value into the entry field it names.
// name is one of entryMembers, exactly.
func unmarshalMember(e *Entry, name string, value json.RawMessage) error {
	switch name {
	case "entry_id":
		return json.Unmarshal(value, &e.EntryID)
	case "entry_type":
		return json.Unmarshal(value, &e.EntryType)
	case "timestamp":
		return json.Unmarshal(value, &e.Timestamp)
	case "format_version":
		return json.Unmarshal(value, &e.FormatVersion)
	case "run_id":
		return json.Unmarshal(value, &e.RunID)
	case "sequence_num":
		return json.Unmarshal(value, &e.SequenceNum)
	case "global_seq":
		return json.Unmarshal(value, &e.GlobalSeq)
	case "content_hash":
		return json.Unmarshal(value, &e.ContentHash)
	case "chain_hash":
		return json.Unmarshal(value, &e.ChainHash)
	case "salt":
		return json.Unmarshal(value, &e.Salt)
	case "leaf_hash":
		return json.Unmarshal(value, &e.LeafHash)
	case "erased":
		return json.Unmarshal(value, &e.Erased)
	}
	return fmt.Errorf("no member %q", name)
}

// foldsToMember reports whether name is one of the format's member names under
// Unicode case folding, and which. Called only for a name that is not one
// exactly.
func foldsToMember(name string) (string, bool) {
	for known := range entryMembers {
		if strings.EqualFold(name, known) {
			return known, true
		}
	}
	return "", false
}

// MaxEntryLineBytes is the longest JSONL line an [EntryReader] reads. An entry
// is a few hundred bytes; the cap is what keeps one endless line from being
// read into memory whole.
const MaxEntryLineBytes = 1 << 20

// errNotAnArray is what any fault in a JSON array's own syntax reports.
var errNotAnArray = errors.New("the input is not a valid JSON array of entries")

// EntryReader reads exported entries one at a time: [DecodeEntries], streamed.
//
// # Description
//
// DecodeEntries holds the input and every entry in memory. An EntryReader
// holds one entry, so a caller can walk a chain of any length by feeding each
// entry to a [Walker] as it is read. It accepts the same two shapes, sniffed
// the same way (a JSON array of entry objects, or one entry object per line),
// and applies the same rules to each entry: the required members, no member
// twice, no member in another case. Input that is not entries is an error
// from Next, never an entry.
//
// # Thread Safety
//
// Not safe for concurrent use.
type EntryReader struct {
	br      *bufio.Reader
	started bool
	array   bool
	dec     *json.Decoder // array input only
	line    int           // JSONL: lines read, counted from the first that is not blank
	entries int           // entries returned so far
	buf     []byte        // JSONL: the current line, reused
	err     error         // sticky: what Next returned last, once it is not nil
}

// NewEntryReader returns a reader of the exported entries in r.
//
// # Description
//
// Nothing is read until the first call to Next.
//
// # Inputs
//
//   - r: a JSON array of entry objects, or JSONL
//
// # Outputs
//
//   - *EntryReader: call Next until it returns io.EOF
//
// # Example
//
//	rd := verify.NewEntryReader(file)
//	w := verify.NewWalker(verify.Options{})
//	for {
//	    e, err := rd.Next()
//	    if err == io.EOF {
//	        break
//	    }
//	    if err != nil {
//	        return err // not a chain: there is no verdict to report
//	    }
//	    w.Add(e)
//	}
//	res := w.Result()
//
// # Limitations
//
//   - A fault is found when it is reached, so entries before it have already
//     been returned. A caller must discard what it built from them: an error
//     from Next means the input is not entries, whatever came first.
//   - A JSONL line longer than [MaxEntryLineBytes] is an error. One element of
//     a JSON array is held whole, whatever its size.
//   - Where an array is faulty in two ways, the error may name a different one
//     than DecodeEntries does: this reader reports the first it reaches.
//
// # Assumptions
//
//   - r is not read by anyone else while the EntryReader is in use.
func NewEntryReader(r io.Reader) *EntryReader {
	return &EntryReader{br: bufio.NewReaderSize(r, 64<<10)}
}

// Next returns the next entry.
//
// # Description
//
// Reads one array element or one line that is not blank, and checks it as
// DecodeEntries checks each entry.
//
// # Inputs
//
//   - none
//
// # Outputs
//
//   - Entry: the entry, when err is nil
//   - error: io.EOF after the last entry of an input that held at least one;
//     otherwise why the input is not entries, or the read error. It names
//     positions and member names and never quotes a value. Once Next returns
//     an error it returns the same one on every later call.
//
// # Example
//
//	e, err := rd.Next()
//	if err == io.EOF {
//	    // every entry has been read
//	}
//
// # Limitations
//
//   - As [NewEntryReader]'s.
//
// # Assumptions
//
//   - None.
func (d *EntryReader) Next() (Entry, error) {
	if d.err != nil {
		return Entry{}, d.err
	}
	e, err := d.next()
	if err == io.EOF && d.entries == 0 {
		err = errors.New("the input holds no entries")
	}
	if err != nil {
		d.err = err
		return Entry{}, err
	}
	d.entries++
	return e, nil
}

// next is Next without the bookkeeping.
func (d *EntryReader) next() (Entry, error) {
	if !d.started {
		if err := d.start(); err != nil {
			return Entry{}, err
		}
	}
	if d.array {
		return d.nextElement()
	}
	return d.nextLine()
}

// start skips leading white space and sniffs the shape from the first byte
// after it, as DecodeEntries does.
func (d *EntryReader) start() error {
	d.started = true
	if err := skipSpace(d.br); err == io.EOF {
		return errors.New("the input is empty")
	} else if err != nil {
		return fmt.Errorf("read the input: %w", err)
	}
	first, err := d.br.Peek(1)
	if err != nil {
		return fmt.Errorf("read the input: %w", err)
	}
	if first[0] != '[' {
		return nil
	}
	d.array = true
	d.dec = json.NewDecoder(d.br)
	if _, err := d.dec.Token(); err != nil {
		return arrayFault(err)
	}
	return nil
}

// nextElement reads one element of a JSON array, or finishes the array.
func (d *EntryReader) nextElement() (Entry, error) {
	if d.dec.More() {
		var doc json.RawMessage
		if err := d.dec.Decode(&doc); err != nil {
			return Entry{}, arrayFault(err)
		}
		e, err := decodeEntry(doc)
		if err != nil {
			return Entry{}, fmt.Errorf("entry %d is not an entry: %w", d.entries, err)
		}
		return e, nil
	}
	if tok, err := d.dec.Token(); err != nil || tok != json.Delim(']') {
		return Entry{}, arrayFault(err)
	}
	// Nothing but white space may follow the array.
	rest := bufio.NewReader(io.MultiReader(d.dec.Buffered(), d.br))
	if err := skipSpace(rest); err == nil {
		return Entry{}, errNotAnArray
	} else if err != io.EOF {
		return Entry{}, fmt.Errorf("read the input: %w", err)
	}
	return Entry{}, io.EOF
}

// nextLine reads the next JSONL line that is not blank.
func (d *EntryReader) nextLine() (Entry, error) {
	for {
		line, err := d.readLine()
		if err == io.EOF && len(line) == 0 {
			return Entry{}, io.EOF
		}
		if err != nil && err != io.EOF {
			return Entry{}, err
		}
		d.line++
		doc := bytes.TrimSpace(line)
		if len(doc) == 0 {
			continue
		}
		e, derr := decodeEntry(doc)
		if derr != nil {
			return Entry{}, fmt.Errorf("line %d is not an entry: %w", d.line, derr)
		}
		return e, nil
	}
}

// readLine returns the next line without its newline, in a buffer the next
// call reuses. It returns io.EOF with the last line when that line has no
// newline, and with no bytes when nothing is left.
func (d *EntryReader) readLine() ([]byte, error) {
	d.buf = d.buf[:0]
	for {
		chunk, err := d.br.ReadSlice('\n')
		d.buf = append(d.buf, chunk...)
		if len(d.buf) > MaxEntryLineBytes+1 {
			return nil, fmt.Errorf("line %d is longer than %d bytes", d.line+1, MaxEntryLineBytes)
		}
		switch err {
		case nil:
			return d.buf[:len(d.buf)-1], nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			return d.buf, io.EOF
		default:
			return nil, fmt.Errorf("read the input: %w", err)
		}
	}
}

// arrayFault is the error for an array that could not be read: the read error
// when the reader failed, and otherwise that the input is not a valid array.
func arrayFault(err error) error {
	var syntax *json.SyntaxError
	if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF || errors.As(err, &syntax) {
		return errNotAnArray
	}
	return fmt.Errorf("read the input: %w", err)
}

// skipSpace consumes white space, as bytes.TrimSpace defines it, and stops
// before the first byte that is not. It returns io.EOF when the input ends
// first.
func skipSpace(br *bufio.Reader) error {
	for {
		r, _, err := br.ReadRune()
		if err != nil {
			return err
		}
		if !unicode.IsSpace(r) {
			return br.UnreadRune()
		}
	}
}
