// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	ctx "context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// The bounds on `proof commit` stdin.
const (
	// commitMaxLine caps one input line: the cap the sink CLI puts on a line.
	// A commit line is five short fields, a few hundred bytes.
	commitMaxLine = sinkMaxLine

	// commitMaxInput caps all of stdin. The whole input is read and checked
	// before anything is written, so this is what bounds the memory a commit
	// takes: at a few hundred bytes a line it is about three million entries.
	// A larger load is split across invocations, which for the default format
	// produces the same chain.
	commitMaxInput = 1 << 30
)

// commitBatch is how many entries go into the store in one transaction. A
// transaction's memory grows with what it writes, so a large commit is written
// as several. A variable only so a test can make batches small.
var commitBatch = 10_000

// contentHashPattern is the shape of a content hash: SHA-512 in lowercase hex.
var contentHashPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

// exitBusy is returned when another writer holds the chain's lease, or
// another process holds the database's file lock past the lock timeout.
//
// Distinct from a generic I/O failure on purpose: "someone else is writing" is
// retryable and "the disk is gone" is not, and a script that cannot tell them
// apart will retry the wrong one forever.
const exitBusy = 4

// commitInput is one line of `proof commit` stdin.
//
// # Description
//
// Deliberately NOT verify.Entry. This verb MINTS positions, so accepting a
// shape that carries chain_hash or global_seq would invite a caller to supply
// values that are then silently recomputed — and believe their hashes were
// preserved. Those fields are rejected by name; see [decodeCommitInput].
//
// IngestedAt is required and orders the batch. It is NOT persisted: once linked,
// global_seq is the order, so store.Entry has no field for it and `proof export`
// cannot emit it. That is why importing an exported chain is a different verb
// (`proof import`) rather than a flag on this one.
//
// # Assumptions
//
//   - Timestamps are RFC 3339 with whatever precision the producer used; they
//     are hash content and are hashed at the precision given.
type commitInput struct {
	EntryID     string `json:"entry_id"`
	EntryType   string `json:"entry_type"`
	Timestamp   string `json:"timestamp"`
	ContentHash string `json:"content_hash"`
	IngestedAt  string `json:"ingested_at"`
}

// mintedFields are the fields this verb assigns and therefore refuses to accept.
var mintedFields = []string{"chain_hash", "global_seq", "sequence_num", "run_id", "previous_hash"}

// cmdCommit links entries onto a chain, minting their positions and hashes.
func cmdCommit(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("commit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to append to")
	formatV2 := fs.Bool("format-v2", false, "produce v2 entries, for a verifier released before v3")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" {
		fmt.Fprintln(stderr, "proof commit: --db and --chain are required")
		return exitUsage
	}

	inputs, err := readAppendInputs(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "proof commit: %v\n", err)
		return exitUsage
	}
	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "proof commit: no entries on stdin")
		return exitUsage
	}

	s, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof commit: %v\n", err)
		// A held lock is retryable; a missing or corrupt file is not. A script
		// that cannot tell them apart retries the wrong one forever.
		if errors.Is(err, boltstore.ErrLocked) {
			return exitBusy
		}
		return exitIOError
	}
	defer s.Close()

	// An entry id names one entry. The same input piped twice, or a retry
	// after a run that stopped part way, would otherwise append every entry a
	// second time under the ids the chain already holds.
	held, err := heldEntryID(ctx.Background(), s, *chainID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "proof commit: %v\n", err)
		return exitIOError
	}
	if held != nil {
		fmt.Fprintf(stderr, "proof commit: chain %q already holds entry_id %q, at global_seq %d. "+
			"Nothing was committed\n", *chainID, held.EntryID, held.GlobalSeq)
		return exitUsage
	}

	var opts []linker.Option
	if *formatV2 {
		opts = append(opts, linker.WithFormatV2())
	}
	l, err := linker.New(s, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "proof commit: %v\n", err)
		return exitIOError
	}

	// v2 binds a run id and a position in the run into every hash, and one
	// invocation is one run: it is written in one call. v3 hashes do not
	// depend on how entries are grouped, so it is written in batches.
	batch := commitBatch
	if *formatV2 {
		batch = len(inputs)
	}
	res, err := appendBatched(ctx.Background(), l, *chainID, inputs, batch)
	switch {
	case errors.Is(err, linker.ErrHeadStateStale):
		// The entries ARE committed. Report success so nobody retries and commits
		// the same evidence twice; the stale head record repairs itself.
		fmt.Fprintf(stderr, "proof commit: warning: %v\n", err)
	case err != nil:
		fmt.Fprintf(stderr, "proof commit: %v\n", err)
		if res.Appended > 0 {
			// Every batch is a whole transaction, so what was written is a
			// valid chain that ends where the failure began.
			fmt.Fprintf(stderr, "proof commit: %d of %d entries were committed before this "+
				"(global_seq %d to %d); the rest were not. A retry of the whole input is "+
				"refused, because the chain now holds those entry ids: commit the rest\n",
				res.Appended, len(inputs), res.FirstSeq, res.LastSeq)
		}
		if errors.Is(err, linker.ErrChainBusy) {
			return exitBusy
		}
		return exitIOError
	}

	out := struct {
		Committed int    `json:"committed"`
		FirstSeq  int64  `json:"first_seq"`
		LastSeq   int64  `json:"last_seq"`
		HeadHash  string `json:"head_hash"`
		RunID     string `json:"run_id,omitempty"`
	}{res.Appended, res.FirstSeq, res.LastSeq, res.HeadHash, res.RunID}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "proof commit: encode result: %v\n", err)
		return exitIOError
	}
	return exitOK
}

// heldEntryID returns the first entry already on the chain whose id one of the
// inputs carries, or nil when there is none.
//
// The store keeps no index by entry id, so this reads the chain, a page at a
// time: its cost grows with the chain's length, and its memory does not.
func heldEntryID(c ctx.Context, s store.Reader, chainID string, inputs []linker.Input) (*store.Entry, error) {
	var ids map[string]struct{}
	for from := int64(0); ; {
		rows, err := s.Range(c, chainID, from, 1<<62, exportPage)
		if err != nil {
			return nil, fmt.Errorf("read chain %q: %w", chainID, err)
		}
		if ids == nil && len(rows) > 0 {
			// Built only once the chain is known to hold something: a first
			// commit to a new chain has nothing to compare against.
			ids = make(map[string]struct{}, len(inputs))
			for i := range inputs {
				ids[inputs[i].EntryID] = struct{}{}
			}
		}
		for i := range rows {
			if _, ok := ids[rows[i].EntryID]; ok {
				return &rows[i], nil
			}
		}
		if len(rows) < exportPage {
			return nil, nil
		}
		from = rows[len(rows)-1].GlobalSeq + 1
	}
}

// appendBatched appends inputs to the chain, at most batch entries to a
// transaction, and returns one Result for the whole.
//
// The inputs are sorted once, in the linker's own order (arrival time, then
// entry id), and each batch is a run of that order. The linker sorts a batch
// the same way, so it leaves each one as it is and the chain is the one a
// single Append of everything would have written. TestCommit_BatchesMatchOneAppend
// holds the two orders together.
//
// On an error the Result still says what earlier batches committed.
func appendBatched(c ctx.Context, l *linker.Linker, chainID string, inputs []linker.Input,
	batch int) (linker.Result, error) {
	sort.SliceStable(inputs, func(i, j int) bool {
		ti, tj := inputs[i].IngestedAt, inputs[j].IngestedAt
		if ti.Equal(tj) {
			return inputs[i].EntryID < inputs[j].EntryID
		}
		return ti.Before(tj)
	})

	var total linker.Result
	var stale error
	for start := 0; start < len(inputs); start += batch {
		end := min(start+batch, len(inputs))
		res, err := l.Append(c, chainID, inputs[start:end])
		if errors.Is(err, linker.ErrHeadStateStale) {
			// Written. The next batch reads the tail from the chain itself.
			stale, err = err, nil
		}
		if err != nil {
			return total, err
		}
		if total.Appended == 0 {
			total.FirstSeq, total.RunID = res.FirstSeq, res.RunID
		}
		total.Appended += res.Appended
		total.LastSeq, total.HeadHash = res.LastSeq, res.HeadHash
	}
	return total, stale
}

// readAppendInputs decodes append-input JSONL.
//
// # Description
//
// Reads every line before returning, so a malformed line N means nothing is
// written rather than a chain left half-appended. The input is bounded: a line
// longer than commitMaxLine, or more than commitMaxInput bytes in all, is an
// error. An entry_id given twice is an error too: the second would be a second
// entry under the first one's name.
//
// # Inputs
//
//   - r: JSONL, one commitInput per non-blank line
//
// # Outputs
//
//   - []linker.Input: in the order read; the linker sorts by IngestedAt
//   - error: naming the offending LINE, since that is what a caller can fix
//
// # Example
//
//	inputs, err := readAppendInputs(os.Stdin)
//
// # Limitations
//
//   - Holds the whole batch in memory, up to the bound on the input.
//
// # Assumptions
//
//   - The caller is originating entries. Use `proof import` to carry existing
//     ones in with their hashes intact.
func readAppendInputs(r io.Reader) ([]linker.Input, error) {
	return readAppendInputsBounded(r, commitMaxLine, commitMaxInput)
}

// readAppendInputsBounded is readAppendInputs with the bounds as arguments, so
// a test can reach them without a gigabyte of input.
func readAppendInputsBounded(r io.Reader, maxLine int, maxInput int64) ([]linker.Input, error) {
	// One byte past the bound is read, so input of exactly the bound is told
	// apart from input that was cut off at it.
	limited := &io.LimitedReader{R: r, N: maxInput + 1}
	tooLarge := func() error {
		return fmt.Errorf("stdin is larger than %d bytes. Nothing was committed: split the "+
			"input across several invocations", maxInput)
	}

	var out []linker.Input
	firstLine := map[string]int{} // entry_id -> the line that gave it first
	sc := bufio.NewScanner(limited)
	// The scanner's cap is the larger of the two arguments, so the first
	// buffer is never bigger than the bound.
	sc.Buffer(make([]byte, 0, min(64*1024, maxLine)), maxLine)

	line := 0
	for sc.Scan() {
		line++
		if limited.N == 0 {
			// The line just read may be one the bound cut short.
			return nil, tooLarge()
		}
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		// Reject minted fields BEFORE decoding into the typed shape, which
		// would silently drop them. A caller who supplied chain_hash believes
		// it was honoured.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		for _, f := range mintedFields {
			if _, present := probe[f]; present {
				return nil, fmt.Errorf("line %d carries %q, which this verb MINTS. "+
					"Accepting it would recompute the value and leave you believing it "+
					"was preserved. To carry existing entries in with their hashes "+
					"intact, use `proof import`", line, f)
			}
		}

		var in commitInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		li, err := in.toLinkerInput()
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if first, dup := firstLine[li.EntryID]; dup {
			return nil, fmt.Errorf("line %d repeats the entry_id %q of line %d. An entry id "+
				"names one entry", line, li.EntryID, first)
		}
		firstLine[li.EntryID] = line
		out = append(out, li)
	}
	switch err := sc.Err(); {
	case limited.N == 0:
		return nil, tooLarge()
	case errors.Is(err, bufio.ErrTooLong):
		return nil, fmt.Errorf("line %d is longer than %d bytes", line+1, maxLine)
	case err != nil:
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return out, nil
}

// toLinkerInput converts one decoded line, validating what the linker cannot.
func (in commitInput) toLinkerInput() (linker.Input, error) {
	ts, err := time.Parse(time.RFC3339Nano, in.Timestamp)
	if err != nil {
		return linker.Input{}, errors.New("timestamp is not an RFC 3339 time, for example 2026-01-20T12:00:01.123456Z")
	}
	// The linker rejects a zero IngestedAt, but only once the whole batch is in
	// hand — and its message cannot name the line. Checked here so the caller
	// is told which line to fix.
	if in.IngestedAt == "" {
		return linker.Input{}, errors.New("ingested_at is required; it orders the batch, " +
			"and ordering by the event timestamp would let a caller choose its own " +
			"position in the chain")
	}
	ingested, err := time.Parse(time.RFC3339Nano, in.IngestedAt)
	if err != nil {
		return linker.Input{}, errors.New("ingested_at is not an RFC 3339 time, for example 2026-01-20T12:00:01.123456Z")
	}
	if ingested.IsZero() {
		return linker.Input{}, errors.New("ingested_at is the zero time")
	}
	// What the linker would refuse is refused here, where the line is known
	// and before a database is opened. A tombstone-shaped content hash is left
	// to the linker, which says why it is reserved.
	if in.EntryID == "" {
		return linker.Input{}, errors.New("entry_id is required")
	}
	if err := chainformat.ValidateTimestamp(ts); err != nil {
		return linker.Input{}, err
	}
	if !contentHashPattern.MatchString(in.ContentHash) && !chainformat.IsTombstoneContentHash(in.ContentHash) {
		return linker.Input{}, fmt.Errorf("content_hash must be 128 lowercase hex characters "+
			"(SHA-512), got %d characters", len(in.ContentHash))
	}
	return linker.Input{
		EntryID:     in.EntryID,
		EntryType:   in.EntryType,
		Timestamp:   ts,
		ContentHash: in.ContentHash,
		IngestedAt:  ingested,
	}, nil
}
