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
	"time"

	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// exitBusy is returned when another writer holds the chain's lease.
//
// Distinct from a generic I/O failure on purpose: "someone else is writing" is
// retryable and "the disk is gone" is not, and a script that cannot tell them
// apart will retry the wrong one forever.
//
// NOT REACHABLE FROM A SECOND PROCESS TODAY, and the reason is worth knowing:
// boltstore.Open passes no Timeout, so bbolt blocks on its exclusive file lock
// rather than failing. A second `proof append` against a database another
// process has open therefore HANGS instead of exiting 4. That affects every
// verb that opens a database, not only this one. Tracked as `_53`.
//
// The code is correct and is reached by an in-process lease conflict, which is
// what a library caller running two appends concurrently produces.
const exitBusy = 4

// appendInput is one line of `proof append` stdin.
//
// # Description
//
// Deliberately NOT verify.Entry. This verb MINTS positions, so accepting a
// shape that carries chain_hash or global_seq would invite a caller to supply
// values that are then silently recomputed — and believe their hashes were
// preserved. Those fields are rejected by name; see [decodeAppendInput].
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
type appendInput struct {
	EntryID     string `json:"entry_id"`
	EntryType   string `json:"entry_type"`
	Timestamp   string `json:"timestamp"`
	ContentHash string `json:"content_hash"`
	IngestedAt  string `json:"ingested_at"`
}

// mintedFields are the fields this verb assigns and therefore refuses to accept.
var mintedFields = []string{"chain_hash", "global_seq", "sequence_num", "run_id", "previous_hash"}

// cmdAppend links entries onto a chain, minting their positions and hashes.
func cmdAppend(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("append", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to append to")
	formatV2 := fs.Bool("format-v2", false, "produce v2 entries, for a verifier released before v3")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" {
		fmt.Fprintln(stderr, "proof append: --db and --chain are required")
		return exitUsage
	}

	inputs, err := readAppendInputs(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "proof append: %v\n", err)
		return exitUsage
	}
	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "proof append: no entries on stdin")
		return exitUsage
	}

	s, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof append: %v\n", err)
		return exitIOError
	}
	defer s.Close()

	var opts []linker.Option
	if *formatV2 {
		opts = append(opts, linker.WithFormatV2())
	}
	l, err := linker.New(s, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "proof append: %v\n", err)
		return exitIOError
	}

	// ONE Append per invocation. WriteBatch is the store port's transactional
	// unit, so a per-line call would turn a 10,000-entry load into 10,000
	// fsyncs — and leave a partial chain behind on failure.
	res, err := l.Append(ctx.Background(), *chainID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "proof append: %v\n", err)
		if errors.Is(err, linker.ErrChainBusy) {
			return exitBusy
		}
		return exitIOError
	}

	out := struct {
		Appended int    `json:"appended"`
		FirstSeq int64  `json:"first_seq"`
		LastSeq  int64  `json:"last_seq"`
		HeadHash string `json:"head_hash"`
		RunID    string `json:"run_id,omitempty"`
	}{res.Appended, res.FirstSeq, res.LastSeq, res.HeadHash, res.RunID}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "proof append: encode result: %v\n", err)
		return exitIOError
	}
	return exitOK
}

// readAppendInputs decodes append-input JSONL.
//
// # Description
//
// Reads every line before returning, so a malformed line N means nothing is
// written rather than a chain left half-appended.
//
// # Inputs
//
//   - r: JSONL, one appendInput per non-blank line
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
//   - Holds the whole batch in memory, which is also what Append requires.
//
// # Assumptions
//
//   - The caller is originating entries. Use `proof import` to carry existing
//     ones in with their hashes intact.
func readAppendInputs(r io.Reader) ([]linker.Input, error) {
	var out []linker.Input
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for line := 1; sc.Scan(); line++ {
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

		var in appendInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		li, err := in.toLinkerInput()
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, li)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return out, nil
}

// toLinkerInput converts one decoded line, validating what the linker cannot.
func (in appendInput) toLinkerInput() (linker.Input, error) {
	ts, err := time.Parse(time.RFC3339Nano, in.Timestamp)
	if err != nil {
		return linker.Input{}, fmt.Errorf("timestamp is not RFC 3339: %w", err)
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
		return linker.Input{}, fmt.Errorf("ingested_at is not RFC 3339: %w", err)
	}
	if ingested.IsZero() {
		return linker.Input{}, errors.New("ingested_at is the zero time")
	}
	return linker.Input{
		EntryID:     in.EntryID,
		EntryType:   in.EntryType,
		Timestamp:   ts,
		ContentHash: in.ContentHash,
		IngestedAt:  ingested,
	}, nil
}
