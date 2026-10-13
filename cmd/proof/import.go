// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	ctx "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// cmdImport loads an exported chain into a store, verbatim.
//
// # Why this does not use the linker
//
// The linker assigns global_seq from the target store's tail, and v3 binds
// global_seq into the hash. Re-linking a segment that starts anywhere but zero
// would therefore produce different hashes for identical entries. Import
// verifies, then writes exactly what it was given.
func cmdImport(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to import into")
	previousHash := fs.String("previous-hash", "", "the chain hash the first imported entry links from; required when importing a SEGMENT rather than a whole chain")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" {
		fmt.Fprintln(stderr, "proof import: --db and --chain are required")
		return exitUsage
	}

	entries, err := loadEntriesFrom(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitUsage
	}
	if len(entries) == 0 {
		fmt.Fprintln(stderr, "proof import: no entries on stdin")
		return exitUsage
	}

	// Verify BEFORE writing. A broken chain is not imported "for later": once
	// stored it is indistinguishable from one that broke in place, and the
	// import is where the provenance is still known.
	res, err := verify.Chain(entries, verify.Options{PreviousHash: *previousHash})
	if err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitIOError
	}
	if res.Verdict == verify.VerdictBroken {
		fmt.Fprintf(stderr, "proof import: refusing to import a broken chain — "+
			"first break at entry %d\n", res.FirstBreak)
		if *previousHash == "" && entries[0].GlobalSeq != 0 {
			fmt.Fprintf(stderr, "\n  This import starts at global_seq %d, so it is a SEGMENT, "+
				"not a whole\n  chain. Its first entry links from its predecessor and not from "+
				"nothing.\n  Pass --previous-hash <that predecessor's chain_hash>; without it "+
				"the\n  first entry cannot verify and every entry after it cascades.\n",
				entries[0].GlobalSeq)
		}
		printResult(stderr, res, false)
		return exitBroken
	}

	s, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		// A held lock is retryable; a missing or corrupt file is not. A script
		// that cannot tell them apart retries the wrong one forever.
		if errors.Is(err, boltstore.ErrLocked) {
			return exitBusy
		}
		return exitIOError
	}
	defer s.Close()

	token, acquired, err := s.Acquire(ctx.Background(), *chainID)
	if err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitIOError
	}
	if !acquired {
		fmt.Fprintln(stderr, "proof import: chain is busy, another writer holds the lease")
		return exitBusy
	}
	defer s.Release(ctx.Background(), *chainID, token)

	rows := make([]store.Entry, 0, len(entries))
	// The first row links from what the caller said it links from: nothing
	// for a whole chain, --previous-hash for a segment. The entries were
	// verified against that hash, and a row that recorded "" instead would
	// say the segment begins a chain.
	prev := *previousHash
	for _, e := range entries {
		row := toStored(*chainID, e)
		// PreviousHash is descriptive — neither format hashes it — but a store
		// that recorded it as empty for every entry would misreport the chain's
		// shape to anything reading rows directly.
		row.PreviousHash = prev
		prev = row.ChainHash
		rows = append(rows, row)
	}

	if err := refuseOccupiedRange(s, *chainID, rows); err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitIOError
	}
	if err := refuseDetachedImport(s, *chainID, rows[0]); err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitIOError
	}

	if err := s.WriteBatch(ctx.Background(), rows); err != nil {
		fmt.Fprintf(stderr, "proof import: %v\n", err)
		return exitIOError
	}

	tail := rows[len(rows)-1]
	if err := s.PutState(ctx.Background(), &store.State{
		ChainID:    *chainID,
		HeadSeq:    tail.GlobalSeq,
		HeadHash:   tail.ChainHash,
		ComputedAt: time.Now().UTC(),
	}); err != nil {
		fmt.Fprintf(stderr, "proof import: entries were written but head state was not: %v\n", err)
		return exitIOError
	}

	fmt.Fprintf(stdout, "imported %d entries into %s (seq %d..%d)\n",
		len(rows), *chainID, rows[0].GlobalSeq, tail.GlobalSeq)
	return exitOK
}

// refuseOccupiedRange fails if any incoming sequence is already taken.
//
// # Description
//
// This is the whole safety of the verb. [store.Writer.WriteBatch] "links
// nothing and validates nothing", and the bolt adapter REPLACES an entry at an
// occupied GlobalSeq — deliberately, because erasure swaps an entry for a
// tombstone at the same position. An import into an occupied range would
// therefore destroy entries silently, and the damaged chain would still verify,
// because the replacements are internally consistent with each other.
//
// # Inputs
//
//   - s: the target store
//   - chainID: the chain being imported into
//   - rows: the incoming entries, ascending by GlobalSeq
//
// # Outputs
//
//   - error: naming the first conflicting global_seq, or nil when the range is
//     free
//
// # Example
//
//	if err := refuseOccupiedRange(s, chainID, rows); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Checks occupancy, not identity. Re-importing an identical chain is
//     refused rather than treated as a no-op, because this cannot tell a
//     duplicate from a collision without trusting the very bytes in question.
//
// # Assumptions
//
//   - The caller holds the chain's lease, so nothing can occupy the range
//     between this check and the write.
func refuseOccupiedRange(s *boltstore.Store, chainID string, rows []store.Entry) error {
	first, last := rows[0].GlobalSeq, rows[len(rows)-1].GlobalSeq

	existing, err := s.Range(ctx.Background(), chainID, first, last, 1)
	if err != nil {
		return fmt.Errorf("check the target range: %w", err)
	}
	if len(existing) > 0 {
		return fmt.Errorf("sequence %d in chain %q is already occupied by entry %q. "+
			"Importing would REPLACE it — the store writes what it is given — and the "+
			"result would still verify, because the surviving entries stay consistent "+
			"with each other. Import into an empty chain, or a free range",
			existing[0].GlobalSeq, chainID, existing[0].EntryID)
	}
	return nil
}

// refuseDetachedImport fails if the chain already holds entries and the import
// does not continue from them.
//
// # Description
//
// A free range is not enough. Entries written before the chain's first entry,
// or after a gap, or after the tail but linking from some other hash, leave
// one chain id over rows that do not link: the store would then hold a chain
// that no walk from its first entry verifies, made of two parts that each
// verified when they were imported. The only import into a chain that has
// entries is the one that continues it: its first entry takes the next
// sequence number, and links from the tail's chain hash.
//
// # Inputs
//
//   - s: the target store
//   - chainID: the chain being imported into
//   - first: the first incoming row, its PreviousHash already set from
//     --previous-hash
//
// # Outputs
//
//   - error: saying which of the two conditions failed, or nil when the chain
//     is empty or the import continues it
//
// # Example
//
//	if err := refuseDetachedImport(s, chainID, rows[0]); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Compares hashes; it does not re-verify the entries already stored.
//
// # Assumptions
//
//   - The caller holds the chain's lease, and the incoming entries have been
//     verified as linking from first.PreviousHash.
func refuseDetachedImport(s *boltstore.Store, chainID string, first store.Entry) error {
	tailHash, tailSeq, err := s.ReadTail(ctx.Background(), chainID)
	if errors.Is(err, store.ErrEmptyChain) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the chain's tail: %w", err)
	}
	if first.GlobalSeq != tailSeq+1 {
		return fmt.Errorf("chain %q already holds entries up to global_seq %d, and this import "+
			"starts at %d. An import into a chain that has entries must continue it: start "+
			"at global_seq %d. Nothing was imported", chainID, tailSeq, first.GlobalSeq, tailSeq+1)
	}
	if first.PreviousHash != tailHash {
		return fmt.Errorf("chain %q already holds entries up to global_seq %d, and this import "+
			"does not link from the last of them. Pass --previous-hash with that entry's "+
			"chain_hash; the entries must verify against it. Nothing was imported",
			chainID, tailSeq)
	}
	return nil
}

// toStored converts an exported entry back to its stored form, verbatim.
//
// # Description
//
// Every hashed field is carried across unchanged: global_seq, chain_hash,
// format_version, and v2's run_id and sequence_num. Recomputing any of them
// would defeat the point of the verb.
//
// PreviousHash is reconstructed from the entry's predecessor at write time by
// the caller (for the first entry, from --previous-hash); it is not hashed in
// either format and the store treats it as descriptive.
//
// # Inputs
//
//   - chainID: the chain being imported into
//   - e: one exported entry
//
// # Outputs
//
//   - store.Entry: ready for WriteBatch
//
// # Example
//
//	rows = append(rows, toStored(chainID, e))
//
// # Limitations
//
//   - A timestamp that cannot be parsed yields the zero time, which
//     verify.Chain has already rejected by the time this runs.
//
// # Assumptions
//
//   - The batch has already been verified, so the fields are self-consistent.
func toStored(chainID string, e verify.Entry) store.Entry {
	ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
	return store.Entry{
		ChainID:       chainID,
		EntryID:       e.EntryID,
		EntryType:     e.EntryType,
		FormatVersion: e.FormatVersion,
		GlobalSeq:     e.GlobalSeq,
		RunID:         e.RunID,
		SequenceNum:   e.SequenceNum,
		Timestamp:     ts,
		ContentHash:   e.ContentHash,
		ChainHash:     e.ChainHash,
	}
}
