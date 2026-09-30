// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package store

import "fmt"

// CheckAppend is the rule every ChainsUpdater applies to what its fn returns:
// the entries and states must be an APPEND onto tails, nothing else.
//
// # Description
//
// For each chain, its entries (in the order given) must continue its tail
// exactly: GlobalSeq tail+1, tail+2, … (0, 1, … for an empty chain), each
// PreviousHash the ChainHash before it (the tail's hash, or empty for a
// genesis entry). Every state must be for a chain that received entries in
// this call, and name exactly its last entry (HeadSeq and HeadHash). An entry
// or state for a chain not in tails is refused. Without this an "append"
// could overwrite history (stores replace an occupied position) or record a
// head no entry produced.
//
// # Inputs
//
//   - tails: the tails the store read, one per chain in the call
//   - entries, states: what fn returned
//
// # Outputs
//
//   - error: the first violation, naming the chain; nil when it is an append
//
// # Example
//
//	if err := store.CheckAppend(tails, entries, states); err != nil {
//	    return err // inside the transaction: nothing is written
//	}
//
// # Limitations
//
//   - Checks structure and linkage, not the hash computation itself (that is
//     the linker's, and the verifier's).
//
// # Assumptions
//
//   - tails has one entry per chain, as the store read them in this
//     transaction.
func CheckAppend(tails []Tail, entries []Entry, states []State) error {
	type cursor struct {
		next int64
		prev string
		last *Entry
	}
	chains := make(map[string]*cursor, len(tails))
	for _, t := range tails {
		c := &cursor{}
		if !t.Empty {
			c.next, c.prev = t.GlobalSeq+1, t.Hash
		}
		chains[t.ChainID] = c
	}
	for i := range entries {
		e := &entries[i]
		c, ok := chains[e.ChainID]
		if !ok {
			return fmt.Errorf("store: entry %s is for chain %q, which this call did not name", e.EntryID, e.ChainID)
		}
		if e.GlobalSeq != c.next {
			return fmt.Errorf("store: chain %q: entry %s at sequence %d, want %d (an append continues the tail)",
				e.ChainID, e.EntryID, e.GlobalSeq, c.next)
		}
		if e.PreviousHash != c.prev {
			return fmt.Errorf("store: chain %q: entry %s does not link to the entry before it", e.ChainID, e.EntryID)
		}
		c.next, c.prev, c.last = c.next+1, e.ChainHash, e
	}
	for _, st := range states {
		c, ok := chains[st.ChainID]
		if !ok {
			return fmt.Errorf("store: state for chain %q, which this call did not name", st.ChainID)
		}
		if c.last == nil {
			return fmt.Errorf("store: state for chain %q, which received no entries in this call", st.ChainID)
		}
		if st.HeadSeq != c.last.GlobalSeq || st.HeadHash != c.last.ChainHash {
			return fmt.Errorf("store: state for chain %q does not name its last entry", st.ChainID)
		}
	}
	return nil
}
