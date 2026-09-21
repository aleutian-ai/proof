// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"fmt"
	"sort"
)

// validateBatchOrdering checks the invariants that make a total order possible.
//
// # Description
//
// Two things make the batch's order undefined rather than merely unusual, and
// both are caught here because neither is recoverable once hashes are computed:
//
//   - A zero IngestedAt has no place in arrival order. Sorting would put it
//     first by accident of the zero value, not because it arrived first.
//   - A duplicate EntryID makes the sort comparator a partial order: two entries
//     sharing an id and an IngestedAt have no defined relative position, so the
//     assigned sequence numbers depend on the sort implementation.
//
// Checked BEFORE sorting, so the reported entry is identifiable by its position
// in the caller's input rather than in a reordered slice.
//
// # Inputs
//
//   - inputs: the batch to check, in caller order
//
// # Outputs
//
//   - string: the offending EntryID, empty when the batch is sound
//   - error: non-nil if either invariant is violated
//
// # Example
//
//	if id, err := validateBatchOrdering(inputs); err != nil {
//	    return Result{}, fmt.Errorf("linker: batch entry %q: %w", id, err)
//	}
//
// # Assumptions
//
//   - inputs is non-empty; the caller has already rejected an empty batch
func validateBatchOrdering(inputs []Input) (string, error) {
	seen := make(map[string]struct{}, len(inputs))
	for i := range inputs {
		if inputs[i].EntryID == "" {
			return "", fmt.Errorf("entry at index %d has an empty entry id", i)
		}
		if inputs[i].IngestedAt.IsZero() {
			return inputs[i].EntryID, fmt.Errorf(
				"entry %q has a zero ingested_at, so its arrival order is undefined",
				inputs[i].EntryID)
		}
		if _, dup := seen[inputs[i].EntryID]; dup {
			return inputs[i].EntryID, fmt.Errorf(
				"duplicate entry id %q in batch, so the batch has no total order",
				inputs[i].EntryID)
		}
		seen[inputs[i].EntryID] = struct{}{}
	}
	return "", nil
}

// sortInputs orders a batch by arrival: IngestedAt, then EntryID.
//
// # Description
//
// This is the ordering authority for sequence assignment. It sorts by arrival
// time and NOT by the event Timestamp, which is a distinction that has already
// caused one production defect and is worth stating rather than inferring.
//
// Ordering by event Timestamp lets a caller choose its own position in the chain
// by backdating an entry. It also diverges from any reader that pages by arrival:
// a late-delivered entry would be assigned a position out of arrival order while
// a watermark advanced past it, and the entry would be re-read on the next pass
// and surface as a spurious break in an intact chain.
//
// The event Timestamp remains hash CONTENT — it is fed to the chain hash in
// [Linker.Append] — but it is never an ordering input.
//
// EntryID is the tie-breaker when two entries share an IngestedAt. Because
// validateBatchOrdering has already rejected duplicate ids, the comparator is a
// total order and the sort is deterministic.
//
// # Inputs
//
//   - inputs: the batch to sort in place
//
// # Assumptions
//
//   - validateBatchOrdering has run and returned no error
func sortInputs(inputs []Input) {
	sort.Slice(inputs, func(i, j int) bool {
		ti, tj := inputs[i].IngestedAt, inputs[j].IngestedAt
		if ti.Equal(tj) {
			return inputs[i].EntryID < inputs[j].EntryID
		}
		return ti.Before(tj)
	})
}
