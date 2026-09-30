// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"errors"
	"fmt"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// ChainInputs is one chain's share of an AppendChains call.
type ChainInputs struct {
	// ChainID is the chain to append to. Distinct within one call.
	ChainID string
	// Inputs are the entries to link, under Append's rules.
	Inputs []Input
}

// AppendChains links batches onto several chains and writes them all in ONE
// atomic transaction: entries and head states together.
//
// # Description
//
// Each batch is validated and sorted exactly as Append does, then linked by
// the same code (link), so for FormatV3 the entries are byte-identical to
// calling Append once per chain. FormatV2 mints one run id per chain, as one
// Append per chain would. The store reads every chain's tail, and writes every
// chain's entries and head, inside one transaction (store.ChainsUpdater): no
// writer can append between the reads and the writes, and either every chain
// is extended or none is.
//
// It needs no lease: the transaction is the lock. A chain leased by an
// Append in progress makes the whole call return ErrChainBusy.
//
// # Inputs
//
//   - ctx: checked before any work, and by the store
//   - batches: at least one; distinct, non-empty chain ids; each with inputs
//     valid for Append
//
// # Outputs
//
//   - []Result: one per batch, in the order given. Nil on error.
//   - error: ErrChainBusy under contention; a validation error naming the
//     batch; an error when the store cannot
//     append to several chains in one transaction; a wrapped store error.
//     Nothing is written on any error. There is no ErrHeadStateStale on this
//     path: heads are written in the same transaction as the entries.
//
// # Example
//
//	res, err := l.AppendChains(ctx, []linker.ChainInputs{
//	    {ChainID: "a", Inputs: aInputs},
//	    {ChainID: "b", Inputs: bInputs},
//	})
//	if errors.Is(err, linker.ErrChainBusy) {
//	    // retry
//	}
//
// # Limitations
//
//   - Every batch is held in memory and written in one transaction; the caller
//     bounds the call.
//   - The store must implement store.ChainsUpdater; there is no fallback to
//     one transaction per chain, which would not be atomic.
//
// # Assumptions
//
//   - The callback given to the store does not re-enter it (it doesn't: it only
//     links). Other goroutines may use the store meanwhile; the store's
//     transaction serializes them.
func (l *Linker) AppendChains(ctx context.Context, batches []ChainInputs) ([]Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	updater, ok := l.store.(store.ChainsUpdater)
	if !ok {
		return nil, errors.New("linker: this store cannot append to several chains in one transaction " +
			"(it does not implement store.ChainsUpdater)")
	}
	if len(batches) == 0 {
		return nil, errors.New("linker: no chains to append to")
	}

	chainIDs := make([]string, len(batches))
	sorted := make([][]Input, len(batches))
	runIDs := make([]string, len(batches))
	seen := make(map[string]bool, len(batches))
	for b, batch := range batches {
		if batch.ChainID == "" {
			return nil, fmt.Errorf("linker: batch %d: chain id must not be empty", b)
		}
		if seen[batch.ChainID] {
			return nil, fmt.Errorf("linker: batch %d: chain %q appears twice", b, batch.ChainID)
		}
		seen[batch.ChainID] = true
		if len(batch.Inputs) == 0 {
			return nil, fmt.Errorf("linker: batch %d (chain %q) must not be empty", b, batch.ChainID)
		}
		if _, err := validateBatchOrdering(batch.Inputs); err != nil {
			return nil, fmt.Errorf("linker: batch %d (chain %q): %w", b, batch.ChainID, err)
		}
		// Copy before sorting, as Append does.
		sorted[b] = make([]Input, len(batch.Inputs))
		copy(sorted[b], batch.Inputs)
		sortInputs(sorted[b])
		if l.format == chainformat.FormatV2 {
			id, err := l.runID()
			if err != nil {
				return nil, fmt.Errorf("linker: generate run id: %w", err)
			}
			runIDs[b] = id
		}
		chainIDs[b] = batch.ChainID
	}

	results := make([]Result, len(batches))
	err := updater.UpdateChains(ctx, chainIDs,
		func(tails []store.Tail) ([]store.Entry, []store.State, error) {
			if len(tails) != len(chainIDs) {
				return nil, nil, fmt.Errorf("linker: the store returned %d tails for %d chains",
					len(tails), len(chainIDs))
			}
			var entries []store.Entry
			states := make([]store.State, len(batches))
			for b := range batches {
				tail := tails[b]
				if tail.ChainID != chainIDs[b] {
					return nil, nil, fmt.Errorf("linker: the store returned the tail of %q for chain %q",
						tail.ChainID, chainIDs[b])
				}
				previousHash, nextGlobalSeq := "", int64(0)
				if !tail.Empty {
					previousHash, nextGlobalSeq = tail.Hash, tail.GlobalSeq+1
				}
				linked, err := l.link(chainIDs[b], previousHash, nextGlobalSeq, runIDs[b], sorted[b])
				if err != nil {
					return nil, nil, fmt.Errorf("batch %d: %w", b, err)
				}
				last := linked[len(linked)-1]
				states[b] = store.State{
					ChainID:    chainIDs[b],
					HeadSeq:    last.GlobalSeq,
					HeadHash:   last.ChainHash,
					ComputedAt: l.now(),
				}
				results[b] = Result{
					RunID:    runIDs[b],
					Appended: len(linked),
					FirstSeq: linked[0].GlobalSeq,
					LastSeq:  last.GlobalSeq,
					HeadHash: last.ChainHash,
				}
				entries = append(entries, linked...)
			}
			return entries, states, nil
		})
	if errors.Is(err, store.ErrChainLeased) {
		return nil, ErrChainBusy
	}
	if err != nil {
		return nil, fmt.Errorf("linker: append chains: %w", err)
	}
	return results, nil
}
