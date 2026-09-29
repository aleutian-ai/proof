// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/verify"
)

// Checkpoint signs one checkpoint for every chain with entries since its last.
//
// # Description
//
// Each checkpoint is a v6 anchor over the whole chain so far, linked to the
// chain's previous checkpoint, with the chain id as its subject. build.Anchor
// verifies the chain before it will sign anything about it, and the existing
// series must verify (under trusted) before anything is signed on top of it.
//
// A chain that cannot be checkpointed (a broken chain, a malformed or
// unverifiable series, an id this sink never writes) is reported in its
// Checkpointed.Problem, and the other chains are still checkpointed: one bad
// chain must not stop the rest.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - signer: an ML-DSA-65 signer, e.g. from a `proof keygen --alg ml-dsa-65` key
//   - trusted: the keys the EXISTING checkpoints may be signed with. nil means
//     the signer's own key only. After a key rotation, pass the old public keys
//     here (with the new one), or no chain checkpointed under the old key could
//     ever be checkpointed again.
//
// # Outputs
//
//   - []Checkpointed: one per chain that has entries since its last checkpoint:
//     the checkpoint written, or the Problem that prevented it. Empty if every
//     chain was already checkpointed.
//   - error: an operational failure (signing, reading or writing files). The
//     checkpoints written before it remain and are valid.
//
// # Example
//
//	done, err := s.Checkpoint(ctx, signer, nil)
//	for _, c := range done {
//	    if c.Problem != "" {
//	        log.Printf("chain %s not checkpointed: %s", c.Chain, c.Problem)
//	    }
//	}
//
// # Limitations
//
//   - Walks each chain with new entries once, a page at a time; a chain with
//     nothing new is skipped from its tail alone.
func (s *Sink) Checkpoint(ctx context.Context, signer anchor.ContextSigner, trusted anchor.KeySource) ([]Checkpointed, error) {
	if signer == nil {
		return nil, errors.New("sink: a signer is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read-only: a checkpoint writes checkpoint files, never the evidence file.
	st, err := s.openStore(true)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	f, err := s.openFolder(false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	chains, err := st.Chains(ctx)
	if err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	if trusted == nil {
		signerID, signerPub, err := anchor.KeyIDOf(signer)
		if err != nil {
			return nil, fmt.Errorf("sink: %w", err)
		}
		if trusted, err = anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{signerID: signerPub}); err != nil {
			return nil, fmt.Errorf("sink: %w", err)
		}
	}

	var out []Checkpointed
	skip := func(chain, problem string) {
		out = append(out, Checkpointed{Chain: chain, Problem: problem})
	}
	for _, chain := range chains {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !ValidChainID(chain) {
			skip(chain, "the evidence file holds a chain id this sink never writes; not checkpointed")
			continue
		}
		anchors, problem, err := f.readAnchors(chain)
		if err != nil {
			return out, err
		}
		if problem != "" {
			skip(chain, problem+"; refusing to add to it")
			continue
		}
		var previous *anchor.Anchor
		if len(anchors) > 0 {
			previous = &anchors[len(anchors)-1]
			// Nothing new since the last checkpoint: known from the tail alone,
			// without walking the chain.
			if _, tail, err := st.ReadTail(ctx, chain); err == nil && previous.EntryCount == tail+1 {
				continue
			}
		}
		// One paged walk: it verifies the chain, binds the existing series as it
		// passes each checkpoint's end (a planted or damaged checkpoint is
		// reported, never extended), and leaves the walker the new checkpoint is
		// built from.
		w := verify.NewWalker(verify.Options{MaxBreaks: 1})
		series := newSeriesCheck(chain, anchors, trusted)
		total := 0
		if err := forEachEntry(ctx, st, chain, func(e store.Entry) {
			w.Add(toVerifyEntry(e))
			series.reached(w)
			total++
		}); err != nil {
			return out, err
		}
		if len(anchors) > 0 {
			series.finish(total)
			if len(series.problems) > 0 {
				skip(chain, "its checkpoints do not verify under the trusted keys: "+series.problems[0])
				continue
			}
		}
		unsigned, err := build.FromWalker(ctx, chain, w, previous, time.Time{})
		if errors.Is(err, build.ErrChainBroken) {
			skip(chain, err.Error())
			continue
		}
		if err != nil {
			return out, fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		signed, err := anchor.SignAnchor(ctx, signer, unsigned)
		if err != nil {
			return out, fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		raw, err := json.MarshalIndent(signed, "", "  ")
		if err != nil {
			return out, fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		dir := filepath.Join("anchors", chain)
		if err := f.mkdirAll(dir, 0o755); err != nil {
			return out, fmt.Errorf("sink: %w", err)
		}
		name := fmt.Sprintf("%04d.json", len(anchors)+1)
		if err := f.writeNew(filepath.Join(dir, name), raw, 0o644); err != nil {
			return out, err
		}
		out = append(out, Checkpointed{Chain: chain,
			File: filepath.Join("anchors", chain, name), Entries: signed.EntryCount})
	}
	return out, nil
}
