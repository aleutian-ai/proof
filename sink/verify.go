// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// Verify checks every chain in the evidence file, each on its own.
//
// # Description
//
// For every chain:
//
//  1. The links are intact: no entry edited, reordered or removed mid-chain.
//  2. Every checkpoint is signed by a key in keys, is for this chain, and binds
//     the entries it covered. This is what catches entries removed from the
//     front, which step 1 cannot.
//  3. Every event's stored content opens its commitment with its nonce, and
//     every erasure record matches its digest.
//  4. Events before an erasure entry are gone: content and nonce both deleted.
//     They count as erased. An event missing WITHOUT an erasure after it is a
//     problem, not an erasure.
//
// Steps 1 and 2 need only the evidence file, the checkpoints and a public key.
// Step 3 needs the content folder and the nonce file, which only the operator
// holds.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - keys: the public keys checkpoints may be signed with
//
// # Outputs
//
//   - Report: per chain, in chain-id order. Report.OK is the verdict.
//   - error: only when verification could not run (a file unreadable). A broken
//     chain is a finding in the Report, not an error.
func (s *Sink) Verify(ctx context.Context, keys anchor.KeySource) (Report, error) {
	if keys == nil {
		return Report{}, errors.New("sink: a key source is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read-only throughout: a verifier must not modify the evidence it checks,
	// and must not create anything (a mistyped folder is reported, not made).
	f, err := s.openFolder(false)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	st, err := s.openStore(true)
	if err != nil {
		return Report{}, err
	}
	defer st.Close()
	ns, err := s.openNoncesReadOnly()
	if err != nil {
		return Report{}, err
	}
	if ns != nil {
		defer ns.Close()
	}
	chains, err := st.Chains(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("sink: %w", err)
	}

	var rep Report
	inStore := map[string]bool{}
	for _, chain := range chains {
		inStore[chain] = true
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if !idPattern.MatchString(chain) {
			// Never build a path from it: it could be "../../somewhere".
			rep.Chains = append(rep.Chains, ChainReport{Chain: chain, Anomaly: "invalid-id",
				Problems: []string{"the evidence file holds a chain id this sink never writes; it was not read"}})
			continue
		}
		cr, err := s.verifyChain(ctx, st, ns, f, chain, keys)
		if err != nil {
			return rep, err
		}
		rep.Chains = append(rep.Chains, cr)
	}

	// A chain removed from the evidence file leaves its checkpoints and content
	// behind. They are the only trace of it, so look for them.
	for _, sub := range []string{"anchors", "content"} {
		dirs, err := f.list(sub)
		if errors.Is(err, errNotRealDir) {
			rep.Chains = append(rep.Chains, ChainReport{Chain: sub + "/", Anomaly: "invalid-folder",
				Problems: []string{fmt.Sprintf("%s/ is %v", sub, errNotRealDir)}})
			continue
		}
		if err != nil {
			return rep, fmt.Errorf("sink: %w", err)
		}
		for _, d := range dirs {
			if inStore[d.Name()] {
				continue
			}
			inStore[d.Name()] = true // report each once
			rep.Chains = append(rep.Chains, ChainReport{Chain: d.Name(), Anomaly: "removed",
				Problems: []string{fmt.Sprintf("%s/ has a folder for this chain, but the evidence file "+
					"has no entries for it: the chain was REMOVED, or a first commit stopped before its "+
					"append (erase the chain to remove what it left)", sub)}})
		}
	}
	sort.Slice(rep.Chains, func(i, j int) bool { return rep.Chains[i].Chain < rep.Chains[j].Chain })
	return rep, nil
}

// verifyChain verifies one chain in two paged passes, never holding it whole:
// the first counts it and finds its last erasure; the second walks it, binding
// each checkpoint as the walk reaches its end, and checks each entry's content.
func (s *Sink) verifyChain(ctx context.Context, st *boltstore.Store, ns *noncestore.Store, f *folder,
	chain string, keys anchor.KeySource) (ChainReport, error) {
	cr := ChainReport{Chain: chain}
	anchors, problem, err := f.readAnchors(chain)
	if err != nil {
		return cr, err
	}

	// Pass 1: the length, and where the last erasure is.
	total, lastErasure := 0, -1
	if err := forEachEntry(ctx, st, chain, func(e store.Entry) {
		if e.EntryType == EntryTypeErasure {
			lastErasure = total
		}
		total++
	}); err != nil {
		return cr, err
	}
	cr.Entries = total

	// The content folder, as a set of names to tick off. The folder first:
	// under a symlinked folder every read would be refused as an escape.
	contentDir := filepath.Join("content", chain)
	files, err := f.list(contentDir)
	if errors.Is(err, errNotRealDir) {
		cr.Problems = append(cr.Problems, fmt.Sprintf("content/%s is %v", chain, errNotRealDir))
		return cr, nil
	}
	if err != nil {
		return cr, fmt.Errorf("sink: %w", err)
	}
	unmatched := make(map[string]bool, len(files))
	for _, fi := range files {
		unmatched[fi.Name()] = true
	}

	// Pass 2: walk, bind checkpoints, check content.
	w := verify.NewWalker(verify.Options{MaxBreaks: 1})
	var series *seriesCheck
	if problem != "" {
		cr.Problems = append(cr.Problems, problem)
	} else {
		series = newSeriesCheck(chain, anchors, keys)
	}
	i, prevSeq := 0, int64(0)
	var contentErr error
	err = forEachEntry(ctx, st, chain, func(e store.Entry) {
		ve := toVerifyEntry(e)
		w.Add(ve)
		if series != nil {
			series.reached(w)
		}
		if contentErr == nil {
			contentErr = s.checkEntry(&cr, ns, f, ve, i, lastErasure, prevSeq, unmatched)
		}
		prevSeq = e.GlobalSeq
		i++
	})
	if err != nil {
		return cr, err
	}
	if contentErr != nil {
		return cr, contentErr
	}

	if res := w.Result(); len(res.Breaks) > 0 {
		cr.Problems = append(cr.Problems, fmt.Sprintf("links BROKEN at entry %d: %s",
			res.FirstBreak, res.Breaks[0].Type))
	}
	covered := int64(0)
	if series != nil {
		series.finish(total)
		cr.Problems = append(cr.Problems, series.problems...)
		cr.Checkpoints, covered = series.verified, series.covered
	}
	cr.Unanchored = total - int(covered)

	// A file matching no entry is content that was never committed: a commit
	// that stopped before its append. It is still personal data, so say so.
	names := make([]string, 0, len(unmatched))
	for n := range unmatched {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cr.Problems = append(cr.Problems, fmt.Sprintf("content file %q matches no entry (a commit "+
			"that did not finish?); erase the chain or remove it", n))
	}
	return cr, nil
}

// seriesCheck verifies a chain's checkpoint series during a single walk: each
// checkpoint is bound when the walk reaches its last entry. The first problem
// stops the series; later checkpoints are not reported as verified.
type seriesCheck struct {
	chain    string
	anchors  []anchor.Anchor
	keys     anchor.KeySource
	next     int
	prevHash string
	prevID   string
	covered  int64
	verified int
	problems []string
	stopped  bool
}

func newSeriesCheck(chain string, anchors []anchor.Anchor, keys anchor.KeySource) *seriesCheck {
	c := &seriesCheck{chain: chain, anchors: anchors, keys: keys,
		prevHash: anchor.SeedAnchorHash, prevID: anchor.SeedAnchorID}
	c.checkNext()
	return c
}

func (c *seriesCheck) fail(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
	c.stopped = true
}

// checkNext applies the series rules that need no entries to the next
// checkpoint, as soon as it becomes the next.
func (c *seriesCheck) checkNext() {
	if c.stopped || c.next >= len(c.anchors) {
		return
	}
	a, n := c.anchors[c.next], c.next+1
	switch {
	case a.Subject != c.chain:
		c.fail("checkpoint %04d is for another chain", n)
	case a.PreviousAnchorID != c.prevID:
		// The hash already binds the predecessor; checking the id too keeps
		// this verifier in step with one following format-spec §9.7 literally.
		c.fail("checkpoint %04d does not name checkpoint %04d as its predecessor", n, n-1)
	case a.EntryCount <= c.covered:
		c.fail("checkpoint %04d covers %d entries, no more than checkpoint %04d did: a series must grow",
			n, a.EntryCount, n-1)
	}
}

// reached binds the next checkpoint if the walk has just reached its last entry.
func (c *seriesCheck) reached(w *verify.Walker) {
	if c.stopped || c.next >= len(c.anchors) || int64(w.Count()) != c.anchors[c.next].EntryCount {
		return
	}
	a, n := c.anchors[c.next], c.next+1
	// A checkpoint commits to the chain as it was when signed: it is bound to
	// exactly the entries it covered, which is what the walker holds now.
	br, err := w.VerifyAnchor(a, c.prevHash, c.keys)
	switch {
	case err != nil:
		c.fail("checkpoint %04d: %v", n, err)
		return
	case !br.Bound || !br.SignatureVerified:
		c.fail("checkpoint %04d does NOT verify: %s", n, br.Detail)
		return
	}
	c.verified++
	c.covered = a.EntryCount
	c.prevHash, c.prevID = a.ChainHash, a.AnchorID
	c.next++
	c.checkNext()
}

// finish reports a checkpoint the walk never reached: it claims more entries
// than the chain holds.
func (c *seriesCheck) finish(total int) {
	if !c.stopped && c.next < len(c.anchors) {
		c.fail("checkpoint %04d claims %d entries; the chain has %d",
			c.next+1, c.anchors[c.next].EntryCount, total)
	}
}

// checkEntry checks one entry's content against the rules of
// docs/sink-format.md §6, given the index of the chain's last erasure and the
// previous entry's sequence. It ticks the entry's file off unmatched.
func (s *Sink) checkEntry(cr *ChainReport, ns *noncestore.Store, f *folder, e verify.Entry, i, lastErasure int,
	prevSeq int64, unmatched map[string]bool) error {
	if !entryIDPattern.MatchString(e.EntryID) {
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %q has an id this sink never assigns; "+
			"it was not read", e.EntryID))
		return nil
	}
	delete(unmatched, e.EntryID+".json")
	content, missing, problem, err := f.readSmall(contentName(cr.Chain, e.EntryID), MaxContentBytes)
	if err != nil {
		return fmt.Errorf("sink: %w", err)
	}
	if problem != "" {
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s: its content: %s", e.EntryID, problem))
		return nil
	}
	var nonce []byte
	noNonce := true // no nonce file at all: nothing can be opened
	if ns != nil {
		var nerr error
		nonce, nerr = ns.Get(cr.Chain, e.EntryID)
		noNonce = errors.Is(nerr, noncestore.ErrNotFound)
		if nerr != nil && !noNonce {
			return fmt.Errorf("sink: nonce for %s: %w", e.EntryID, nerr)
		}
	}

	switch {
	case e.EntryType == EntryTypeErasure:
		// The record must be EXACTLY the one for this position, and hash under
		// the erasure domain. An event relabelled as an erasure fails both:
		// its commitment is not a domain-separated hash of any record.
		if i == 0 {
			cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s is the first entry: "+
				"there is nothing before it to erase", e.EntryID))
			return nil
		}
		want := erasureRecord(prevSeq)
		if missing || !bytes.Equal(content, want) || erasureHash(want) != e.ContentHash {
			cr.Problems = append(cr.Problems, fmt.Sprintf("erasure record %s is missing, MODIFIED, "+
				"or not the erasure record for its position", e.EntryID))
		}
	case e.EntryType != EntryTypeEvent:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s has type %q, which this sink never writes",
			e.EntryID, e.EntryType))
	case i < lastErasure:
		if !missing || !noNonce {
			cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was erased, but its content or nonce "+
				"is still here: run erase again", e.EntryID))
			return nil
		}
		cr.Erased++
	case missing:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s is MISSING: the chain records it, "+
			"its content is gone, and no erasure was recorded", e.EntryID))
	case noNonce:
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s cannot be opened: its nonce is gone, "+
			"and no erasure was recorded", e.EntryID))
	case !commitment.Verify(e.ContentHash, nonce, content):
		cr.Problems = append(cr.Problems, fmt.Sprintf("entry %s was MODIFIED: its content no longer "+
			"opens the commitment", e.EntryID))
	default:
		cr.Opened++
	}
	return nil
}
