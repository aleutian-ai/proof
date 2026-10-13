// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/internal/fault"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// CheckpointOption configures one Checkpoint call.
type CheckpointOption func(*checkpointConfig)

type checkpointConfig struct {
	confirmed   map[string]string // chain → the erasure entry the caller made on it
	vouched     map[string]bool   // chains whose erasure the operator vouches for
	recordTrust anchor.KeySource
	heads       CheckpointHeads
	only        []string // when set, the only chains considered
	onlySet     bool
	err         error
}

// erasureUnconfirmed is why a chain that ends with an erasure nothing vouches
// for is not checkpointed.
const erasureUnconfirmed = "it ends with an erasure that no checkpoint covers, and nothing shows this sink " +
	"made it (an erasure record takes no key: anyone who can write the folder can append one), so it was " +
	"not signed. An erase run confirms its own erasures when it checkpoints them itself (`proof sink erase " +
	"… --key`); once that run is over, nothing in the folder can. On a sink that signs its records, give " +
	"the record public key (`proof sink checkpoint --record-trust`). Otherwise, if you know this erasure " +
	"is yours (an erase without --key, or one whose checkpoint did not complete), vouch for the chain: " +
	"`proof sink checkpoint --key … --confirm-erased-chain <this chain id>` (in Go: ConfirmErasedChains). " +
	"If you do not know where it came from, it was written into the folder by something else: treat the " +
	"chain as tampered with"

// notAnUnconfirmedErasure is the Problem of a chain named to ConfirmErasedChains
// that is not in the state that option is for.
const notAnUnconfirmedErasure = "it was named as an erased chain to vouch for, but it does not end with an " +
	"erasure that no checkpoint covers: nothing was confirmed for it"

// ConfirmErasures names erasures the caller itself just made, so that
// Checkpoint signs over them.
//
// # Description
//
// An erasure record takes no key. One appended to the end of a chain by anyone
// who can write the folder, with the chain's index row removed, verifies
// exactly as a real erasure does before its checkpoint, and a checkpoint over
// it would turn it into a signed "erased". So Checkpoint signs a chain that
// ends with an uncovered erasure only when it has evidence the operator made
// it. This is one kind: the results EraseSubject, EraseSubjectClass and
// ResumeErasures return, passed back in the same process. Each confirms one
// erasure entry ON ITS OWN CHAIN: the chain must end with exactly the entry the
// result names. An entry id alone would not do, because it can be read from
// the evidence file and written onto another chain.
//
// The other kinds are the erasure's record signature (CheckpointRecordTrust)
// and the operator's explicit word (ConfirmErasedChains).
//
// # Inputs
//
//   - results: what an erase call returned. A result with no erasure entry (a
//     chain that had no entries) is ignored, and so is one marked Relinked: its
//     erasure entry was on the chain before the call, and the call does not
//     vouch for it. A result whose chain or entry id is not the sink's own
//     shape makes Checkpoint fail.
//
// # Outputs
//
//   - CheckpointOption: to pass to Checkpoint
//
// # Example
//
//	res, err := s.EraseSubject(ctx, subject)
//	if err != nil {
//	    return err
//	}
//	done, err := s.Checkpoint(ctx, signer, nil, sink.ConfirmErasures(res.Erased...))
//
// # Limitations
//
//   - It confirms what the caller says. Pass only results an erase call
//     returned to this process.
//   - An erase call also completes erasures an earlier call left pending, and
//     returns them. A pending marker is itself a row in the folder, so an
//     erasure completed that way is only as trustworthy as the index was.
//   - A result identifies a chain: never log one beside its subject.
//
// # Assumptions
//
//   - The results came from this process's own erase calls.
func ConfirmErasures(results ...EraseResult) CheckpointOption {
	return func(c *checkpointConfig) {
		for _, r := range results {
			if r.ErasureEntryID == "" || r.Relinked {
				continue
			}
			if !ValidChainID(r.Chain) || !entryIDPattern.MatchString(r.ErasureEntryID) {
				c.err = errors.New("sink: ConfirmErasures: not a chain and an erasure entry of this sink")
				return
			}
			if c.confirmed == nil {
				c.confirmed = map[string]string{}
			}
			c.confirmed[r.Chain] = r.ErasureEntryID
		}
	}
}

// ConfirmErasedChains is the operator's explicit word that the erasure at the
// end of each chain named is their own, so that Checkpoint signs over it.
//
// # Description
//
// The sink can attribute an erasure only while the erase call's results are in
// hand (ConfirmErasures), or by its record signature. An honest erasure that
// missed both (erased without checkpointing in the same process, a crash in
// between, a checkpoint that failed, on a sink that does not sign) would
// otherwise never be checkpointed, and its chain would be refused on every
// run. This option covers that case: the caller names the chain, taken from
// Verify's report, and vouches for it.
//
// The chain must still be exactly in that state: it ends with a genuine
// erasure that no verified checkpoint covers, has no index row, and has no
// problem at all. A chain named that is not is reported with a Problem and
// nothing is signed for it.
//
// # Inputs
//
//   - chains: chain ids this sink mints; anything else makes Checkpoint fail
//
// # Outputs
//
//   - CheckpointOption: to pass to Checkpoint
//
// # Example
//
//	// rep.Chains[i].Index == sink.IndexErasedUnanchored, and you erased it:
//	done, err := s.Checkpoint(ctx, signer, nil, sink.ConfirmErasedChains(rep.Chains[i].Chain))
//
// # Limitations
//
//   - The sink cannot check the claim. A forged erasure vouched for this way
//     becomes a signed "erased". Use it only for an erasure you know you made.
//   - It names a chain: never take the id from, or put it into, anything that
//     also names the subject.
//
// # Assumptions
//
//   - The caller knows the erasure's origin from outside the folder.
func ConfirmErasedChains(chains ...string) CheckpointOption {
	return func(c *checkpointConfig) {
		for _, chain := range chains {
			if !ValidChainID(chain) {
				c.err = errors.New("sink: ConfirmErasedChains: not a chain id this sink mints")
				return
			}
			if c.vouched == nil {
				c.vouched = map[string]bool{}
			}
			c.vouched[chain] = true
		}
	}
}

// CheckpointRecordTrust makes Checkpoint check every record signature of the
// chains it signs, and accept an uncovered erasure whose own signature
// verifies.
//
// # Description
//
// With record trust Checkpoint verifies each chain as Verify does
// WithRecordTrust: every entry must carry a valid signature by a key src
// holds, or the chain is not checkpointed. A chain that ends with an erasure no
// checkpoint covers is then signed when the erasure entry's own signature
// verified and nothing else about the chain fails (no orphan signature rows
// either): the record key vouches for the erasure, as ConfirmErasures does for
// an unsigned sink.
//
// # Inputs
//
//   - src: the record keys, separate from the checkpoint keys. nil makes
//     Checkpoint fail.
//
// # Outputs
//
//   - CheckpointOption: to pass to Checkpoint
//
// # Example
//
//	done, err := s.Checkpoint(ctx, signer, nil, sink.CheckpointRecordTrust(recordKeys))
//
// # Limitations
//
//   - A chain with any unsigned or badly signed entry is refused, erased or
//     not: on a sink that does not sign, do not pass it.
//   - A leaked record key can sign an erasure. Until it is distrusted, that
//     erasure is accepted here.
//
// # Assumptions
//
//   - src is safe for concurrent use.
func CheckpointRecordTrust(src anchor.KeySource) CheckpointOption {
	return func(c *checkpointConfig) {
		if src == nil {
			c.err = errors.New("sink: CheckpointRecordTrust needs a key source")
			return
		}
		if v := reflect.ValueOf(src); v.Kind() == reflect.Pointer && v.IsNil() {
			c.err = errors.New("sink: CheckpointRecordTrust needs a key source (got a nil pointer)")
			return
		}
		c.recordTrust = src
	}
}

// TrackHeads makes Checkpoint keep each chain's series head in h, and refuse
// to extend a series that is shorter than its head or differs from it.
//
// # Description
//
// For every chain it looks at, Checkpoint asks h for the head. A series with
// fewer checkpoints than the head, or with another anchor chain hash at the
// head's number, "was cut or restarted": the chain is reported with that
// Problem and nothing is signed for it. After writing a checkpoint, the new
// head is recorded.
//
// A chain that has checkpoints but no head yet (h was first given after they
// were made), or whose head is behind its series (a run that stopped between
// writing a checkpoint and recording it), is verified in full, and its head is
// recorded if it verifies. That is trust on first use: a series restarted
// before h ever saw it is recorded as it stands.
//
// # Inputs
//
//   - h: where heads are kept; nil makes Checkpoint fail. A FileHeads file
//     inside the sink folder is refused.
//
// # Outputs
//
//   - CheckpointOption: to pass to Checkpoint
//
// # Example
//
//	heads := sink.FileHeads("/var/lib/proof-heads/sink-data.heads.json")
//	done, err := s.Checkpoint(ctx, signer, nil, sink.TrackHeads(heads))
//
// # Limitations
//
//   - Heads are written in batches and at the end of the run. A run killed
//     before that leaves heads behind their series; the next run catches up.
//   - It protects against someone who can rewrite the sink folder and not h.
//
// # Assumptions
//
//   - h is safe for concurrent use, and one process checkpoints at a time.
func TrackHeads(h CheckpointHeads) CheckpointOption {
	return func(c *checkpointConfig) {
		if h == nil {
			c.err = errors.New("sink: TrackHeads needs a CheckpointHeads")
			return
		}
		if v := reflect.ValueOf(h); v.Kind() == reflect.Pointer && v.IsNil() {
			c.err = errors.New("sink: TrackHeads needs a CheckpointHeads (got a nil pointer)")
			return
		}
		c.heads = h
	}
}

// OnlyChains limits Checkpoint to the chains named, instead of every chain in
// the evidence file.
//
// # Description
//
// For checkpointing the chains an erase call just erased, in the same run,
// without signing (or reporting) anything else. A chain named that the
// evidence file does not hold is skipped.
//
// # Inputs
//
//   - chains: chain ids this sink mints; anything else makes Checkpoint fail.
//     None at all means no chain: Checkpoint then does nothing.
//
// # Outputs
//
//   - CheckpointOption: to pass to Checkpoint
//
// # Example
//
//	done, err := s.Checkpoint(ctx, signer, nil, sink.ConfirmErasures(res.Erased...), sink.OnlyChains(chains...))
//
// # Limitations
//
//   - The list is held in memory.
//
// # Assumptions
//
//   - None.
func OnlyChains(chains ...string) CheckpointOption {
	return func(c *checkpointConfig) {
		c.onlySet = true
		for _, chain := range chains {
			if !ValidChainID(chain) {
				c.err = errors.New("sink: OnlyChains: not a chain id this sink mints")
				return
			}
			c.only = append(c.only, chain)
		}
	}
}

// Checkpoint signs one checkpoint for every chain with entries since its last.
//
// # Description
//
// Each checkpoint is a v6 anchor over the whole chain so far, linked to the
// chain's previous checkpoint, with the chain id as its subject. Nothing is
// signed that Verify would not pass: the chain is verified in full first (its
// links, its content against its commitments, its erasure, its index row), and
// the existing series must verify (under trusted) before anything is signed on
// top of it.
//
// A chain that ends with an erasure no checkpoint covers is signed only with
// evidence that the operator made the erasure: ConfirmErasures, or its record
// signature (CheckpointRecordTrust), or the operator's explicit word
// (ConfirmErasedChains). Without one it is not checkpointed, and Verify keeps
// reporting it as erased-unanchored.
//
// A chain that cannot be checkpointed (a broken chain, a malformed or
// unverifiable series, an unconfirmed erasure, a series behind its recorded
// head, an id this sink never writes) is reported in its Checkpointed.Problem,
// and the other chains are still checkpointed: one bad chain must not stop the
// rest.
//
// # Inputs
//
//   - ctx: honoured between chains
//   - signer: an ML-DSA-65 signer, e.g. from a `proof keygen --alg ml-dsa-65` key
//   - trusted: the keys the EXISTING checkpoints may be signed with. nil means
//     the signer's own key only. After a key rotation, pass the old public keys
//     here (with the new one), or no chain checkpointed under the old key could
//     ever be checkpointed again.
//   - opts: ConfirmErasures, ConfirmErasedChains, CheckpointRecordTrust,
//     TrackHeads, OnlyChains
//
// # Outputs
//
//   - []Checkpointed: one per chain that has entries since its last checkpoint:
//     the checkpoint written, or the Problem that prevented it. Empty if every
//     chain was already checkpointed.
//   - error: an operational failure (signing, reading or writing files, or
//     recording a head). The checkpoints written before it remain and are
//     valid. ErrCorrupt when a file of the folder is damaged.
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
//   - Verifies each chain with new entries in full before signing it (three
//     paged passes, reading every entry's content); a chain with nothing new
//     is skipped from its tail alone.
//   - An erasure the operator's own erase call completed because the index
//     had the chain marked pending is confirmed like any other: a pending
//     marker written into the index by someone else makes the sink itself
//     erase that chain. See docs/sink-format.md §6.
//   - Without TrackHeads it cannot tell that a chain's checkpoints were
//     deleted: it starts a new series at 0001.
//
// # Assumptions
//
//   - signer, trusted and any option's sources are safe for concurrent use.
func (s *Sink) Checkpoint(ctx context.Context, signer anchor.ContextSigner, trusted anchor.KeySource,
	opts ...CheckpointOption) (_ []Checkpointed, err error) {
	defer fault.Recover(&err)()
	if signer == nil {
		return nil, errors.New("sink: a signer is required")
	}
	var cfg checkpointConfig
	for _, o := range opts {
		o(&cfg)
		if cfg.err != nil {
			return nil, cfg.err
		}
	}
	if cfg.heads != nil {
		if err := s.headsOutsideFolder(cfg.heads); err != nil {
			return nil, err
		}
		cfg.heads = callerHeads{cfg.heads}
	}
	// The caller's own code, from here on called through wrappers: a panic in
	// it is the caller's, not a damaged file (see callbacks.go).
	signer = callerSigner{signer}
	if trusted != nil {
		trusted = callerKeys{trusted}
	}
	// Read-only on the folder's files (a checkpoint writes checkpoint files,
	// never entries), and a page at a time: the files are released between
	// pages, so a writer never waits for every chain to be checkpointed.
	if trusted == nil {
		signerID, signerPub, err := anchor.KeyIDOf(signer)
		if err != nil {
			return nil, fmt.Errorf("sink: %w", err)
		}
		if trusted, err = anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{signerID: signerPub}); err != nil {
			return nil, fmt.Errorf("sink: %w", err)
		}
	}
	var rc *recordChecker
	if cfg.recordTrust != nil {
		rc = &recordChecker{src: callerKeys{cfg.recordTrust}, keys: map[string][]byte{}}
	}
	var recorder *headRecorder
	if cfg.heads != nil {
		recorder = &headRecorder{heads: cfg.heads}
		// Whatever ends the run, the checkpoints it wrote get their heads: a
		// cancelled context must not leave them unrecorded.
		defer func() {
			if ferr := recorder.flush(context.WithoutCancel(ctx)); ferr != nil {
				err = errors.Join(err, ferr)
			}
		}()
	}

	var out []Checkpointed
	vouchedFor := map[string]bool{} // chains whose vouching was used
	skip := func(chain, problem string) {
		out = append(out, Checkpointed{Chain: chain, Problem: problem})
	}
	one := func(p *pageFiles, chain string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ValidChainID(chain) {
			skip(chain, "the evidence file holds a chain id this sink never writes; not checkpointed")
			return nil
		}
		anchors, problem, err := p.f.readAnchors(chain)
		if err != nil {
			return err
		}
		if problem != "" {
			skip(chain, problem+"; refusing to add to it")
			return nil
		}
		// The recorded head, before anything else: a series that was cut back
		// has "new" entries to sign, and signing them is the restart.
		recorded := true // nothing to record: no heads, or the head is the series
		if cfg.heads != nil {
			count, hash, ok, err := cfg.heads.Head(ctx, chain)
			if err != nil {
				return fmt.Errorf("sink: read the checkpoint heads: %w", err)
			}
			if ok {
				if hp := headProblem(anchors, count, hash); hp != "" {
					skip(chain, hp+"; refusing to add to it. If the checkpoints were removed, restore them")
					return nil
				}
			}
			recorded = len(anchors) == 0 || (ok && count == len(anchors))
		}
		var previous *anchor.Anchor
		nothingNew := false
		if len(anchors) > 0 {
			previous = &anchors[len(anchors)-1]
			// Nothing new since the last checkpoint: known from the tail alone,
			// without walking the chain.
			if _, tail, err := p.st.ReadTail(ctx, chain); err == nil && previous.EntryCount == tail+1 {
				if recorded {
					return nil
				}
				nothingNew = true // verified below, only to record its head
			}
		}
		notSigned := "so it was not signed: "
		if nothingNew {
			notSigned = "so its checkpoint head was not recorded: "
		}
		// Nothing is signed that Verify would not pass. A checkpoint is the
		// operator's signature over the chain as it stands, so the chain is
		// verified in full first: its links, its content against its
		// commitments, its erasure, its index row, its existing checkpoints.
		// Checking the links alone signed over content that had been modified
		// or deleted, and over an erasure written into the middle of a chain.
		row, err := p.ix.state(chain)
		if err != nil {
			return err
		}
		cr, err := s.verifyChain(ctx, p.st, p.sec, p.sig, rc, p.f, chain, trusted, row, chainChecks{})
		if err != nil {
			return err
		}
		if len(cr.Problems) > 0 {
			skip(chain, "it does not verify (its existing checkpoints are checked against the trusted "+
				"keys), "+notSigned+cr.Problems[0])
			return nil
		}
		// An erasure no checkpoint covers is keyless: signed only when the
		// caller made it (its entry id confirmed), or its record signature
		// verified (verifyChain then already reports the chain as erased).
		if cr.Index == IndexErasedUnanchored {
			last, err := lastEntryID(ctx, p.st, chain)
			if err != nil {
				return err
			}
			// Confirmed for THIS chain: an entry id is public, and could have
			// been copied onto another chain.
			switch {
			case cfg.confirmed[chain] == last:
			case cfg.vouched[chain]:
				vouchedFor[chain] = true
			default:
				skip(chain, erasureUnconfirmed)
				return nil
			}
		}
		// One more paged walk: it binds the existing series as it passes each
		// checkpoint's end (a planted or damaged checkpoint is reported, never
		// extended), and leaves the walker the new checkpoint is built from.
		w := verify.NewWalker(verify.Options{MaxBreaks: 1})
		series := newSeriesCheck(chain, anchors, trusted)
		total := 0
		if err := forEachEntry(ctx, p.st, chain, func(e store.Entry) {
			w.Add(toVerifyEntry(e))
			series.Reached(w)
			total++
		}); err != nil {
			return err
		}
		if len(anchors) > 0 {
			series.Finish(total)
			if len(series.Problems()) > 0 {
				skip(chain, "its checkpoints do not verify under the trusted keys: "+series.Problems()[0])
				return nil
			}
			if int64(total) == previous.EntryCount {
				// Nothing to sign: the series verified, and its head is recorded.
				if recorder != nil && !recorded {
					return recorder.add(ctx, chain, len(anchors), previous.ChainHash)
				}
				return nil
			}
		}
		unsigned, err := build.FromWalker(ctx, chain, w, previous, time.Time{})
		if errors.Is(err, build.ErrChainBroken) {
			skip(chain, err.Error())
			return nil
		}
		if err != nil {
			return fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		signed, err := anchor.SignAnchor(ctx, signer, unsigned)
		if err != nil {
			return fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		raw, err := json.MarshalIndent(signed, "", "  ")
		if err != nil {
			return fmt.Errorf("sink: chain %s: %w", chain, err)
		}
		dir := filepath.Join("anchors", chain)
		if err := p.f.mkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("sink: %w", err)
		}
		name := fmt.Sprintf("%04d.json", len(anchors)+1)
		if err := p.f.writeNew(filepath.Join(dir, name), raw, 0o644); err != nil {
			return err
		}
		out = append(out, Checkpointed{Chain: chain,
			File: filepath.Join("anchors", chain, name), Entries: signed.EntryCount})
		// The checkpoint is durable: now its head.
		if recorder != nil {
			return recorder.add(ctx, chain, len(anchors)+1, signed.ChainHash)
		}
		return nil
	}
	// The chains to look at: every chain in the evidence file, a page of ids at
	// a time, or only those named.
	only := append([]string(nil), cfg.only...)
	sort.Strings(only)
	at := 0
	var cursor *string // nil: from the first chain ("" can be a crafted chain id)
	err = s.inPages(ctx, true, func(p *pageFiles, deadline time.Time) (bool, error) {
		if cfg.onlySet {
			for started := at; at < len(only); at++ {
				if at > started && time.Now().After(deadline) {
					return false, nil
				}
				chain := only[at]
				if at > 0 && only[at-1] == chain {
					continue // named twice
				}
				if in, err := inStore(ctx, p, chain); err != nil {
					return false, err
				} else if !in {
					continue
				}
				if err := one(p, chain); err != nil {
					return false, err
				}
			}
			return true, nil
		}
		chains, err := p.st.ChainsAfter(ctx, cursor, pageMaxChains)
		if err != nil {
			return false, fmt.Errorf("sink: %w", err)
		}
		for i, chain := range chains {
			if i > 0 && time.Now().After(deadline) {
				return false, nil
			}
			cursor = &chains[i]
			if err := one(p, chain); err != nil {
				return false, err
			}
		}
		return len(chains) < pageMaxChains, nil
	}, nil)
	if err == nil {
		// A chain vouched for that was not in the state vouching is for: said,
		// not passed over. (One refused for another reason already has its row.)
		reported := map[string]bool{}
		for _, c := range out {
			reported[c.Chain] = true
		}
		names := make([]string, 0, len(cfg.vouched))
		for chain := range cfg.vouched {
			if !vouchedFor[chain] && !reported[chain] {
				names = append(names, chain)
			}
		}
		sort.Strings(names)
		for _, chain := range names {
			skip(chain, notAnUnconfirmedErasure)
		}
	}
	return out, err
}

// lastEntryID returns the id of a chain's last entry.
func lastEntryID(ctx context.Context, st *boltstore.Store, chain string) (string, error) {
	_, tail, err := st.ReadTail(ctx, chain)
	if err != nil {
		return "", fmt.Errorf("sink: read chain %s: %w", chain, err)
	}
	rows, err := st.Range(ctx, chain, tail, tail, 1)
	if err != nil {
		return "", fmt.Errorf("sink: read chain %s's last entry: %w", chain, err)
	}
	if len(rows) != 1 {
		return "", fmt.Errorf("sink: chain %s: its last entry is not where its tail says", chain)
	}
	return rows[0].EntryID, nil
}
