// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	boltstore "github.com/aleutian-ai/proof/store/bolt"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store"
)

// Commit commits records, each to the chain its key names.
//
// # Description
//
// Every record is validated before any file is touched. Records are then
// grouped by chain, keeping their order, and each chain gets one atomic append.
// For each record: a salted commitment goes on the chain, the content goes to
// content/<chain>/, and the nonce to the nonce file. Content and nonces are
// written BEFORE the append, and removed again if it fails: an entry whose
// content was never stored could never be opened.
//
// Entry ids and timestamps are assigned here, never taken from the records.
//
// A record with a Source is committed at most once per chain, across calls and
// crashes: its position is recorded (in evidence.db.sources) before the append,
// and checked against the chain on every later Commit of that Source. A crash
// between the two leaves a recorded position that is not on the chain, and the
// record is then committed normally. This is what lets a streaming consumer
// acknowledge after committing without committing a redelivery twice.
//
// # Inputs
//
//   - ctx: honoured by the append
//   - records: 1 to MaxBatch records
//
// # Outputs
//
//   - []Committed: per chain, in order of first appearance. On error, the chains
//     committed before the failure.
//   - error: a record is invalid (nothing written), or one chain's append failed.
//     Each chain is atomic; the batch as a whole is not.
func (s *Sink) Commit(ctx context.Context, records []Record) ([]Committed, error) {
	if n := len(records); n == 0 || n > MaxBatch {
		return nil, fmt.Errorf("sink: commit 1 to %d records, got %d", MaxBatch, n)
	}
	type pair struct{ class, subject string }
	var order []pair
	groups := map[pair][]Record{}
	sourced := false
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return nil, &RecordError{Index: i, Err: err}
		}
		p := pair{r.Class, r.Subject}
		if r.Source != "" {
			sourced = true
		}
		if _, seen := groups[p]; !seen {
			order = append(order, p)
		}
		groups[p] = append(groups[p], r)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The first Commit creates the folder; nothing else does.
	f, err := s.openFolder(true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, ns, err := s.openFiles()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	defer ns.Close()
	// Opened only when needed, so a sink that never sees a Source has no
	// sources file.
	var src *sourcesStore
	if sourced {
		if src, err = openSources(s.sourcesPath(), s.lockTimeout); err != nil {
			return nil, err
		}
		defer src.Close()
	}
	// The subject index. The evidence file is opened first by every writer, and
	// its exclusive lock is what serializes them: whoever holds it can open the
	// secret files in any order without deadlock (erase opens them in another
	// order). Readers open the evidence file first too (a shared lock), so none
	// can hold a secret file while a writer holds the evidence file.
	subj, err := openSubjects(s.subjectsPath(), s.lockTimeout)
	if err != nil {
		return nil, err
	}
	defer subj.Close()
	l, err := linker.New(st)
	if err != nil {
		return nil, fmt.Errorf("sink: prepare the chains: %w", err)
	}

	var done []Committed
	for _, p := range order {
		chain, err := s.resolveChain(ctx, st, subj, p.class, p.subject)
		if err != nil {
			return done, err
		}
		c, err := s.commitChain(ctx, l, st, ns, src, f, chain, groups[p])
		if err != nil {
			return done, fmt.Errorf("sink: chain %s: %w (chains before it in this batch were committed)",
				chain, err)
		}
		c.Class, c.Subject = p.class, p.subject
		done = append(done, c)
	}
	return done, nil
}

// resolveChain returns the chain of a (class, subject) pair, minting one when
// the pair is new.
//
// A new pair's index rows are written HERE, before its chain has any entry:
// so a chain never exists without its row, and erasing the subject always finds
// it. A crash after this and before the append leaves a row with no chain, which
// is harmless: the next commit of the pair reuses it, and erasing the subject
// cleans it up.
func (s *Sink) resolveChain(ctx context.Context, st *boltstore.Store, subj *subjectsStore,
	class, subject string) (string, error) {
	chain, ok, err := subj.lookup(subject, class)
	if err != nil || ok {
		return chain, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		if chain, err = s.mintChainID(class); err != nil {
			return "", err
		}
		if !ValidChainID(chain) || !strings.HasPrefix(chain, class+".") {
			return "", fmt.Errorf("sink: minted an invalid chain id for class %s; nothing was bound", class)
		}
		// 128 random bits do not collide in practice, but a collision would
		// merge two subjects' histories, so it is checked, not assumed: the id
		// must be unused both in the store and in the index.
		_, _, terr := st.ReadTail(ctx, chain)
		if terr == nil {
			continue // the id has entries already: taken
		}
		if !errors.Is(terr, store.ErrEmptyChain) {
			return "", fmt.Errorf("sink: check a new chain id is unused: %w", terr)
		}
		if taken, err := subj.taken(chain); err != nil || taken { // live OR pending
			continue
		}
		if err := subj.bind(subject, class, chain); err != nil {
			return "", err
		}
		return chain, nil
	}
	return "", errors.New("sink: could not mint an unused chain id; the random source is suspect")
}

// dropDuplicates removes records whose Source is already committed on the
// chain, or repeated earlier in the batch.
func dropDuplicates(ctx context.Context, st *boltstore.Store, src *sourcesStore, chain string,
	recs []Record) ([]Record, int, error) {
	if src == nil {
		return recs, 0, nil
	}
	keep := make([]Record, 0, len(recs))
	inBatch := map[string]bool{}
	dups := 0
	for _, r := range recs {
		if r.Source == "" {
			keep = append(keep, r)
			continue
		}
		if inBatch[r.Source] {
			dups++
			continue
		}
		inBatch[r.Source] = true
		p, found, err := src.get(chain, r.Source)
		if err != nil {
			return nil, 0, err
		}
		if found {
			// Recorded. Committed only if the chain holds that entry at that
			// position; otherwise the earlier attempt stopped before its append.
			rows, err := st.Range(ctx, chain, p.seq, p.seq, 1)
			if err != nil {
				return nil, 0, fmt.Errorf("check source position: %w", err)
			}
			if len(rows) == 1 && rows[0].EntryID == p.entryID {
				dups++
				continue
			}
		}
		keep = append(keep, r)
	}
	return keep, dups, nil
}

// commitChain appends one chain's records in a single atomic append.
func (s *Sink) commitChain(ctx context.Context, l *linker.Linker, st *boltstore.Store,
	ns *noncestore.Store, src *sourcesStore, f *folder, chain string, recs []Record) (Committed, error) {
	recs, dups, err := dropDuplicates(ctx, st, src, chain, recs)
	if err != nil {
		return Committed{}, err
	}
	out := Committed{Chain: chain, Entries: len(recs), Duplicates: dups}
	if len(recs) == 0 {
		return out, nil
	}
	if err := s.appendChain(ctx, l, st, ns, src, f, chain, recs); err != nil {
		return Committed{}, err
	}
	return out, nil
}

// The three writes appendChain makes, each as the smallest interface it needs.
// Production passes the real stores; a test passes one that fails, to prove that
// whatever failed part-way leaves nothing behind.
type (
	nonceWriter interface {
		PutBatch(chain string, nonces map[string][]byte) error
		DeleteBatch(chain string, entryIDs []string) error
	}
	positionWriter interface {
		putBatch(chain string, positions map[string]position) error
	}
	appender interface {
		Append(ctx context.Context, chain string, inputs []linker.Input) (linker.Result, error)
	}
)

// appendChain writes content, nonces and source positions, then appends.
//
// Order and failure: content files, then nonces, then positions, then the
// append. If any of them fails, everything written before it is removed:
// content files and nonces (the secrets). Positions are left; a position with no
// entry behind it is harmless, because the next Commit of that source checks the
// chain and commits it.
func (s *Sink) appendChain(ctx context.Context, l appender, st *boltstore.Store,
	ns nonceWriter, src positionWriter, f *folder, chain string, recs []Record) error {
	if err := f.mkdirAll(filepath.Join("content", chain), 0o700); err != nil {
		return fmt.Errorf("create content folder: %w", err)
	}
	// The sequence the first entry will get. Nothing else can append meanwhile:
	// this process holds Sink.mu and the evidence file's lock.
	next := int64(0)
	if _, tail, err := st.ReadTail(ctx, chain); err == nil {
		next = tail + 1
	} else if !errors.Is(err, store.ErrEmptyChain) {
		return fmt.Errorf("read chain tail: %w", err)
	}
	positions := map[string]position{}
	// Stamped now, one microsecond apart: the linker orders a batch by arrival
	// and hashes timestamps at microsecond precision. The chain's sequence, not
	// these, is the authoritative order.
	now := time.Now().UTC().Truncate(time.Microsecond)
	inputs := make([]linker.Input, len(recs))
	nonces := make(map[string][]byte, len(recs))
	var written []string
	cleanup := func() {
		for _, p := range written {
			_ = f.root.Remove(p)
		}
		ids := make([]string, 0, len(nonces))
		for id := range nonces {
			ids = append(ids, id)
		}
		_ = ns.DeleteBatch(chain, ids)
		if next == 0 {
			// A first commit created the folder: remove it too, or Verify would
			// report a removed chain. Leftovers of an earlier attempt keep it
			// (the removal fails on a non-empty folder), for erasure to find.
			_ = f.root.Remove(filepath.Join("content", chain))
		}
	}

	for i, r := range recs {
		id, err := newEntryID()
		if err != nil {
			cleanup()
			return err
		}
		c, nonce, err := commitment.Salted(r.Content)
		if err != nil {
			cleanup()
			return err
		}
		path := contentName(chain, id)
		if err := f.writeNew(path, r.Content, 0o600); err != nil {
			cleanup()
			return err
		}
		written = append(written, path)
		nonces[id] = nonce
		stamp := now.Add(time.Duration(i) * time.Microsecond)
		inputs[i] = linker.Input{EntryID: id, EntryType: EntryTypeEvent,
			Timestamp: stamp, ContentHash: c, IngestedAt: stamp}
		if r.Source != "" {
			// Strictly increasing stamps keep the linker's arrival order equal to
			// this order, so entry i lands at next+i.
			positions[r.Source] = position{entryID: id, seq: next + int64(i)}
		}
	}
	if err := ns.PutBatch(chain, nonces); err != nil {
		cleanup()
		return fmt.Errorf("store nonces: %w", err)
	}
	// Positions go down BEFORE the append. A position with no entry behind it is
	// harmless: the next Commit of that source sees it is not on the chain. An
	// entry with no position is the duplicate this exists to prevent.
	if len(positions) > 0 {
		if err := src.putBatch(chain, positions); err != nil {
			cleanup()
			return fmt.Errorf("record sources: %w", err)
		}
	}
	res, err := l.Append(ctx, chain, inputs)
	if err != nil && !errors.Is(err, linker.ErrHeadStateStale) {
		// ErrHeadStateStale means the entries ARE written; only the saved head
		// record lags, and the next append repairs it. Anything else: nothing was
		// written, so nothing may be left behind.
		cleanup()
		return fmt.Errorf("append: %w", err)
	}
	if len(positions) > 0 && res.FirstSeq != next {
		// Cannot happen while this process holds the file. If it ever does, the
		// entries ARE committed, so this must not look like a failure (the caller
		// would retry and commit twice). Re-record the positions from the actual
		// sequence instead: the batch order is kept, so entry i is at FirstSeq+i.
		for i, r := range recs {
			if r.Source != "" {
				positions[r.Source] = position{entryID: inputs[i].EntryID, seq: res.FirstSeq + int64(i)}
			}
		}
		if err := src.putBatch(chain, positions); err != nil {
			return fmt.Errorf("committed, but correcting the source positions failed: %w; "+
				"a redelivery of this batch may be committed again", err)
		}
	}
	return nil
}
