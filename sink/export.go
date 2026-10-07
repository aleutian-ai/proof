// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// BundleFormat is the export bundle format this sink writes (docs/bundle-format.md).
const BundleFormat = "aleutian.proof.bundle.v1"

// Bundle limits (bundle-format.md §5). An exporter never writes a bundle that
// conforming verifiers must refuse. Variables only so tests can shrink them.
var (
	maxBundleBytes       int64 = 256 << 20
	maxBundleChains            = 100_000
	maxBundleEntries           = 1_000_000
	maxBundleCheckpoints       = 100_000
)

// Export errors. Each is wrapped with what failed; positions, never ids.
var (
	// ErrExportEmpty: the selection matched no chain. An empty bundle proves
	// nothing and verifies as unauthenticated, so none is written.
	ErrExportEmpty = errors.New("sink: the selection matched no chain; nothing to export")
	// ErrExportTooLarge: the bundle would exceed bundle-format.md §5's limits.
	ErrExportTooLarge = errors.New("sink: the export would exceed the bundle limits; narrow the selection")
	// ErrExportUnrepresentable: the folder holds something bundle.v1 cannot
	// represent faithfully. The export fails rather than hide it.
	ErrExportUnrepresentable = errors.New("sink: the folder holds what a bundle cannot represent faithfully")
	// ErrDisclosure: a requested disclosure cannot be honoured.
	ErrDisclosure = errors.New("sink: a requested disclosure cannot be made")
	// ErrExportSelection: the selection itself is not valid (a caller's mistake).
	ErrExportSelection = errors.New("sink: the export selection is not valid")
)

// Disclose says which events' content and nonces an export includes.
type Disclose int

const (
	// DiscloseNone: no content and no nonces (integrity only). The default.
	DiscloseNone Disclose = iota
	// DiscloseAll: every live event's content and nonce.
	DiscloseAll
	// DiscloseListed: exactly the events named in ExportSelection.DiscloseIDs.
	DiscloseListed
)

// ExportSelection is what an export includes. Exactly one of Chains,
// Subject or All selects the chains.
type ExportSelection struct {
	// Chains are chain ids to export, in this order.
	Chains []string
	// Subject exports the subject's chains, found through the secret index
	// (in Class only, when set). The subject is never written to the bundle.
	Subject string
	// Class narrows Subject to one class.
	Class string
	// All exports every chain in the folder.
	All bool
	// Disclose says which events' content and nonces are included.
	Disclose Disclose
	// DiscloseIDs are the entry ids to disclose, with DiscloseListed. Each must
	// be exactly one live event in the selected chains. Repeats count once.
	DiscloseIDs []string
}

// ExportSummary is what an export wrote: for the operator, never part of the
// bundle.
type ExportSummary struct {
	Chains      int
	Entries     int
	Checkpoints int
	Disclosed   int
	// CheckpointKeyIDs and RecordKeyIDs are the key ids that signed what was
	// exported, sorted: the public keys the recipient will need.
	CheckpointKeyIDs []string
	RecordKeyIDs     []string
	// IncompleteErasures counts chains whose events before an erasure still
	// have content in this folder (`proof sink erase --resume` finishes them).
	// That content is never disclosed.
	IncompleteErasures int
	// PendingErasures counts chains whose subject is forgotten but whose
	// erasure is not finished. They are exported for integrity, and nothing on
	// them is disclosed (`proof sink erase --resume` finishes them).
	PendingErasures int
}

// Export writes the selected chains to w as a bundle (docs/bundle-format.md).
//
// # Description
//
// Each chain is read whole under one lock hold, with a pause between chains,
// as VerifyEach does, so a live writer is not starved. A multi-chain export is
// therefore NOT one snapshot of the folder: each chain is as it was when it
// was read.
//
// The bundle carries no subject, no source position, no index row and no key.
// It carries content and nonces only for the events Disclose names. It is
// still pseudonymous personal data (bundle-format.md §2).
//
// Damage is never repaired or hidden. A signature row is exported exactly
// (split at its storage boundary). What bundle.v1 cannot represent faithfully
// fails the whole export (ErrExportUnrepresentable): an invalid chain id, a
// gap or stray file among a chain's checkpoints, checkpoint text that is not
// UTF-8, an unreadable signatures file, or a live event asked to be disclosed
// whose content or nonce is missing.
//
// # Inputs
//
//   - ctx: cancels between chains and within long reads.
//   - sel: what to export.
//   - w: where the bundle goes.
//
// # Outputs
//
//   - ExportSummary: what was written.
//   - error: on any error, what was already written to w is NOT a bundle;
//     discard it. ErrExportEmpty, ErrExportTooLarge, ErrExportUnrepresentable
//     and ErrDisclosure name the cause.
//
// # Example
//
//	f, _ := os.CreateTemp(dir, ".bundle-*")
//	sum, err := s.Export(ctx, sink.ExportSelection{Subject: "u-81"}, f)
//	if err != nil {
//	    os.Remove(f.Name())
//	    return err
//	}
//
// # Limitations
//
//   - One huge chain holds the lock for its own duration.
//   - Exported before an erasure, a bundle keeps what it holds: a later
//     erasure does not reach it (bundle-format.md §2).
//
// # Assumptions
//
//   - The caller writes w to a temporary file and keeps it only on success.
func (s *Sink) Export(ctx context.Context, sel ExportSelection, w io.Writer) (ExportSummary, error) {
	var sum ExportSummary
	listed, err := checkSelection(sel)
	if err != nil {
		return sum, err
	}
	chains, err := s.exportChains(ctx, sel)
	if err != nil {
		return sum, err
	}
	if len(chains) == 0 {
		return sum, ErrExportEmpty
	}
	if len(chains) > maxBundleChains {
		return sum, fmt.Errorf("%w: %d chains, at most %d", ErrExportTooLarge, len(chains), maxBundleChains)
	}

	cw := &countingWriter{w: bufio.NewWriterSize(w, 1<<16)}
	ex := &exporter{sel: sel, listedSet: map[string]bool{}, found: map[string]int{}, cw: cw,
		cpKeys: map[string]bool{}, recKeys: map[string]bool{}}
	for _, id := range listed {
		ex.listedSet[id] = true
	}
	cw.str(`{"format":`)
	cw.json(BundleFormat)
	cw.str(`,"chains":[`)
	for i, chain := range chains {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		if i > 0 {
			cw.str(",")
			if err := pause(ctx); err != nil {
				return sum, err
			}
		}
		err := func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			p, err := s.openPage(true)
			if err != nil {
				return err
			}
			defer p.close()
			return ex.chain(ctx, p, i, chain)
		}()
		if err != nil {
			return sum, err
		}
		if cw.err != nil {
			return sum, fmt.Errorf("sink: export: %w", cw.err)
		}
		if cw.n > maxBundleBytes {
			return sum, fmt.Errorf("%w: over %d bytes", ErrExportTooLarge, maxBundleBytes)
		}
	}
	cw.str("]}")
	if err := cw.flush(); err != nil {
		return sum, fmt.Errorf("sink: export: %w", err)
	}
	if cw.n > maxBundleBytes {
		return sum, fmt.Errorf("%w: over %d bytes", ErrExportTooLarge, maxBundleBytes)
	}
	for _, id := range listed {
		switch ex.found[id] {
		case 0:
			return sum, fmt.Errorf("%w: a listed entry is not a live event in the selected chains", ErrDisclosure)
		case 1:
		default:
			return sum, fmt.Errorf("%w: a listed entry id matches more than one event", ErrDisclosure)
		}
	}
	sum = ExportSummary{Chains: len(chains), Entries: ex.entries, Checkpoints: ex.checkpoints,
		Disclosed: ex.disclosed, CheckpointKeyIDs: sortedKeys(ex.cpKeys), RecordKeyIDs: sortedKeys(ex.recKeys),
		IncompleteErasures: ex.incomplete, PendingErasures: ex.pending}
	return sum, nil
}

// checkSelection validates sel, returning the listed disclosure ids, deduplicated.
func checkSelection(sel ExportSelection) ([]string, error) {
	n := 0
	if len(sel.Chains) > 0 {
		n++
	}
	if sel.Subject != "" {
		n++
	}
	if sel.All {
		n++
	}
	if n != 1 {
		return nil, fmt.Errorf("%w: export exactly one of: chains, a subject, or all", ErrExportSelection)
	}
	if sel.Class != "" && sel.Subject == "" {
		return nil, fmt.Errorf("%w: a class narrows a subject's export; give a subject", ErrExportSelection)
	}
	if sel.Class != "" && !ValidClass(sel.Class) {
		return nil, fmt.Errorf("%w: class", ErrExportSelection)
	}
	if sel.Subject != "" && !ValidSubject(sel.Subject) {
		return nil, fmt.Errorf("%w: subject", ErrExportSelection)
	}
	seen := map[string]bool{}
	for i, c := range sel.Chains {
		if !ValidChainID(c) {
			return nil, fmt.Errorf("%w: chain #%d is not a chain id", ErrExportSelection, i)
		}
		if seen[c] {
			return nil, fmt.Errorf("%w: chain #%d is named twice", ErrExportSelection, i)
		}
		seen[c] = true
	}
	switch sel.Disclose {
	case DiscloseNone, DiscloseAll:
		if len(sel.DiscloseIDs) > 0 {
			return nil, fmt.Errorf("%w: disclosure ids need DiscloseListed", ErrExportSelection)
		}
		return nil, nil
	case DiscloseListed:
	default:
		return nil, fmt.Errorf("%w: unknown disclosure policy", ErrExportSelection)
	}
	if len(sel.DiscloseIDs) == 0 {
		return nil, fmt.Errorf("%w: DiscloseListed needs at least one entry id", ErrExportSelection)
	}
	var out []string
	dup := map[string]bool{}
	for _, id := range sel.DiscloseIDs {
		if !entryIDPattern.MatchString(id) {
			return nil, fmt.Errorf("%w: a listed id is not an entry id", ErrDisclosure)
		}
		if !dup[id] {
			dup[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// exportChains resolves the selection to chain ids, in export order.
func (s *Sink) exportChains(ctx context.Context, sel ExportSelection) ([]string, error) {
	switch {
	case len(sel.Chains) > 0:
		return sel.Chains, nil
	case sel.Subject != "":
		s.mu.Lock()
		defer s.mu.Unlock()
		p, err := s.openPage(true)
		if err != nil {
			return nil, err
		}
		defer p.close()
		if p.subj == nil {
			return nil, nil
		}
		chains, err := p.subj.chainsOf(sel.Subject, sel.Class)
		if err != nil {
			return nil, fmt.Errorf("sink: read the subject index: %w", err)
		}
		sort.Strings(chains)
		return chains, nil
	default:
		var all []string
		var cursor *string
		for {
			var page []string
			err := func() error {
				s.mu.Lock()
				defer s.mu.Unlock()
				p, err := s.openPage(false)
				if err != nil {
					return err
				}
				defer p.close()
				page, err = p.st.ChainsAfter(ctx, cursor, pageMaxChains)
				return err
			}()
			if err != nil {
				return nil, fmt.Errorf("sink: list chains: %w", err)
			}
			all = append(all, page...)
			if len(all) > maxBundleChains {
				return all, nil // the caller reports it as too large
			}
			if len(page) < pageMaxChains {
				return all, nil
			}
			last := page[len(page)-1]
			cursor = &last
			if err := pause(ctx); err != nil {
				return nil, err
			}
		}
	}
}

// pause is the gap between chains, with nothing held (as inPages does).
func pause(ctx context.Context) error {
	if betweenPages != nil {
		betweenPages()
	}
	t := time.NewTimer(pageGap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// exporter is one export's state.
type exporter struct {
	sel       ExportSelection
	listedSet map[string]bool
	found     map[string]int // listed id → events matched
	cw        *countingWriter
	cpKeys    map[string]bool
	recKeys   map[string]bool

	entries, checkpoints, disclosed, incomplete, pending int
}

// hex32 is a key id's shape; hex128 a hash's.
var (
	hex32  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// tooBig reports whether the bundle written so far is over the byte limit.
func (ex *exporter) tooBig() error {
	if ex.cw.n > maxBundleBytes {
		return fmt.Errorf("%w: over %d bytes", ErrExportTooLarge, maxBundleBytes)
	}
	return nil
}

// readEntries reads a chain's entries a page at a time, stopping as soon as
// the bundle's entry limit would be passed (never holding more than it
// allows), and checking for cancellation between pages. Errors name the chain
// by position: a chain id beside the caller's subject would be a row of the
// secret index.
func (ex *exporter) readEntries(ctx context.Context, p *pageFiles, pos int, chain string) ([]store.Entry, error) {
	var rows []store.Entry
	start := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := p.st.Range(ctx, chain, start, 1<<62, entryPage)
		if err != nil {
			return nil, fmt.Errorf("sink: chain #%d: read: %w", pos, redact(err))
		}
		if ex.entries+len(rows)+len(page) > maxBundleEntries {
			return nil, fmt.Errorf("%w: over %d entries", ErrExportTooLarge, maxBundleEntries)
		}
		rows = append(rows, page...)
		if len(page) < entryPage {
			return rows, nil
		}
		next := page[len(page)-1].GlobalSeq + 1
		if next <= start {
			return nil, fmt.Errorf("%w: chain #%d: an entry's stored sequence does not match its position",
				ErrExportUnrepresentable, pos)
		}
		start = next
	}
}

// representable refuses an entry bundle.v1 cannot carry faithfully: a chain
// format other than v3 (a bundle verifier would report a hash mismatch where
// the folder reports the format), or a timestamp outside years 0001-9999 (no
// format-spec §4 timestamp can express it).
func representable(r store.Entry) bool {
	if r.FormatVersion != chainformat.FormatV3 {
		return false
	}
	y := r.Timestamp.UTC().Year()
	return y >= 1 && y <= 9999
}

// wellFormed is bundle-format.md §7.1's well-formedness, for the fields the
// store can hold out of shape.
func wellFormed(r store.Entry) bool {
	return entryIDPattern.MatchString(r.EntryID) && r.GlobalSeq >= 0 &&
		(r.PreviousHash == "" || hex128.MatchString(r.PreviousHash)) &&
		hex128.MatchString(r.ContentHash) && hex128.MatchString(r.ChainHash)
}

// chain writes one chain, read under the page p holds.
func (ex *exporter) chain(ctx context.Context, p *pageFiles, pos int, chain string) error {
	if !ValidChainID(chain) {
		return fmt.Errorf("%w: chain #%d has an invalid id", ErrExportSelection, pos)
	}
	if p.sigErr != nil {
		return fmt.Errorf("%w: the signatures file is not one this sink writes", ErrExportUnrepresentable)
	}
	rows, err := ex.readEntries(ctx, p, pos, chain)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		// Bound in the index but never appended (a first commit that stopped),
		// or not in this folder at all: nothing a bundle can carry.
		return fmt.Errorf("%w: chain #%d has no entries in this folder", ErrExportEmpty, pos)
	}
	for _, r := range rows {
		if !representable(r) {
			return fmt.Errorf("%w: chain #%d holds an entry that is not chain format v3, "+
				"or whose timestamp is outside years 0001-9999", ErrExportUnrepresentable, pos)
		}
	}
	ex.entries += len(rows)
	texts, err := readAnchorTexts(p.f, chain, maxBundleCheckpoints-ex.checkpoints, maxBundleBytes-ex.cw.n)
	if err != nil {
		if errors.Is(err, ErrExportTooLarge) {
			return err
		}
		return fmt.Errorf("%w: chain #%d: %v", ErrExportUnrepresentable, pos, redact(err))
	}
	ex.checkpoints += len(texts)

	// E: the last well-formed entry, after a well-formed predecessor, holding
	// the erasure hash for its position, whatever its label (bundle-format.md
	// §7.3). Events before it are erased: never disclosed.
	erasedBefore := -1
	for i := len(rows) - 1; i >= 1; i-- {
		if wellFormed(rows[i]) && wellFormed(rows[i-1]) &&
			rows[i].ContentHash == erasureHash(erasureRecord(rows[i-1].GlobalSeq)) {
			erasedBefore = i
			break
		}
	}
	// A genuine erasure (labelled so) is what `erase --resume` acts on: only
	// then is leftover content an incomplete erasure worth reporting.
	genuine := erasedBefore >= 0 && rows[erasedBefore].EntryType == EntryTypeErasure
	// A chain whose subject is forgotten but whose erasure is not finished:
	// nothing on it is ever disclosed.
	pending := p.ix.state(chain) == IndexPending

	cw := ex.cw
	cw.str(`{"chain_id":`)
	cw.json(chain)
	cw.str(`,"entries":[`)
	incomplete, withheld := false, false
	for i, r := range rows {
		if i > 0 {
			cw.str(",")
		}
		cw.str(`{"entry_id":`)
		cw.json(r.EntryID)
		cw.str(`,"entry_type":`)
		cw.json(r.EntryType)
		cw.str(`,"global_seq":`)
		cw.json(strconv.FormatInt(r.GlobalSeq, 10))
		cw.str(`,"previous_hash":`)
		cw.json(r.PreviousHash)
		cw.str(`,"timestamp":`)
		cw.json(r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"))
		cw.str(`,"content_hash":`)
		cw.json(r.ContentHash)
		cw.str(`,"chain_hash":`)
		cw.json(r.ChainHash)
		if err := ex.signature(p, chain, r.EntryID); err != nil {
			return err
		}
		d, err := ex.disclosure(p, pos, chain, r, i < erasedBefore, i == erasedBefore, pending)
		if err != nil {
			return err
		}
		incomplete = incomplete || (genuine && d.leftover)
		withheld = withheld || d.withheld
		if d.disclosed {
			ex.disclosed++
		}
		cw.str("}")
		if err := ex.tooBig(); err != nil {
			return err
		}
		if i%entryPage == entryPage-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	if incomplete {
		ex.incomplete++
	}
	if withheld {
		ex.pending++
	}
	cw.str(`],"checkpoints":[`)
	for i, t := range texts {
		if i > 0 {
			cw.str(",")
		}
		cw.json(string(t))
		if err := ex.tooBig(); err != nil {
			return err
		}
		var head struct {
			SigningKeyID string `json:"signing_key_id"`
		}
		if json.Unmarshal(t, &head) == nil && hex32.MatchString(head.SigningKeyID) {
			ex.cpKeys[head.SigningKeyID] = true
		}
	}
	cw.str("]}")
	return ex.tooBig()
}

// signature writes an entry's record_signature member, if it has a row:
// exactly as stored, split at the storage boundary (key id ‖ signature),
// whatever its length. Never repaired, padded or omitted.
func (ex *exporter) signature(p *pageFiles, chain, entryID string) error {
	if p.sig == nil {
		return nil
	}
	raw, found, err := p.sig.raw(chain, entryID)
	if err != nil {
		return fmt.Errorf("sink: read a signature row: %w", redact(err))
	}
	if !found {
		return nil
	}
	cut := min(len(raw), signatureKeyIDSize)
	keyID := hex.EncodeToString(raw[:cut])
	ex.cw.str(`,"record_signature":{"key_id":`)
	ex.cw.json(keyID)
	ex.cw.str(`,"signature":`)
	ex.cw.json(base64.StdEncoding.EncodeToString(raw[cut:]))
	ex.cw.str("}")
	if len(raw) == signatureRowSize && hex32.MatchString(keyID) {
		ex.recKeys[keyID] = true
	}
	return nil
}

// disclosed is what disclosure did with one entry.
type disclosed struct {
	disclosed bool // content and nonce were written
	leftover  bool // erased, yet content or a nonce is still in this folder
	withheld  bool // wanted, but its chain's erasure is pending
}

// disclosure writes an event's disclosed member when the policy asks for it.
// Erased events, events on a chain whose erasure is pending, and erasure
// records are never disclosed. A live event asked for whose content or nonce
// is missing or damaged fails the export: leaving it out would read as
// `committed`, hiding the damage.
func (ex *exporter) disclosure(p *pageFiles, pos int, chain string, r store.Entry,
	erased, isErasure, pending bool) (disclosed, error) {
	listed := ex.listedSet[r.EntryID]
	// The entry holding the erasure hash is the erasure record, whatever its
	// label says: never an event to disclose.
	if r.EntryType != EntryTypeEvent || isErasure {
		if listed {
			return disclosed{}, fmt.Errorf("%w: a listed entry is not an event", ErrDisclosure)
		}
		return disclosed{}, nil
	}
	want := ex.sel.Disclose == DiscloseAll || listed
	var content, nonce []byte
	var tooBig bool
	if p.sec != nil {
		var err error
		if content, nonce, tooBig, err = p.sec.get(chain, r.EntryID); err != nil {
			return disclosed{}, fmt.Errorf("sink: read a content row: %w", redact(err))
		}
	}
	defer clear(nonce)
	present := content != nil || nonce != nil || tooBig
	switch {
	case erased:
		if listed {
			return disclosed{leftover: present}, fmt.Errorf("%w: a listed entry is erased", ErrDisclosure)
		}
		return disclosed{leftover: present}, nil // `all` skips erased events
	case pending && want:
		if listed {
			return disclosed{}, fmt.Errorf("%w: a listed entry is on a chain whose erasure is pending "+
				"(proof sink erase --resume finishes it)", ErrDisclosure)
		}
		return disclosed{withheld: true}, nil
	case !want:
		return disclosed{}, nil
	}
	if listed {
		ex.found[r.EntryID]++
	}
	switch {
	case tooBig:
		return disclosed{}, fmt.Errorf("%w: chain #%d: an event's content is over the limit", ErrExportUnrepresentable, pos)
	case content == nil || nonce == nil:
		return disclosed{}, fmt.Errorf("%w: chain #%d: a live event's content or nonce is missing", ErrExportUnrepresentable, pos)
	case len(nonce) != commitmentNonceSize:
		return disclosed{}, fmt.Errorf("%w: chain #%d: a live event's stored nonce is damaged", ErrExportUnrepresentable, pos)
	}
	ex.cw.str(`,"disclosed":{"content":`)
	ex.cw.json(base64.StdEncoding.EncodeToString(content))
	ex.cw.str(`,"nonce":`)
	ex.cw.json(hex.EncodeToString(nonce))
	ex.cw.str("}")
	return disclosed{disclosed: true}, nil
}

// commitmentNonceSize is a salted commitment's nonce length (format-spec §8).
const commitmentNonceSize = 32

// readAnchorTexts returns a chain's checkpoint files, exactly, in number
// order: nil when it has none. A gap, a stray file, a non-regular file, or
// text that is not UTF-8 (a JSON string cannot carry it unchanged) is an error.
// It stops with ErrExportTooLarge as soon as the files exceed maxCount, or
// their text exceeds maxBytes, never reading further.
func readAnchorTexts(f *folder, chain string, maxCount int, maxBytes int64) ([][]byte, error) {
	dir := filepath.Join("anchors", chain)
	ents, err := f.list(dir)
	if errors.Is(err, errNotRealDir) {
		return nil, fmt.Errorf("its checkpoint folder is %v", errNotRealDir)
	}
	if err != nil {
		return nil, err
	}
	if len(ents) > maxCount {
		return nil, fmt.Errorf("%w: over %d checkpoints", ErrExportTooLarge, maxBundleCheckpoints)
	}
	type numbered struct {
		n    int
		name string
	}
	var files []numbered
	for _, e := range ents {
		m := anchorName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, errors.New("its checkpoint folder holds a file that is not a checkpoint")
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, errors.New("a checkpoint file has an unusable number")
		}
		files = append(files, numbered{n, e.Name()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n < files[j].n })
	out := make([][]byte, 0, len(files))
	var total int64
	for i, nf := range files {
		if nf.n != i+1 {
			return nil, fmt.Errorf("checkpoint %d is missing (the series must run 1..n)", i+1)
		}
		raw, missing, problem, err := f.readSmall(filepath.Join(dir, nf.name), maxAnchorBytes)
		if err != nil {
			return nil, err
		}
		if missing || problem != "" {
			return nil, fmt.Errorf("checkpoint %d: %s", i+1, orMissing(problem, missing))
		}
		if !utf8.Valid(raw) {
			return nil, fmt.Errorf("checkpoint %d is not UTF-8 text", i+1)
		}
		if total += int64(len(raw)); total > maxBytes {
			return nil, fmt.Errorf("%w: over %d bytes", ErrExportTooLarge, maxBundleBytes)
		}
		out = append(out, raw)
	}
	return out, nil
}

// countingWriter writes, counts bytes and keeps the first error.
type countingWriter struct {
	w   *bufio.Writer
	n   int64
	err error
}

func (c *countingWriter) str(s string) {
	if c.err != nil {
		return
	}
	k, err := c.w.WriteString(s)
	c.n += int64(k)
	c.err = err
}

// json writes s as a JSON string. Go escapes <, >, & and U+2028/U+2029; the
// value decoded is s exactly (it is valid UTF-8: callers check checkpoint text).
func (c *countingWriter) json(s string) {
	b, err := json.Marshal(s)
	if err != nil {
		c.err = err
		return
	}
	c.str(string(b))
}

func (c *countingWriter) flush() error {
	if c.err != nil {
		return c.err
	}
	return c.w.Flush()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
