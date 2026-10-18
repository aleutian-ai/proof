// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// ErrChainBusy is returned when another appender holds the chain's lease.
//
// Contention is an expected outcome rather than a failure: a chain has one
// appender at a time by design. Callers should retry, not treat it as corruption.
var ErrChainBusy = errors.New("linker: chain is busy, another append holds the lease")

// ErrUnexpectedChainHash means an input's ExpectChainHash differed from the
// chain hash linking gave it. The whole call was refused; nothing was written.
var ErrUnexpectedChainHash = errors.New("linker: an entry's chain hash is not the one the caller expected")

// ErrHeadStateStale is returned, TOGETHER WITH a populated Result, when the
// entries were durably written but the saved head record could not be updated.
//
// The append HAPPENED. Treat it as success and log the warning: retrying would
// append the same evidence twice. The stale record is harmless — the next append
// reads the tail from the stored entries, never from it.
var ErrHeadStateStale = errors.New("linker: entries written, but the saved head record was not updated")

// ErrFormatRegression is returned, before anything is written, when a linker
// configured for v2 or v3 is asked to append to a chain whose last entry is
// v4. A chain never goes back from v4 (format-spec §2.5): a v3 tombstone after
// it would leave every entry before it unlinked.
var ErrFormatRegression = errors.New("linker: the chain's last entry is v4, and a chain never goes back from v4")

// Input is an entry awaiting linkage.
//
// It carries only what the linker cannot derive. Position (run id, sequence
// number, global sequence), linkage (previous hash), and the resulting chain hash
// are all assigned by [Linker.Append].
//
// Note what this type does NOT have. There is no field for a run id, a sequence
// number, or a chain hash, so "the linker never accepts a caller-supplied
// position" is enforced by the type rather than by a validation rule someone can
// relax later. Adding any of those fields would undo that guarantee.
type Input struct {
	// EntryID uniquely identifies this entry. Required, valid UTF-8, and unique
	// within the batch — duplicates make the batch's order undefined.
	EntryID string

	// EntryType classifies the entry. In v4, which is the default, it is
	// required: 1 to 256 bytes of UTF-8 with no control character, never
	// "tombstone" (format-spec §2.0).
	EntryType string

	// Timestamp is the event time. It is hash CONTENT and never an ordering
	// input — see sortInputs. Stored and hashed at the precision given, so pass
	// the original value rather than one reconstructed from milliseconds.
	// Its UTC year must be 0000 to 9999: the chain hash writes four digits.
	Timestamp time.Time

	// ContentHash commits to the entry's content: 128 lowercase hex characters.
	ContentHash string

	// Salt is the v4 salt (format-spec §2.0). LEAVE IT EMPTY: the linker mints
	// one per entry with crypto/rand. It exists for a writer layered on the
	// linker that must know an entry's chain hash before the append (the sink,
	// which signs records against it): such a writer mints the salt itself with
	// chainformat.NewSaltV4 and pins the result with ExpectChainHash. A salt
	// chosen by whoever produced the content would let them make a leaf hash
	// guessable. Refused unless the linker writes v4, unless ExpectChainHash is
	// set, and when two entries of one batch carry the same salt.
	Salt string

	// IngestedAt is arrival time, and the ordering authority for this batch.
	// Required and non-zero.
	IngestedAt time.Time

	// ExpectChainHash, when set, is the chain hash the caller computed for this
	// entry (and may have signed against). Linking refuses the WHOLE call,
	// writing nothing, if the entry's chain hash is anything else: a moved
	// tail, another sequence or order, or another format all change it.
	// Optional; empty means no expectation.
	ExpectChainHash string
}

// Result reports what one Append did.
type Result struct {
	// RunID is the batch identifier the linker minted for this call.
	//
	// EMPTY for v3, which is the default: v3 does not have run ids. In v2 it is
	// bound into every hash in the batch and is therefore part of the artefact,
	// since an export that loses it cannot be re-linked into the same chain.
	RunID string

	// Appended is the number of entries written.
	Appended int

	// FirstSeq and LastSeq are the global sequence numbers assigned to the first
	// and last entries of the batch.
	FirstSeq int64
	LastSeq  int64

	// HeadHash is the chain hash of the last entry — what the next append links
	// from.
	HeadHash string
}

// Linker assigns chain positions and computes linking hashes.
//
// Construct one with [New]. A Linker is safe for concurrent use.
type Linker struct {
	store  store.Store
	now    func() time.Time
	runID  func() (string, error)
	salt   func() (string, error)
	format int

	// saltFor, set only by this package's tests, mints a salt from the entry,
	// so that two linkers appending in different orders produce one chain.
	saltFor func(Input) (string, error)
}

// Option configures a Linker.
type Option func(*Linker)

// WithClock replaces the clock used for state timestamps.
//
// Intended for tests. The clock never affects a chain hash — entry timestamps
// come from the caller — so a fake clock cannot change what a chain attests.
func WithClock(now func() time.Time) Option {
	return func(l *Linker) { l.now = now }
}

// WithRunIDFunc replaces run id generation.
//
// Intended for tests that need reproducible hashes. Production code must not use
// this to make run ids predictable: a run id is a hash input IN V2, and a
// predictable one lets an attacker who controls content precompute a target
// hash. It has no effect on a v3 linker, which mints no run ids.
func WithRunIDFunc(fn func() (string, error)) Option {
	return func(l *Linker) { l.runID = fn }
}

// WithSaltFunc replaces v4 salt generation.
//
// Intended for tests that need reproducible hashes, exactly as [WithRunIDFunc]
// is. Production code must not use it: a salt that can be predicted makes a
// leaf hash guessable, and so lets someone holding an erased entry's content
// confirm it was there (format-spec §5.0). A salt the function returns is
// validated like any other. It has no effect on a v2 or v3 linker.
func WithSaltFunc(fn func() (string, error)) Option {
	return func(l *Linker) { l.salt = fn }
}

// WithFormatV3 makes the linker write v3 entries.
//
// # Description
//
// Deprecated: v3 is frozen (format-spec §2.6). It is kept for one release so
// that something which must still produce v3 can, and is then removed. v4 is
// the default and the format to use. A chain that already holds a v4 entry is
// never written in v3: the append is refused (§2.5).
//
// # Example
//
//	l, err := linker.New(st, linker.WithFormatV3())
func WithFormatV3() Option {
	return func(l *Linker) { l.format = chainformat.FormatV3 }
}

// WithFormatV2 makes the linker write v2 entries.
//
// # Description
//
// v4 is the default and the format to use. v2 exists for one reason: something
// that must keep producing bytes an older verifier accepts. It binds a run id
// and a batch-local sequence number into every hash, which makes a chain depend
// on how its entries were grouped into calls — appending A and B together does
// not produce the same chain as appending A then B.
//
// This does not affect READING. A verifier handles both formats whatever the
// linker was configured to write, because a store can hold entries of both.
//
// # Example
//
//	l, err := linker.New(st, linker.WithFormatV2())
func WithFormatV2() Option {
	return func(l *Linker) { l.format = chainformat.FormatV2 }
}

// New returns a Linker that appends to s.
//
// # Description
//
// The Linker holds the store for the lifetime of its use; it does not close it.
// Closing the store remains the caller's responsibility.
//
// # Inputs
//
//   - s: the store to append to. Must be non-nil.
//   - opts: optional overrides, for tests
//
// # Outputs
//
//   - *Linker: ready to use
//   - error: if s is nil
//
// # Example
//
//	st, err := bolt.Open("chain.db")
//	if err != nil {
//	    return err
//	}
//	defer st.Close()
//	l, err := linker.New(st)
func New(s store.Store, opts ...Option) (*Linker, error) {
	if s == nil {
		return nil, errors.New("linker: store must not be nil")
	}
	l := &Linker{
		store:  s,
		now:    func() time.Time { return time.Now().UTC() },
		runID:  newRunID,
		salt:   chainformat.NewSaltV4,
		format: chainformat.FormatV4,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Append links a batch of entries onto a chain and writes them atomically.
//
// # Description
//
// One call is one run. The linker mints a run id, sorts the batch by arrival,
// assigns each entry a batch-local sequence number and a chain-wide global
// sequence, and computes each chain hash over the previous entry's hash. The
// batch is then written in a single transaction and the chain's head state
// updated.
//
// The run id and the batch-local sequence number are both bound into the chain
// hash, so the grouping of entries into Append calls changes the hashes produced.
// Appending A and B together is not equivalent to appending A then B. See the
// package documentation.
//
// The chain's lease is held for the whole operation. If another appender holds
// it, Append returns [ErrChainBusy] without writing.
//
// # Inputs
//
//   - ctx: cancelled contexts abort before any write
//   - chainID: the chain to append to. Must be non-empty.
//   - inputs: the entries to link. Must be non-empty. Each must carry a unique
//     EntryID that is valid UTF-8, a non-zero IngestedAt, a Timestamp whose UTC
//     year is 0000 to 9999, and a valid ContentHash. inputs is not mutated; the
//     batch is sorted on a copy.
//
// # Outputs
//
//   - Result: the run id, the sequence range assigned, and the new head hash
//   - error: [ErrChainBusy] under contention, [ErrPositionSupplied] if an input
//     carries a linker-assigned field, [ErrUnexpectedChainHash] if an input's
//     ExpectChainHash differs from the hash it got (nothing written; the index
//     in the message is after sorting by IngestedAt, then EntryID), a
//     validation error naming the offending entry, or a wrapped store error
//
// # Example
//
//	res, err := l.Append(ctx, "chain-1", []linker.Input{{
//	    EntryID:     "e1",
//	    Timestamp:   eventTime,
//	    ContentHash: contentHash,
//	    IngestedAt:  arrivalTime,
//	}})
//	if errors.Is(err, linker.ErrChainBusy) {
//	    // another appender holds the chain; retry
//	}
//
// # Limitations
//
//   - The whole batch is held in memory and written as one transaction. A batch
//     large enough to matter should be split by the caller — but note that
//     splitting changes the hashes, because each call is its own run.
//   - No cross-batch deduplication. An EntryID already present in the chain is
//     not detected here; the store's write semantics govern that case.
//
// # Assumptions
//
//   - The store's WriteBatch is atomic, as the port requires. A store that
//     cannot provide atomicity can leave a head that no stored entry produced.
func (l *Linker) Append(ctx context.Context, chainID string, inputs []Input) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if chainID == "" {
		return Result{}, errors.New("linker: chain id must not be empty")
	}
	if len(inputs) == 0 {
		return Result{}, errors.New("linker: batch must not be empty")
	}
	if _, err := validateBatchOrdering(inputs); err != nil {
		return Result{}, fmt.Errorf("linker: %w", err)
	}

	// Copy before sorting: mutating the caller's slice would reorder a batch the
	// caller may still be holding for its own bookkeeping.
	batch := make([]Input, len(inputs))
	copy(batch, inputs)
	sortInputs(batch)

	// v3 has no run id. Minting one anyway would put an unused value on every
	// entry, which invites a reader to believe it means something.
	var runID string
	if l.format == chainformat.FormatV2 {
		var err error
		if runID, err = l.runID(); err != nil {
			return Result{}, fmt.Errorf("linker: generate run id: %w", err)
		}
	}

	token, acquired, err := l.store.Acquire(ctx, chainID)
	if err != nil {
		return Result{}, fmt.Errorf("linker: acquire chain lease: %w", err)
	}
	if !acquired {
		return Result{}, ErrChainBusy
	}
	defer func() {
		// Release on every path. A lease left held blocks the chain for every
		// future appender, which is worse than any error this could mask, so the
		// release error is deliberately not allowed to overwrite a real failure.
		_ = l.store.Release(context.WithoutCancel(ctx), chainID, token)
	}()

	previousHash, nextGlobalSeq, err := l.continuation(ctx, chainID)
	if err != nil {
		return Result{}, err
	}
	if l.format != chainformat.FormatV4 && previousHash != "" {
		tail, err := l.store.Range(ctx, chainID, nextGlobalSeq-1, nextGlobalSeq-1, 1)
		if err != nil {
			return Result{}, fmt.Errorf("linker: read chain tail: %w", err)
		}
		if len(tail) == 1 && tail[0].FormatVersion == chainformat.FormatV4 {
			return Result{}, ErrFormatRegression
		}
	}

	entries, err := l.link(chainID, previousHash, nextGlobalSeq, runID, batch)
	if err != nil {
		return Result{}, err
	}

	if err := l.store.WriteBatch(ctx, entries); err != nil {
		return Result{}, fmt.Errorf("linker: write batch: %w", err)
	}

	last := entries[len(entries)-1]
	if err := l.store.PutState(ctx, &store.State{
		ChainID:    chainID,
		HeadSeq:    last.GlobalSeq,
		HeadHash:   last.ChainHash,
		ComputedAt: l.now(),
	}); err != nil {
		// The entries are durably written at this point. A stale head is
		// recoverable — the next append reads the tail from the chain itself — so
		// the Result is returned WITH the error: a caller that saw only an error
		// would retry, and append the same evidence twice.
		return Result{
			RunID:    runID,
			Appended: len(entries),
			FirstSeq: entries[0].GlobalSeq,
			LastSeq:  last.GlobalSeq,
			HeadHash: last.ChainHash,
		}, fmt.Errorf("%w: %v", ErrHeadStateStale, err)
	}

	return Result{
		RunID:    runID,
		Appended: len(entries),
		FirstSeq: entries[0].GlobalSeq,
		LastSeq:  last.GlobalSeq,
		HeadHash: last.ChainHash,
	}, nil
}

// link computes a sorted batch's entries, linked onto previousHash from
// nextGlobalSeq. It is the ONLY place chain hashes are computed: Append and
// AppendChains both call it, so batching can never produce different hashes
// from appending one chain at a time.
func (l *Linker) link(chainID, previousHash string, nextGlobalSeq int64, runID string,
	batch []Input) ([]store.Entry, error) {
	entries := make([]store.Entry, len(batch))
	salts := map[string]bool{}
	for i := range batch {
		seqNum := int64(i)
		globalSeq := nextGlobalSeq + seqNum

		var chainHash, salt, leaf string
		var hashErr error
		switch {
		case batch[i].Salt != "" && l.format != chainformat.FormatV4:
			hashErr = errors.New("a salt is a v4 field, and this linker writes v" + strconv.Itoa(l.format))
		case batch[i].Salt != "" && batch[i].ExpectChainHash == "":
			// Only a writer that minted the salt and pinned the hash it gives
			// may supply one (format-spec §2.0): anyone else would be choosing it.
			hashErr = errors.New("a supplied salt needs ExpectChainHash: leave Salt empty and the linker mints one")
		case batch[i].Salt != "" && salts[batch[i].Salt]:
			hashErr = errors.New("two entries of the batch have the same salt; every entry's is fresh")
		case l.format == chainformat.FormatV2:
			chainHash, hashErr = chainformat.ComputeChainHash(
				previousHash, runID, seqNum, batch[i].Timestamp, batch[i].ContentHash)
		case l.format == chainformat.FormatV3:
			chainHash, hashErr = chainformat.ComputeChainHashV3(
				previousHash, globalSeq, batch[i].Timestamp, batch[i].ContentHash)
		default:
			if salt = batch[i].Salt; salt == "" {
				if l.saltFor != nil {
					salt, hashErr = l.saltFor(batch[i])
				} else {
					salt, hashErr = l.salt()
				}
				if hashErr != nil {
					break
				}
			}
			salts[salt] = true
			if leaf, hashErr = chainformat.ComputeLeafHashV4(
				batch[i].EntryID, batch[i].EntryType, batch[i].ContentHash, salt); hashErr != nil {
				break
			}
			chainHash, hashErr = chainformat.ComputeChainHashV4(previousHash, globalSeq, batch[i].Timestamp, leaf)
		}
		if hashErr != nil {
			return nil, fmt.Errorf(
				"linker: entry %q at batch index %d: %w", batch[i].EntryID, i, hashErr)
		}
		if batch[i].ExpectChainHash != "" && batch[i].ExpectChainHash != chainHash {
			// Before any write, on both paths (Append links before WriteBatch;
			// AppendChains inside the store's transaction). Names the index, not
			// the chain.
			return nil, fmt.Errorf("%w (batch index %d)", ErrUnexpectedChainHash, i)
		}

		entries[i] = store.Entry{
			ChainID:       chainID,
			EntryID:       batch[i].EntryID,
			EntryType:     batch[i].EntryType,
			FormatVersion: l.format,
			GlobalSeq:     globalSeq,
			Timestamp:     batch[i].Timestamp,
			ContentHash:   batch[i].ContentHash,
			PreviousHash:  previousHash,
			ChainHash:     chainHash,
			Salt:          salt,
			LeafHash:      leaf,
		}
		// v2 only: these are hash inputs there and meaningless noise in v3.
		if l.format == chainformat.FormatV2 {
			entries[i].RunID = runID
			entries[i].SequenceNum = seqNum
		}
		previousHash = chainHash
	}
	return entries, nil
}

// continuation reads where the next entry links from.
//
// # Description
//
// The chain itself is the authority, not the stored head state. State is a cache
// that lets a reader find the head without walking; if it disagrees with the
// chain, the chain wins. Reading the tail directly means a stale or missing state
// row costs a read rather than producing a fork.
//
// # Outputs
//
//   - string: the hash to link from, empty for a genesis entry
//   - int64: the global sequence to assign to the first entry of the batch
//   - error: a wrapped store error; an empty chain is not an error
func (l *Linker) continuation(ctx context.Context, chainID string) (string, int64, error) {
	chainHash, globalSeq, err := l.store.ReadTail(ctx, chainID)
	if errors.Is(err, store.ErrEmptyChain) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("linker: read chain tail: %w", err)
	}
	return chainHash, globalSeq + 1, nil
}

// newRunID returns a fresh run id: 32 hex characters from crypto/rand.
//
// # Description
//
// Hex rather than a UUID because the run id is a hash input and this package
// holds a zero-dependency line; a UUID library would buy formatting and nothing
// else. Hex also cannot contain the '|' separator that the chain hash preimage
// uses, which the format's delimiter-safety rule requires.
//
// The value must be unpredictable, not merely unique. It is bound into every
// chain hash in the batch, so a predictable run id would let an attacker who
// controls entry content precompute a target hash.
func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
