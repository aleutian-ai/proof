// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"errors"
	"fmt"
	"regexp"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/internal/fault"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// ErrBusy is returned when another process, or another Sink on the same
// folder, holds its files past the lock timeout. It is retryable: nothing was
// changed. See WithLockTimeout.
var ErrBusy = errors.New("sink: the folder is in use by another process")

// ErrCorrupt is returned by every operation when one of the folder's files
// cannot be used as the database it should be: truncated, overwritten, or not
// a sink file (a valid database without the buckets a secrets file or subject
// index has is one of these). No operation panics, faults or hangs on such a
// file. For Verify it means the folder does not verify.
//
// It is reached in one of three ways:
//
//   - the file was refused when it was opened;
//   - an operation that writes (Commit, EraseSubject, EraseSubjectClass,
//     ResumeErasures, Repair, RequireRecordSigning) read the file through
//     before first writing to it, and it did not read cleanly. This check runs
//     once per file per Sink (WithoutIntegrityCheck turns it off) and refuses
//     the call before anything is written;
//   - a read or write met the damage inside the storage layer, which panicked
//     or faulted. The call that met it returns ErrCorrupt, and that open file
//     is not used again. In a call that had already written to other files,
//     what is left is what a crash at that point leaves (see each operation).
//
// In the last case the file is abandoned, not closed: closing it would enter
// the storage layer again, which can wait for good on a lock the failed
// transaction left held. Its file lock is released and its descriptor closed,
// so later calls can open the file again (and will report it damaged again);
// its memory map, the size of the file in address space, stays until the
// process exits. A long-lived process that keeps calling into a damaged folder
// leaks one such mapping per file per call: stop and repair the folder.
//
// What is covered is DAMAGE: a file cut short, pages overwritten, and meta
// pages or a freelist header holding a size or a count that cannot fit the
// file (those are refused before the storage layer reads them, on every open).
// What is NOT covered is a file deliberately crafted beyond that. Pages that
// point back at each other are followed without end inside one call, and a
// count or offset inside a data page is believed as written. These are a
// sink's own files, not an interchange format: evidence from someone else is
// verified as an exported bundle, never by opening their files.
//
// A panic in code the CALLER supplied (a signer, a key source, a heads store,
// VerifyEach's function, Export's writer) is not ErrCorrupt: it comes back out
// of the operation as the caller's own panic.
//
// It is the same value as the bolt store's ErrCorrupt.
var ErrCorrupt = fault.ErrCorrupt

// ErrInvalidRecord is returned (wrapped, usually in a *RecordError) for a
// record that can never be committed: a bad key, empty or oversized content, or
// an oversized source. It is NOT retryable. A streaming consumer should
// terminate or dead-letter the message, not redeliver it.
var ErrInvalidRecord = errors.New("sink: invalid record")

// ErrSourceConflict is returned (wrapped in a *RecordError) for a record whose
// Source is already committed on its chain, or given earlier in the same call,
// with DIFFERENT content, or whose committed content is missing or unreadable
// so that it cannot be compared.
//
// A duplicate is a record the chain already holds. A Source that points at an
// entry holding other content is not that: either the producer reused a
// position for a new message, or a row was written into the sources file to
// make a new record vanish. Either way the record was NOT committed, and
// nothing else in the call was. It is NOT retryable: a redelivery fails the
// same way. A streaming consumer should dead-letter the message and look at
// why. The message never repeats the source or the content.
var ErrSourceConflict = errors.New("sink: a record's source is already committed with other content")

// RecordError reports which record of a Commit call could not be committed for
// a reason of its own.
//
// errors.Is(err, ErrInvalidRecord) holds when the record was invalid (and
// ErrInvalidClass or ErrInvalidSubject additionally when the class or the
// subject was the problem); errors.Is(err, ErrSourceConflict) when its Source
// is already committed with other content. Neither is retryable.
type RecordError struct {
	Index int   // position in the records passed to Commit
	Err   error // wraps ErrInvalidRecord or ErrSourceConflict
}

func (e *RecordError) Error() string { return fmt.Sprintf("sink: record %d: %v", e.Index, e.Err) }

// Unwrap returns the underlying validation error.
func (e *RecordError) Unwrap() error { return e.Err }

// ErasureIncompleteError reports an erasure call that did part of its work. It
// is returned only AFTER the subject was checked erasable and (for
// EraseSubject/EraseSubjectClass) forgotten; a problem found before that is a
// plain error, and nothing changed.
//
// What holds (the recovery invariant, docs/sink-format.md §4.3): every chain NOT in
// Pending is completely erased and its index row cleared; each chain in Pending
// is marked pending, a row that holds no subject. Running ResumeErasures, or any
// later erasure, completes them and compacts again, without ever re-linking a
// subject. It is safe to retry.
//
// The message counts; it never names the subject, and the erase calls return
// it with every chain id in the message replaced (as Commit does): logged next
// to the subject, a chain id would re-create the secret link. Pending (and the
// SubjectErasure's chains) carry the ids, for a caller that needs them; never
// log them beside the subject.
type ErasureIncompleteError struct {
	// Forgotten is true when this call removed the subject's rows from the
	// index: the subject is no longer linked to any chain there.
	Forgotten bool
	// Pending are the chains whose erasure is still incomplete.
	Pending []string
	// Compacted is true when the files erased values live in (secrets,
	// sources, subjects) were rewritten after the last deletion. The signatures
	// file holds no erased values; a failure to rewrite it is reported in Err
	// but does not clear Compacted.
	Compacted bool
	// Err joins every failure.
	Err error
}

func (e *ErasureIncompleteError) Error() string {
	return fmt.Sprintf("sink: erasure incomplete (subject forgotten: %t; %d chains pending; "+
		"files compacted: %t); run erase --resume to finish: %v",
		e.Forgotten, len(e.Pending), e.Compacted, e.Err)
}

// Unwrap returns the joined failures.
func (e *ErasureIncompleteError) Unwrap() error { return e.Err }

// ErrRecordSignerRequired: this sink signs its records (a commit's record
// signatures were stored), and this Sink was opened without WithRecordSigner.
// Nothing was written. A configuration error: retrying will not help.
var ErrRecordSignerRequired = errors.New("sink: this sink signs its records; open it with WithRecordSigner")

// ErrSinkNotSigning: this Sink was opened WithRecordSigner, but the sink already
// holds unsigned entries, and a sink's signing mode is fixed from its first
// entry. Nothing was written. A configuration error: retrying will not help.
var ErrSinkNotSigning = errors.New("sink: this sink already holds unsigned entries; it cannot start signing")

// busy maps the store's and bbolt's lock timeouts to ErrBusy, keeping the
// original error in the chain.
func busy(err error) error {
	if errors.Is(err, boltstore.ErrLocked) || errors.Is(err, bolt.ErrTimeout) {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	return err
}

// PairError reports that one (class, subject) pair of a Commit call could not
// be committed because of that pair's own stored state: an inconsistent index
// row, an index that re-links an erased chain, or a chain id that could not be
// minted. Nothing in the call was committed.
//
// Records are the indexes (in the records passed to Commit) of every record of
// that pair. A streaming consumer can set exactly those aside (dead-letter
// them) and retry the rest: the fault is in stored state, so redelivering them
// would fail again, and fail every batch they are in.
type PairError struct {
	Records []int // indexes into the records passed to Commit
	Err     error
}

func (e *PairError) Error() string {
	return fmt.Sprintf("records %v (one class and subject): %v", e.Records, e.Err)
}

// Unwrap returns the underlying failure.
func (e *PairError) Unwrap() error { return e.Err }

// chainIDInText matches a chain id anywhere in a message.
var chainIDInText = regexp.MustCompile(`[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}`)

// redactedError is an error whose message has every chain id replaced, and
// which still unwraps to the original (so errors.Is and errors.As reach the
// cause). Commit returns its errors this way: next to the caller's own
// records, a chain id in a logged error would be a row of the secret index
// (docs/sink-format.md §7).
type redactedError struct{ err error }

func (e redactedError) Error() string {
	return chainIDInText.ReplaceAllString(e.err.Error(), "<chain>")
}
func (e redactedError) Unwrap() error { return e.err }

// redact wraps err so its message names no chain; nil stays nil.
func redact(err error) error {
	if err == nil {
		return nil
	}
	return redactedError{err}
}
