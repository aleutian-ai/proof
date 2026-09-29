// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"

	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// ErrBusy is returned when another process, or another Sink on the same
// folder, holds its files past the lock timeout. It is retryable: nothing was
// changed. See WithLockTimeout.
var ErrBusy = errors.New("sink: the folder is in use by another process")

// ErrInvalidRecord is returned (wrapped, usually in a *RecordError) for a
// record that can never be committed: a bad key, empty or oversized content, or
// an oversized source. It is NOT retryable. A streaming consumer should
// terminate or dead-letter the message, not redeliver it.
var ErrInvalidRecord = errors.New("sink: invalid record")

// RecordError reports which record of a Commit call was invalid.
//
// errors.Is(err, ErrInvalidRecord) holds for every RecordError, and
// errors.Is(err, ErrInvalidClass) or errors.Is(err, ErrInvalidSubject)
// additionally when the class or the subject was the problem.
type RecordError struct {
	Index int   // position in the records passed to Commit
	Err   error // wraps ErrInvalidRecord
}

func (e *RecordError) Error() string { return fmt.Sprintf("sink: record %d: %v", e.Index, e.Err) }

// Unwrap returns the underlying validation error.
func (e *RecordError) Unwrap() error { return e.Err }

// ErasureIncompleteError reports an erasure call that did part of its work. It
// is returned only AFTER the subject was checked erasable and (for
// EraseSubject/EraseSubjectClass) forgotten; a problem found before that is a
// plain error, and nothing changed.
//
// What holds (ticket _69b, "Erasure recovery invariant"): every chain NOT in
// Pending is completely erased and its index row cleared; each chain in Pending
// is marked pending, a row that holds no subject. Running ResumeErasures, or any
// later erasure, completes them and compacts again, without ever re-linking a
// subject. It is safe to retry.
//
// The message counts; it never names the subject. The wrapped Err names chain
// ids (opaque) for diagnosis.
type ErasureIncompleteError struct {
	// Forgotten is true when this call removed the subject's rows from the
	// index: the subject is no longer linked to any chain there.
	Forgotten bool
	// Pending are the chains whose erasure is still incomplete.
	Pending []string
	// Compacted is true when all three secret files (nonces, sources, subjects)
	// were rewritten after the last deletion.
	Compacted bool
	// Err joins every failure.
	Err error
}

func (e *ErasureIncompleteError) Error() string {
	return fmt.Sprintf("sink: erasure incomplete (subject forgotten: %t; %d chains pending; "+
		"secret files compacted: %t); run erase --resume to finish: %v",
		e.Forgotten, len(e.Pending), e.Compacted, e.Err)
}

// Unwrap returns the joined failures.
func (e *ErasureIncompleteError) Unwrap() error { return e.Err }

// busy maps the store's and bbolt's lock timeouts to ErrBusy, keeping the
// original error in the chain.
func busy(err error) error {
	if errors.Is(err, boltstore.ErrLocked) || errors.Is(err, bolt.ErrTimeout) {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	return err
}
