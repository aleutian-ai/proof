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
// errors.Is(err, ErrInvalidKey) additionally when the key was the problem.
type RecordError struct {
	Index int   // position in the records passed to Commit
	Err   error // wraps ErrInvalidRecord
}

func (e *RecordError) Error() string { return fmt.Sprintf("sink: record %d: %v", e.Index, e.Err) }

// Unwrap returns the underlying validation error.
func (e *RecordError) Unwrap() error { return e.Err }

// busy maps the store's and bbolt's lock timeouts to ErrBusy, keeping the
// original error in the chain.
func busy(err error) error {
	if errors.Is(err, boltstore.ErrLocked) || errors.Is(err, bolt.ErrTimeout) {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	return err
}
