// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package fault turns a panic raised while reading a damaged store file into an
// error.
//
// # Description
//
// The store files are bbolt databases, read through a memory map. bbolt trusts
// the pages it maps: a truncated file faults (SIGBUS or SIGSEGV) on the first
// read past its end, and a page with the wrong contents trips one of bbolt's
// own assertions or an index out of range. Each of those is a panic, and an
// unrecovered panic ends the process: a service embedding the sink is killed by
// a damaged file, and the CLI exits with the Go runtime's status 2, which is
// this CLI's code for a usage error.
//
// [Recover] is deferred at the boundary of an operation that reads store files.
// It makes memory faults on the calling goroutine panic instead of crashing the
// process, and reports any panic as [ErrCorrupt].
//
// # Limitations
//
//   - It recovers every panic at the boundary, not only bbolt's: a damaged page
//     surfaces as an ordinary runtime error (index out of range, nil
//     dereference) as often as an assertion, so the two cannot be told apart.
//     A programming error inside the boundary is therefore reported as
//     ErrCorrupt too, with the panic's text.
//   - A fault on another goroutine is not covered: the setting is per goroutine.
package fault

import (
	"errors"
	"fmt"
	"runtime/debug"
)

// ErrCorrupt means a store file could not be read because its contents are not
// a well-formed database: truncated, overwritten, or not a store file at all.
var ErrCorrupt = errors.New("a store file is damaged: truncated, overwritten, or not a store file")

// Recover reports a panic in the calling function as ErrCorrupt.
//
// # Description
//
// Call it at the top of a function with a named error result, and defer what
// it returns. From that call until the function returns, a memory fault on
// this goroutine panics instead of ending the process; the deferred function
// restores the previous setting and, if the function is panicking, stops the
// panic and sets *errp.
//
// # Inputs
//
//   - errp: the calling function's named error result; must not be nil
//
// # Outputs
//
//   - func(): the function to defer
//
// # Example
//
//	func (s *Sink) Verify(...) (_ Report, err error) {
//	    defer fault.Recover(&err)()
//	    ...
//	}
//
// # Limitations
//
//   - As the package's.
//
// # Assumptions
//
//   - Deferred functions that ran before this one (closing files, rolling back
//     a transaction) have left nothing that needs the panic to continue.
func Recover(errp *error) func() {
	old := debug.SetPanicOnFault(true)
	return func() {
		debug.SetPanicOnFault(old)
		if r := recover(); r != nil {
			*errp = fmt.Errorf("%w (%v)", ErrCorrupt, r)
		}
	}
}
