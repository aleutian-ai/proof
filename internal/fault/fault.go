// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package fault turns a panic or memory fault raised inside the storage layer
// on a damaged store file, reading or writing, into an error.
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
// [Guard] does the same around every single call into the storage layer, and
// remembers that one failed. That is what the operations that WRITE need:
// after a panic inside a write transaction the storage layer may still hold a
// lock, and anything that enters it again (closing the file included) can wait
// on that lock for good. A guarded handle is never entered again.
//
// Code the CALLER supplied and that runs inside such a region (a function
// argument, a signer, a key source) is run through [Callback]: its panic is
// the caller's, comes back to the caller as it was, and poisons nothing.
//
// # Limitations
//
//   - It recovers every panic at the boundary, not only bbolt's: a damaged page
//     surfaces as an ordinary runtime error (index out of range, nil
//     dereference) as often as an assertion, so the two cannot be told apart.
//     A programming error in this module's own code inside the boundary is
//     therefore reported as ErrCorrupt too, with the panic's text.
//   - Only truncated files and overwritten pages are what this is for. A file
//     crafted to exhaust memory or to loop is not a panic and is not recovered
//     here (package safebolt refuses the cases it can before bbolt reads them).
//   - A fault on another goroutine is not covered: the setting is per goroutine.
package fault

import (
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
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
			if cp, ok := r.(callbackPanic); ok {
				// Not the storage layer's: the caller's own code panicked. It
				// gets its panic back, now that everything has unwound.
				panic(cp.value)
			}
			// Joined, not assigned: an error a deferred function set on the way
			// out (a failed flush) must not be lost to the panic's.
			*errp = errors.Join(fmt.Errorf("%w (%v)", ErrCorrupt, r), *errp)
		}
	}
}

// callbackPanic carries a panic raised by caller-supplied code out through the
// storage layer and the guards around it, which must not mistake it for a
// damaged file.
type callbackPanic struct{ value any }

// Callback runs caller-supplied code inside a guarded region.
//
// # Description
//
// A Guard, and Recover, report every panic under them as a damaged file. Code
// the caller supplied (a function passed in, a signer, a key source, a writer)
// is not the storage layer: if it panics, that is the caller's bug, and
// reporting it as corruption would be wrong twice over, once in what it says
// and once in abandoning a healthy file. Callback marks such a panic. It then
// passes through any Guard without poisoning it (the storage layer still
// unwinds normally: a transaction rolls back), and comes out of Recover, or of
// a function that deferred Rethrow, as the caller's original panic.
//
// While fn runs, a memory fault is fatal again, as it is in any Go code: the
// fault setting the guards need is not held across the caller's code.
//
// # Inputs
//
//   - fn: the caller-supplied code; must not be nil
//
// # Example
//
//	err := s.db.Update(func(tx *bolt.Tx) error {
//	    fault.Callback(func() { entries, err = fn(tails) })
//	    return err
//	})
//
// # Limitations
//
//   - The re-raised panic's stack trace starts where it is re-raised, not where
//     the caller's code panicked.
//
// # Assumptions
//
//   - Something up the stack defers Recover or Rethrow; otherwise the panic
//     surfaces wrapped.
func Callback(fn func()) {
	old := debug.SetPanicOnFault(false)
	defer func() {
		debug.SetPanicOnFault(old)
		if r := recover(); r != nil {
			if _, ok := r.(callbackPanic); !ok {
				r = callbackPanic{value: r}
			}
			panic(r)
		}
	}()
	fn()
}

// Rethrow gives a caller's panic, marked by Callback, back to the caller
// unchanged. Defer it in a function that runs caller-supplied code under a
// Guard and has no Recover of its own.
//
// # Example
//
//	func (s *Store) UpdateChains(fn ...) error {
//	    defer fault.Rethrow()
//	    ...
//	}
//
// # Limitations
//
//   - As Callback's.
//
// # Assumptions
//
//   - It is deferred directly (it calls recover).
func Rethrow() {
	if r := recover(); r != nil {
		if cp, ok := r.(callbackPanic); ok {
			panic(cp.value)
		}
		panic(r)
	}
}

// Guard runs calls into one open store file, turns a panic or memory fault in
// any of them into [ErrCorrupt], and from then on refuses every further call.
//
// The zero value is ready. A Guard must not be copied after first use.
type Guard struct {
	// write serializes RunWrite: a writer queued behind one that panicked sees
	// the poisoned flag instead of entering the storage layer.
	write    sync.Mutex
	poisoned atomic.Bool
}

// Run calls fn, reporting a panic or memory fault in it as ErrCorrupt.
//
// # Description
//
// For a call that only reads. If an earlier call on this Guard panicked, fn is
// not called at all. If fn panics, the Guard is poisoned: the handle it guards
// must not be entered again, not even to close it (see [Guard.Poisoned]).
//
// # Inputs
//
//   - fn: the call into the storage layer; must not be nil
//
// # Outputs
//
//   - error: fn's error, unchanged; or an error wrapping ErrCorrupt when fn
//     panicked or faulted, now or on an earlier call
//
// # Example
//
//	err := s.guard.Run(func() error { return s.db.View(read) })
//
// # Limitations
//
//   - A call already inside the storage layer on another goroutine when this
//     one panics is not interrupted.
//   - As the package's: every panic is reported as ErrCorrupt.
//
// # Assumptions
//
//   - fn does not start goroutines that touch the store file: a fault on
//     another goroutine still ends the process.
func (g *Guard) Run(fn func() error) (err error) {
	if g.poisoned.Load() {
		return errPoisoned
	}
	old := debug.SetPanicOnFault(true)
	defer func() {
		debug.SetPanicOnFault(old)
		if r := recover(); r != nil {
			if _, ok := r.(callbackPanic); ok {
				// The caller's code, not the storage layer: the handle is fine
				// (its transaction rolled back as the panic passed), and the
				// panic goes on to Recover or Rethrow.
				panic(r)
			}
			g.poisoned.Store(true)
			err = fmt.Errorf("%w (%v)", ErrCorrupt, r)
		}
	}()
	return fn()
}

// WaitForWriter waits, up to d, for a RunWrite in progress on another
// goroutine to return, and reports whether none is running. For abandoning a
// poisoned handle: its file lock should not be released under a write that is
// still inside the storage layer.
//
// # Inputs
//
//   - d: the longest to wait
//
// # Outputs
//
//   - func(): call it when done, to let writers proceed (never nil)
//   - bool: false when a write was still running after d
//
// # Example
//
//	done, _ := g.WaitForWriter(2 * time.Second)
//	defer done()
//
// # Limitations
//
//   - A writer stuck inside the storage layer for good is not waited for
//     beyond d.
//
// # Assumptions
//
//   - Not called from inside RunWrite on the same Guard.
func (g *Guard) WaitForWriter(d time.Duration) (func(), bool) {
	deadline := time.Now().Add(d)
	for {
		if g.write.TryLock() {
			return g.write.Unlock, true
		}
		if time.Now().After(deadline) {
			return func() {}, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// RunWrite is Run for a call that writes: one at a time.
//
// # Description
//
// The storage layer runs one write transaction at a time and makes the others
// wait on a lock. A write that panics may never release that lock, so the
// waiting is done here instead: a writer that waited behind a panicking one
// returns ErrCorrupt without entering the storage layer.
//
// # Inputs
//
//   - fn: the writing call; must not be nil, and must not call RunWrite on the
//     same Guard (it would wait on itself)
//
// # Outputs
//
//   - error: as [Guard.Run]
//
// # Example
//
//	err := s.guard.RunWrite(func() error { return s.db.Update(write) })
//
// # Limitations
//
//   - As [Guard.Run].
//
// # Assumptions
//
//   - As [Guard.Run].
func (g *Guard) RunWrite(fn func() error) error {
	g.write.Lock()
	defer g.write.Unlock()
	return g.Run(fn)
}

// Poisoned reports whether a call on this Guard panicked.
//
// # Description
//
// A poisoned handle must be abandoned, not closed: closing it enters the
// storage layer, which may wait for good on a lock the failed call left held.
//
// # Outputs
//
//   - bool: true once any Run or RunWrite call has panicked or faulted
//
// # Example
//
//	if s.guard.Poisoned() {
//	    return abandon() // never db.Close()
//	}
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - None.
func (g *Guard) Poisoned() bool { return g.poisoned.Load() }

// Poison marks the Guard poisoned without a call having panicked on it.
//
// # Description
//
// For a call that ran under another Guard and involved this handle too (a copy
// from one file into another): the panic unwound through both.
//
// # Example
//
//	if src.Poisoned() {
//	    dst.Poison()
//	}
//
// # Limitations
//
//   - It cannot be undone.
//
// # Assumptions
//
//   - None.
func (g *Guard) Poison() { g.poisoned.Store(true) }

// errPoisoned is returned for every call after the one that panicked.
var errPoisoned = fmt.Errorf("%w (an earlier operation on this file failed inside the storage layer; "+
	"the handle is no longer used)", ErrCorrupt)
