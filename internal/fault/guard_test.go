// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package fault

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestGuard_PanicIsAnErrorAndPoisons: a panic inside a guarded call is
// ErrCorrupt, and no later call is made.
func TestGuard_PanicIsAnErrorAndPoisons(t *testing.T) {
	var g Guard
	want := errors.New("an ordinary error")
	if err := g.Run(func() error { return want }); err != want || g.Poisoned() {
		t.Fatalf("an ordinary error: %v, poisoned %v; want it unchanged and no poison", err, g.Poisoned())
	}
	if err := g.Run(func() error { panic("assertion failed: page 7") }); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a panic: %v; want ErrCorrupt", err)
	}
	if !g.Poisoned() {
		t.Fatal("the guard is not poisoned after a panic")
	}
	called := false
	for _, run := range []func(func() error) error{g.Run, g.RunWrite} {
		if err := run(func() error { called = true; return nil }); !errors.Is(err, ErrCorrupt) || called {
			t.Fatalf("a call on a poisoned guard: %v (made: %v); want ErrCorrupt and no call", err, called)
		}
	}
}

// TestGuard_MemoryFaultIsAnError: a fault (what a read past the end of a
// memory-mapped file is) is recovered, not fatal.
func TestGuard_MemoryFaultIsAnError(t *testing.T) {
	var g Guard
	var p *int
	if err := g.Run(func() error { _ = *p; return nil }); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a nil dereference: %v; want ErrCorrupt", err)
	}
}

// TestGuard_AWriterBehindAPanicDoesNotEnter: a writer that waited behind one
// that panicked returns ErrCorrupt without running. Inside the storage layer it
// would wait on the lock the panicked writer never released.
func TestGuard_AWriterBehindAPanicDoesNotEnter(t *testing.T) {
	var g Guard
	inside, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = g.RunWrite(func() error {
			close(inside)
			<-release
			panic("damaged")
		})
	}()
	<-inside
	second := make(chan error, 1)
	entered := false
	go func() { second <- g.RunWrite(func() error { entered = true; return nil }) }()
	time.Sleep(20 * time.Millisecond) // let it queue
	close(release)
	wg.Wait()
	select {
	case err := <-second:
		if !errors.Is(err, ErrCorrupt) || entered {
			t.Fatalf("the queued writer: %v (entered: %v); want ErrCorrupt without entering", err, entered)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the queued writer did not return")
	}
}

// TestCallback_ACallersPanicIsNotCorruption: a panic in caller-supplied code,
// run through Callback inside a guarded region, does not poison the Guard and
// is not reported as ErrCorrupt. It comes back as the caller's own panic, from
// Recover and from Rethrow alike.
func TestCallback_ACallersPanicIsNotCorruption(t *testing.T) {
	mine := errors.New("the caller's bug")
	for name, boundary := range map[string]func(g *Guard) (err error){
		"Recover": func(g *Guard) (err error) {
			defer Recover(&err)()
			return g.RunWrite(func() error { Callback(func() { panic(mine) }); return nil })
		},
		"Rethrow": func(g *Guard) (err error) {
			defer Rethrow()
			return g.Run(func() error { Callback(func() { panic(mine) }); return nil })
		},
	} {
		t.Run(name, func(t *testing.T) {
			var g Guard
			var got any
			var err error
			func() {
				defer func() { got = recover() }()
				err = boundary(&g)
			}()
			if got != mine {
				t.Fatalf("recovered %v (error result %v); want the caller's own panic back", got, err)
			}
			if g.Poisoned() {
				t.Fatal("a caller's panic poisoned the handle")
			}
			if err := g.Run(func() error { return nil }); err != nil {
				t.Fatalf("the guard after a caller's panic: %v", err)
			}
		})
	}
	// A caller's nil dereference is the caller's too.
	var p *int
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("a caller's nil dereference was swallowed")
			}
		}()
		var err error
		defer Recover(&err)()
		Callback(func() { _ = *p })
	}()
}

// TestRecover_KeepsAnErrorSetOnTheWayOut: an error a deferred function set
// while the panic unwound (a flush that failed) is joined to the panic's, not
// replaced by it.
func TestRecover_KeepsAnErrorSetOnTheWayOut(t *testing.T) {
	flush := errors.New("the flush failed")
	run := func() (err error) {
		defer Recover(&err)()
		defer func() { err = errors.Join(err, flush) }()
		panic("a damaged page")
	}
	err := run()
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, flush) {
		t.Fatalf("err = %v; want both ErrCorrupt and the flush error", err)
	}
}
