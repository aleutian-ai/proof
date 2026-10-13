// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/store"
)

// filled is a chain database with enough entries to have several pages.
func filled(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var entries []store.Entry
	for i := 0; i < 400; i++ {
		entries = append(entries, store.Entry{ChainID: "c", EntryID: fmt.Sprintf("e-%04d", i), GlobalSeq: int64(i),
			ContentHash: strings.Repeat("ab", 64), ChainHash: strings.Repeat("cd", 64), Timestamp: time.Unix(int64(i), 0)})
	}
	if err := s.WriteBatch(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func overwritePages(t *testing.T, path string, fromPage int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := fromPage * os.Getpagesize()
	if len(raw) <= start {
		t.Fatalf("%s is %d bytes: no page %d", path, len(raw), fromPage)
	}
	copy(raw[start:], bytes.Repeat([]byte{0xA5}, len(raw)-start))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// every method of a Store, each returning only its error.
func everyMethod(s *Store) map[string]func(ctx context.Context) error {
	return map[string]func(ctx context.Context) error{
		"WriteBatch": func(ctx context.Context) error {
			return s.WriteBatch(ctx, []store.Entry{{ChainID: "c", EntryID: "new", GlobalSeq: 9999,
				ContentHash: strings.Repeat("ab", 64), ChainHash: strings.Repeat("cd", 64)}})
		},
		"ReadTail":    func(ctx context.Context) error { _, _, err := s.ReadTail(ctx, "c"); return err },
		"Predecessor": func(ctx context.Context) error { _, err := s.Predecessor(ctx, "c", 200); return err },
		"Range":       func(ctx context.Context) error { _, err := s.Range(ctx, "c", 0, 1<<62, 0); return err },
		"Bounds":      func(ctx context.Context) error { _, _, err := s.Bounds(ctx, "c"); return err },
		"Chains":      func(ctx context.Context) error { _, err := s.Chains(ctx); return err },
		"ChainsAfter": func(ctx context.Context) error { _, err := s.ChainsAfter(ctx, nil, 10); return err },
		"GetState":    func(ctx context.Context) error { _, err := s.GetState(ctx, "c"); return err },
		"PutState": func(ctx context.Context) error {
			return s.PutState(ctx, &store.State{ChainID: "c"})
		},
		"UpdateChains": func(ctx context.Context) error {
			return s.UpdateChains(ctx, []string{"c"}, func(tails []store.Tail) ([]store.Entry, []store.State, error) {
				return nil, nil, errors.New("nothing to write")
			})
		},
		"Acquire": func(ctx context.Context) error { _, _, err := s.Acquire(ctx, "c"); return err },
		"Release": func(ctx context.Context) error { return s.Release(ctx, "c", "token") },
	}
}

// TestCorrupt_OpenRefusesADamagedFile: the first open of a damaged file for
// writing is refused with ErrCorrupt, before anything is written. It once
// panicked inside bbolt (or, cut short, faulted in the memory map).
func TestCorrupt_OpenRefusesADamagedFile(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, path string){
		"truncated": func(t *testing.T, path string) {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, fi.Size()/2); err != nil {
				t.Fatal(err)
			}
		},
		"pages overwritten": func(t *testing.T, path string) { overwritePages(t, path, 2) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filled(t)
			// A copy under a new name: the check runs once per file, and this
			// process already opened the original.
			fresh := filepath.Join(t.TempDir(), "copy.db")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fresh, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			damage(t, fresh)
			before, _ := os.ReadFile(fresh)
			if _, err := Open(fresh); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open = %v; want ErrCorrupt", err)
			}
			if after, _ := os.ReadFile(fresh); !bytes.Equal(before, after) {
				t.Fatal("the refused open wrote to the file")
			}
		})
	}
}

// overwriteOnePage replaces one page with 0xA5, leaving the rest intact.
func overwriteOnePage(t *testing.T, path string, page int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	size := os.Getpagesize()
	copy(raw[page*size:(page+1)*size], bytes.Repeat([]byte{0xA5}, size))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCorrupt_EveryMethodReturns: with the check skipped, damage is met inside
// a method. Whichever method meets it returns an error wrapping ErrCorrupt;
// every method after that returns it too; and Close returns instead of waiting
// on a lock. Each page of the file is damaged in turn, alone, so that for some
// of them the file still opens and the damage is first met by the method.
func TestCorrupt_EveryMethodReturns(t *testing.T) {
	healthy := filled(t)
	raw, err := os.ReadFile(healthy)
	if err != nil {
		t.Fatal(err)
	}
	pages := len(raw) / os.Getpagesize()
	met := map[string]int{} // method → cases in which it, not Open, met the damage
	for name := range everyMethod(nil) {
		for page := 2; page < pages; page++ {
			path := filepath.Join(t.TempDir(), "chain.db")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			overwriteOnePage(t, path, page)
			done := make(chan bool, 1)
			go func() {
				s, err := Open(path, WithoutCheck(), WithLockTimeout(time.Second))
				if err != nil {
					done <- false // met at open: refused there
					return
				}
				ctx := context.Background()
				first := everyMethod(s)[name](ctx)
				if !errors.Is(first, ErrCorrupt) {
					_ = s.Close()
					done <- false
					return
				}
				// From here on, every method says so without touching the file.
				for other, call := range everyMethod(s) {
					if err := call(ctx); !errors.Is(err, ErrCorrupt) {
						t.Errorf("%s after %s met the damage = %v; want ErrCorrupt", other, name, err)
					}
				}
				if err := s.Close(); !errors.Is(err, ErrCorrupt) {
					t.Errorf("Close = %v; want an error wrapping ErrCorrupt", err)
				}
				done <- true
			}()
			select {
			case hit := <-done:
				if hit {
					met[name]++
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("%s on a database with page %d damaged did not return", name, page)
			}
			// The file is not left locked by an abandoned handle.
			s, err := Open(path, WithReadOnly(), WithLockTimeout(time.Second))
			if errors.Is(err, ErrLocked) {
				t.Fatalf("%s, page %d: the file was left locked: %v", name, page, err)
			}
			if err == nil {
				s.Close()
			}
		}
	}
	t.Logf("cases in which the method met the damage: %v", met)
	// The test must reach the methods, a read and a write at least, or it
	// proves nothing about them.
	if met["Range"] == 0 || met["WriteBatch"] == 0 {
		t.Fatalf("damage was never met inside Range and WriteBatch (%v): every case was refused at open", met)
	}
}

// TestUpdateChains_ACallersPanicIsNotCorruption: a bug in the function a
// caller passes to UpdateChains (here a write to a nil map) on a healthy file
// was reported as "a store file is damaged", and the Store was finished for
// good. It is the caller's panic: it comes back as it was raised, nothing was
// written, and the Store goes on working.
func TestUpdateChains_ACallersPanicIsNotCorruption(t *testing.T) {
	ctx := context.Background()
	path := filled(t)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var recovered any
	var returned error
	func() {
		defer func() { recovered = recover() }()
		returned = s.UpdateChains(ctx, []string{"c"}, func([]store.Tail) ([]store.Entry, []store.State, error) {
			var m map[string]int
			m["bug"] = 1
			return nil, nil, nil
		})
	}()
	if recovered == nil {
		t.Fatalf("the caller's panic was swallowed; UpdateChains returned %v", returned)
	}
	if e, ok := recovered.(error); !ok || !strings.Contains(e.Error(), "nil map") || errors.Is(e, ErrCorrupt) {
		t.Fatalf("recovered %v; want the caller's own runtime error", recovered)
	}
	// The Store is not poisoned: it reads, writes and closes.
	if _, seq, err := s.ReadTail(ctx, "c"); err != nil || seq != 399 {
		t.Fatalf("ReadTail after the caller's panic: %d, %v", seq, err)
	}
	if err := s.PutState(ctx, &store.State{ChainID: "c"}); err != nil {
		t.Fatalf("a write after the caller's panic: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close = %v; the Store was abandoned", err)
	}
}
