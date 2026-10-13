// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package safebolt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

var testBucket = []byte("rows")

// newFile writes a database with enough rows to have branch and leaf pages.
func newFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(testBucket)
		if err != nil {
			return err
		}
		for i := 0; i < 2000; i++ {
			if err := b.Put([]byte(fmt.Sprintf("key-%06d", i)), bytes.Repeat([]byte{'v'}, 200)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func truncateHalf(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, fi.Size()/2); err != nil {
		t.Fatal(err)
	}
}

// overwrite replaces the file's bytes from a page on with 0xA5.
func overwrite(t *testing.T, path string, fromPage int) {
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

// TestCheck: a healthy file passes; a truncated or overwritten one is
// ErrCorrupt, returned, not a crash.
func TestCheck(t *testing.T) {
	if err := Check(newFile(t), nil); err != nil {
		t.Fatalf("a healthy file: %v", err)
	}
	for name, damage := range map[string]func(t *testing.T, path string){
		"truncated":                  truncateHalf,
		"everything after the metas": func(t *testing.T, p string) { overwrite(t, p, 2) },
		"the last pages":             func(t *testing.T, p string) { overwrite(t, p, 20) },
		"the meta pages too":         func(t *testing.T, p string) { overwrite(t, p, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			path := newFile(t)
			damage(t, path)
			if err := Check(path, nil); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Check = %v; want ErrCorrupt", err)
			}
		})
	}
}

// TestChecker_OncePerFile: a file that passed is not read again; one that
// failed is.
func TestChecker_OncePerFile(t *testing.T) {
	var c Checker
	path := newFile(t)
	if err := c.Once(path, nil); err != nil {
		t.Fatal(err)
	}
	// Damaged after it passed: not read again (the guard is what catches it).
	overwrite(t, path, 2)
	if err := c.Once(path, nil); err != nil {
		t.Fatalf("a file that had passed was checked again: %v", err)
	}
	// A file that fails keeps failing.
	bad := newFile(t)
	overwrite(t, bad, 2)
	for i := 0; i < 2; i++ {
		if err := c.Once(bad, nil); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("call %d on a damaged file: %v; want ErrCorrupt", i, err)
		}
	}
	// A missing or empty file has nothing to check.
	if err := c.Once(filepath.Join(t.TempDir(), "absent.db"), nil); err != nil {
		t.Fatalf("an absent file: %v", err)
	}
}

// TestPoisonedHandle: a panic inside a write transaction is an error; the
// handle then refuses every call without entering bbolt, Close returns instead
// of waiting on the writer lock, and the file lock is released, so the file can
// be opened again in the same process.
func TestPoisonedHandle(t *testing.T) {
	path := newFile(t)
	db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(testBucket).Put([]byte("k"), []byte("v")); err != nil {
			return err
		}
		panic("a damaged page")
	})
	if !errors.Is(err, ErrCorrupt) || !db.Poisoned() {
		t.Fatalf("Update = %v, poisoned %v; want ErrCorrupt and a poisoned handle", err, db.Poisoned())
	}
	entered := false
	for name, call := range map[string]func() error{
		"View":   func() error { return db.View(func(*bolt.Tx) error { entered = true; return nil }) },
		"Update": func() error { return db.Update(func(*bolt.Tx) error { entered = true; return nil }) },
		"Do":     func() error { return db.Do(func() error { entered = true; return nil }) },
		"Begin":  func() error { _, err := db.Begin(); return err },
	} {
		if err := call(); !errors.Is(err, ErrCorrupt) || entered {
			t.Fatalf("%s on a poisoned handle = %v (entered: %v); want ErrCorrupt without a call", name, err, entered)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Close = %v; want an error wrapping ErrCorrupt (the handle was abandoned)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close on a poisoned handle did not return")
	}
	// The lock is gone: an exclusive open succeeds at once.
	again, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("the abandoned handle still holds the file: %v", err)
	}
	// And the panicking transaction wrote nothing.
	if err := again.View(func(tx *bolt.Tx) error {
		if tx.Bucket(testBucket).Get([]byte("k")) != nil {
			return errors.New("the panicking transaction's write is in the file")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDamagedFile_EveryCallReturns: on a file whose pages were overwritten,
// reading, writing and closing all return.
func TestDamagedFile_EveryCallReturns(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, path string){
		"truncated":         truncateHalf,
		"pages overwritten": func(t *testing.T, p string) { overwrite(t, p, 2) },
		"late pages":        func(t *testing.T, p string) { overwrite(t, p, 20) },
	} {
		t.Run(name, func(t *testing.T) {
			path := newFile(t)
			damage(t, path)
			done := make(chan struct{})
			go func() {
				defer close(done)
				db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second})
				if err != nil {
					t.Logf("Open: %v", err)
					return
				}
				err = db.View(func(tx *bolt.Tx) error {
					return tx.Bucket(testBucket).ForEach(func(k, v []byte) error { return nil })
				})
				t.Logf("View: %v", err)
				err = db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket(testBucket)
					for i := 0; i < 3000; i++ {
						if err := b.Put([]byte(fmt.Sprintf("new-%06d", i)), bytes.Repeat([]byte{'n'}, 300)); err != nil {
							return err
						}
					}
					return nil
				})
				t.Logf("Update: %v", err)
				t.Logf("Close: %v", db.Close())
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("a call on a damaged file did not return")
			}
			// Whatever happened, the file is not left locked.
			if db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true}); err == nil {
				db.Close()
			} else if errors.Is(err, bolt.ErrTimeout) {
				t.Fatalf("the file was left locked: %v", err)
			}
		})
	}
}

// TestCompact_DamagedSource: copying a damaged file is an error, and both
// handles close.
func TestCompact_DamagedSource(t *testing.T) {
	path := newFile(t)
	overwrite(t, path, 20)
	src, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Skipf("the damaged file does not open: %v", err)
	}
	dst, err := Open(filepath.Join(t.TempDir(), "copy.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := Compact(dst, src); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Compact = %v; want ErrCorrupt", err)
	}
	done := make(chan struct{})
	go func() { src.Close(); dst.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("closing after a failed copy did not return")
	}
}

// craftFreelist rewrites the freelist page header of the file's current meta:
// its count, and (for the 0xFFFF marker) the 8-byte count that follows.
func craftFreelist(t *testing.T, path string, count uint16, bigCount uint64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, ok := readMeta(f, 0)
	if m1, ok1 := readMeta(f, int64(os.Getpagesize())); ok1 && (!ok || m1.txid > m.txid) {
		m, ok = m1, true
	}
	if !ok || m.freelist == noFreelist {
		t.Fatalf("no meta page with a freelist in %s", path)
	}
	var head [10]byte
	binary.LittleEndian.PutUint16(head[0:], count)
	if _, err := f.WriteAt(head[:2], int64(m.freelist*m.pageSize)+offCount); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(head[2:], bigCount)
	if _, err := f.WriteAt(head[2:], int64(m.freelist*m.pageSize)+pageHeaderSize); err != nil {
		t.Fatal(err)
	}
}

// TestPrecheck_ACraftedFreelistIsRefusedBeforeBboltReadsIt: a freelist page
// whose count is the 0xFFFF marker followed by 2^46 made bbolt allocate that
// many entries: "fatal error: runtime: out of memory", which is not a panic and
// ends the process (2^40 was killed after 25 seconds). Ten bytes of the file.
// The values are now refused before bbolt is given the file, on every open.
func TestPrecheck_ACraftedFreelistIsRefusedBeforeBboltReadsIt(t *testing.T) {
	for name, big := range map[string]uint64{"2^46 entries": 1 << 46, "2^40 entries": 1 << 40, "one more than fits": 0} {
		for _, readOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/read-only %v", name, readOnly), func(t *testing.T) {
				path := newFile(t)
				if big == 0 {
					// Without the marker: more entries than one page holds.
					craftFreelist(t, path, 0xFFFE, 0)
				} else {
					craftFreelist(t, path, 0xFFFF, big)
				}
				done := make(chan error, 1)
				go func() {
					db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: readOnly, PreLoadFreelist: true})
					if err == nil {
						db.Close()
					}
					done <- err
				}()
				select {
				case err := <-done:
					if !errors.Is(err, ErrCorrupt) {
						t.Fatalf("Open = %v; want ErrCorrupt", err)
					}
				case <-time.After(20 * time.Second):
					t.Fatal("Open did not return")
				}
				if err := Check(path, nil); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("Check = %v; want ErrCorrupt", err)
				}
			})
		}
	}
}

// TestPrecheck_SizesThatCannotFitTheFile: a database that records more pages
// than its file holds (a file cut short) is refused at open, read-only too,
// and a healthy file is not.
func TestPrecheck_SizesThatCannotFitTheFile(t *testing.T) {
	path := newFile(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := precheck(f); err != nil {
		t.Fatalf("a healthy file: %v", err)
	}
	if _, ok := readMeta(f, 0); !ok {
		t.Fatal("the healthy file's meta page was not recognised: the check reads nothing")
	}
	f.Close()
	truncateHalf(t, path)
	for _, readOnly := range []bool{false, true} {
		if _, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: readOnly}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open (read-only %v) of a file cut short = %v; want ErrCorrupt", readOnly, err)
		}
	}
	// An empty file is a new database.
	empty := filepath.Join(t.TempDir(), "new.db")
	db, err := Open(empty, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("a new file: %v", err)
	}
	db.Close()
}

// TestPoisonedClose_DoesNotEnterBbolt: after a write transaction that never
// released bbolt's writer lock, bbolt's own Close waits on that lock for good.
// That is why a poisoned handle is abandoned: its Close must return, and
// release the file, without calling bbolt's.
func TestPoisonedClose_DoesNotEnterBbolt(t *testing.T) {
	path := newFile(t)
	db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// A write transaction left open: what a transaction that panicked while its
	// rollback also failed leaves behind.
	stuck, err := db.db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	// bbolt's Close, as a recover at the end of the operation used to call it.
	bboltClosed := make(chan struct{})
	go func() { _ = db.db.Close(); close(bboltClosed) }()
	select {
	case <-bboltClosed:
		t.Fatal("bbolt's Close returned with a write transaction open: this test no longer shows the hang")
	case <-time.After(300 * time.Millisecond):
		// It hangs, as expected.
	}
	db.guard.Poison()
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Close = %v; want the handle abandoned (ErrCorrupt)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close on a poisoned handle hangs: it entered bbolt")
	}
	// The file lock is released although bbolt never closed the file.
	again, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("the abandoned handle still holds the file: %v", err)
	}
	again.Close()
	// Let the goroutine stuck in bbolt's Close go.
	_ = stuck.Rollback()
	<-bboltClosed
}

// TestPoisonedClose_WaitsForAWriteInProgress: Close on a poisoned handle does
// not release the file lock under a write another goroutine is still making.
func TestPoisonedClose_WaitsForAWriteInProgress(t *testing.T) {
	path := newFile(t)
	db, err := Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	inside, finish := make(chan struct{}), make(chan struct{})
	written := make(chan error, 1)
	go func() {
		written <- db.Update(func(tx *bolt.Tx) error {
			close(inside)
			<-finish
			return tx.Bucket(testBucket).Put([]byte("late"), []byte("write"))
		})
	}()
	<-inside
	db.guard.Poison() // as a read on another goroutine meeting damage would
	closed := make(chan struct{})
	go func() { _ = db.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close released the file while a write was in progress")
	case <-time.After(200 * time.Millisecond):
	}
	close(finish)
	if err := <-written; err != nil {
		t.Fatalf("the write in progress: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return after the write finished")
	}
}
