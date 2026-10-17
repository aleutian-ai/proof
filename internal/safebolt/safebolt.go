// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package safebolt opens bbolt files so that a damaged one is an error, never
// a crash or a hang.
//
// # Description
//
// bbolt reads its file through a memory map and trusts every page: a file cut
// short faults on the first read past its end, and a page holding the wrong
// bytes trips an assertion or an index out of range. Each is a panic. Inside a
// write transaction it is worse: the transaction may never release bbolt's
// writer lock, and the next call that enters bbolt, closing the file included,
// then waits on that lock for good.
//
// A [DB] wraps one open file. Every call into bbolt goes through a
// [fault.Guard]: a panic or memory fault becomes an error wrapping
// [fault.ErrCorrupt], and the handle is poisoned. A poisoned handle is never
// entered again. Its Close does not call bbolt's Close: it releases the file
// lock and closes the descriptor directly, and leaves the file's memory map
// and bbolt's in-memory state behind until the process exits.
//
// [Check] reads a whole file through a read-only handle before it is trusted
// for writing: the early, clean refusal.
//
// # Limitations
//
//   - A poisoned handle leaks its memory map (address space the size of the
//     file) until the process exits.
//   - Every panic inside a guarded call is reported as corruption, a
//     programming error included (see package fault).
//   - What is covered is DAMAGE: a file cut short, pages overwritten, and the
//     sizes and counts in the meta pages and the freelist header. A file
//     deliberately CRAFTED is outside what this promises. One whose branch
//     pages point back at each other is followed by bbolt without end, inside
//     one call; an element count or offset inside a data page is believed as
//     written. These are a store's own files, not an interchange format.
//   - Unix only (flock), like the rest of proof's file handling.
package safebolt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/internal/fault"
	"github.com/aleutian-ai/proof/internal/osfile"
)

// ErrCorrupt is fault.ErrCorrupt: the file is not a well-formed database.
var ErrCorrupt = fault.ErrCorrupt

// maxBucketDepth bounds how deep Check follows buckets inside buckets. The
// files this module writes use one level.
const maxBucketDepth = 16

// minLeafElementBytes is the least a key costs in a bbolt leaf page (its
// element header). A file of n bytes therefore holds fewer than n/16 keys;
// Check stops a walk that yields more, which only pages that loop can.
const minLeafElementBytes = 16

// abandonWait is how long Close on a poisoned handle waits for a write in
// progress on another goroutine before it releases the file lock anyway.
const abandonWait = 2 * time.Second

// A file that fails the check before opening is read again this many times,
// this far apart, before it is refused.
const (
	precheckRetries  = 2
	precheckRetryGap = 20 * time.Millisecond
)

// DB is one open bbolt file whose every call is guarded.
//
// Safe for concurrent use, as bbolt is. Writes run one at a time.
type DB struct {
	db    *bolt.DB
	guard fault.Guard
	files *openedFiles
}

// openedFiles collects the descriptors bbolt opened for one DB, so a poisoned
// handle can release them without entering bbolt.
type openedFiles struct {
	mu    sync.Mutex
	files []*os.File
}

func (o *openedFiles) add(f *os.File) {
	o.mu.Lock()
	o.files = append(o.files, f)
	o.mu.Unlock()
}

// release unlocks and closes every descriptor. Unlocking first matters: a file
// lock belongs to the open file, which the memory map keeps alive after the
// descriptor is closed.
func (o *openedFiles) release() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, f := range o.files {
		osfile.Unlock(f)
		_ = f.Close()
	}
	o.files = nil
}

// Open opens a bbolt file as bolt.Open does, guarded.
//
// # Description
//
// Before bbolt is given the file, its meta pages and freelist page header are
// read directly and refused (ErrCorrupt) when they hold a page size, a page id
// or a count that cannot fit the file: bbolt believes those values, and a
// freelist claiming 2^46 entries makes it allocate until the process dies,
// which no recover can catch. This runs on every open, read-only included.
//
// bbolt then reads the meta pages and (for writing) the freelist while opening,
// and either can panic on a damaged file. That is reported as ErrCorrupt, and
// the descriptor bbolt opened is released.
//
// # Inputs
//
//   - path: the file
//   - mode: the mode a new file is created with
//   - opts: bbolt's options; nil for its defaults. opts.OpenFile is honoured
//     (and wrapped, to keep the descriptor).
//
// # Outputs
//
//   - *DB: the open file; the caller must Close it
//   - error: bolt.Open's error, unchanged (bolt.ErrTimeout for a held lock); or
//     an error wrapping ErrCorrupt when opening panicked or faulted
//
// # Example
//
//	db, err := safebolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
//	if err != nil {
//	    return err
//	}
//	defer db.Close()
//
// # Limitations
//
//   - As the package's.
//
// # Assumptions
//
//   - opts.OpenFile, if set, returns the file bbolt should use, as bbolt
//     requires of it.
func Open(path string, mode os.FileMode, opts *bolt.Options) (*DB, error) {
	var o bolt.Options
	if opts != nil {
		o = *opts
	} else {
		o = *bolt.DefaultOptions
	}
	open := o.OpenFile
	if open == nil {
		open = os.OpenFile
	}
	d := &DB{files: &openedFiles{}}
	o.OpenFile = func(p string, flag int, m os.FileMode) (*os.File, error) {
		f, err := open(p, flag, m)
		if err != nil {
			return nil, err
		}
		// Before bbolt reads a byte of it: sizes and counts it would believe.
		// It is read before bbolt takes the file lock, so a writer in another
		// process can be part-way through a commit: damage is still there a
		// moment later, a commit in progress is not.
		err = precheck(f)
		for try := 0; err != nil && try < precheckRetries; try++ {
			time.Sleep(precheckRetryGap)
			err = precheck(f)
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		d.files.add(f)
		return f, nil
	}
	err := d.guard.Run(func() error {
		db, err := bolt.Open(path, mode, &o)
		d.db = db
		return err
	})
	if d.guard.Poisoned() {
		d.files.release()
		return nil, err
	}
	if err != nil {
		return nil, err // bbolt closed what it opened
	}
	return d, nil
}

// View runs fn in a read-only transaction, as bolt.DB.View does.
//
// # Inputs
//
//   - fn: reads through tx; must not keep tx or anything it returned
//
// # Outputs
//
//   - error: fn's error or bbolt's; or one wrapping ErrCorrupt when the read
//     panicked or faulted, or the handle is poisoned
//
// # Example
//
//	err := db.View(func(tx *bolt.Tx) error {
//	    v = bytes.Clone(tx.Bucket(name).Get(key))
//	    return nil
//	})
//
// # Limitations
//
//   - As the package's.
//
// # Assumptions
//
//   - fn starts no goroutine that reads the file.
func (d *DB) View(fn func(tx *bolt.Tx) error) error {
	return d.guard.Run(func() error { return d.db.View(fn) })
}

// Update runs fn in a read-write transaction, as bolt.DB.Update does.
//
// # Inputs
//
//   - fn: writes through tx; must not call Update on the same DB
//
// # Outputs
//
//   - error: fn's error or bbolt's (nothing was written); or one wrapping
//     ErrCorrupt when the transaction panicked or faulted, or the handle is
//     poisoned. After a panic whether the transaction reached the disk is not
//     known.
//
// # Example
//
//	err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(name).Put(k, v) })
//
// # Limitations
//
//   - As the package's.
//
// # Assumptions
//
//   - fn starts no goroutine that touches the file.
func (d *DB) Update(fn func(tx *bolt.Tx) error) error {
	return d.guard.RunWrite(func() error { return d.db.Update(fn) })
}

// Begin starts a read-only transaction the caller keeps, as bolt.DB.Begin(false).
//
// # Description
//
// For a consistent view held across several calls. Every read through the
// returned transaction must itself run inside [DB.Do], and the transaction
// must end with [DB.Rollback] before Close.
//
// # Outputs
//
//   - *bolt.Tx: the transaction
//   - error: bbolt's; or one wrapping ErrCorrupt
//
// # Example
//
//	tx, err := db.Begin()
//	if err != nil {
//	    return err
//	}
//	defer db.Rollback(tx)
//	err = db.Do(func() error { v = bytes.Clone(tx.Bucket(name).Get(key)); return nil })
//
// # Limitations
//
//   - Read-only: a kept write transaction would hold the writer lock outside
//     the guard.
//
// # Assumptions
//
//   - The caller rolls it back.
func (d *DB) Begin() (*bolt.Tx, error) {
	var tx *bolt.Tx
	err := d.guard.Run(func() error {
		var err error
		tx, err = d.db.Begin(false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// Do runs a read through a transaction from [DB.Begin], guarded.
//
// # Inputs
//
//   - fn: the read
//
// # Outputs
//
//   - error: fn's; or one wrapping ErrCorrupt when it panicked or faulted, or
//     the handle is poisoned (fn is then not called)
//
// # Example
//
//	err := db.Do(func() error { n = tx.Bucket(name).Stats().KeyN; return nil })
//
// # Limitations
//
//   - As the package's.
//
// # Assumptions
//
//   - fn only reads.
func (d *DB) Do(fn func() error) error { return d.guard.Run(fn) }

// Rollback ends a transaction from [DB.Begin]. On a poisoned handle it does
// nothing: the transaction is abandoned with the handle.
//
// # Inputs
//
//   - tx: the transaction; nil is ignored
//
// # Example
//
//	defer db.Rollback(tx)
//
// # Limitations
//
//   - Errors are dropped: a read-only rollback has nothing to report.
//
// # Assumptions
//
//   - tx came from this DB.
func (d *DB) Rollback(tx *bolt.Tx) {
	if tx == nil {
		return
	}
	_ = d.guard.Run(tx.Rollback)
}

// Poisoned reports whether a call on this handle panicked or faulted.
//
// # Outputs
//
//   - bool: true once the handle must no longer be used
//
// # Example
//
//	if db.Poisoned() {
//	    // the file is damaged; every further call returns ErrCorrupt
//	}
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - None.
func (d *DB) Poisoned() bool { return d.guard.Poisoned() }

// Close releases the file.
//
// # Description
//
// A healthy handle is closed by bbolt. A poisoned one is NOT: bbolt's Close
// takes the writer lock, which the failed transaction may still hold, and
// would wait for good. Instead the file lock is released and the descriptor
// closed directly, so other handles and processes can open the file again. The
// memory map and bbolt's in-memory state stay until the process exits.
//
// # Outputs
//
//   - error: bbolt's close error; or, for a poisoned handle, an error wrapping
//     ErrCorrupt saying it was abandoned
//
// # Example
//
//	defer db.Close()
//
// # Limitations
//
//   - A poisoned handle leaks its memory map until the process exits.
//   - A panic inside bbolt's own Close poisons the handle and is handled the
//     same way.
//
// # Assumptions
//
//   - Every transaction from Begin was rolled back.
func (d *DB) Close() error {
	if !d.guard.Poisoned() {
		err := d.guard.RunWrite(d.db.Close)
		if !d.guard.Poisoned() {
			return err
		}
	}
	// A write still inside bbolt on another goroutine: give it a moment to
	// come out before the file lock goes. One stuck there for good is the
	// reason the handle is abandoned, and is not waited for.
	done, _ := d.guard.WaitForWriter(abandonWait)
	d.files.release()
	done()
	return fmt.Errorf("%w (the handle was abandoned, not closed: its memory map stays until the process exits)",
		ErrCorrupt)
}

// Compact copies src into dst as bolt.Compact does, guarded on both handles.
//
// # Inputs
//
//   - dst: an empty file opened for writing
//   - src: the file to copy, opened read-only
//
// # Outputs
//
//   - error: bolt.Compact's; or one wrapping ErrCorrupt when reading src or
//     writing dst panicked or faulted (both handles are then poisoned: the
//     panic cannot be attributed to one)
//
// # Example
//
//	err := safebolt.Compact(dst, src)
//
// # Limitations
//
//   - One transaction: the copy is held in memory until it commits.
//
// # Assumptions
//
//   - Nothing else uses either handle meanwhile.
func Compact(dst, src *DB) error {
	err := src.guard.Run(func() error { return bolt.Compact(dst.db, src.db, 0) })
	if src.guard.Poisoned() {
		// The panic unwound through dst's write transaction too.
		dst.guard.Poison()
	}
	return err
}

// Check reads a whole bbolt file and reports whether it is well formed.
//
// # Description
//
// The file is opened read-only (a shared lock; nothing is created or changed)
// with its freelist loaded, and then, in one transaction:
//
//   - the file must be at least as long as the database it records;
//   - every bucket is walked, buckets inside buckets included, and every key
//     read; keys must be in strictly increasing order.
//
// That reads every branch and leaf page the database reaches, so a file cut
// short, or one whose pages were overwritten, fails here instead of inside a
// later write. Values are not read: a large value's pages are only counted.
//
// bbolt's own consistency check (Tx.Check) is deliberately not used: it runs
// on a goroutine it starts itself, and a panic or memory fault there cannot be
// recovered, so on exactly the files this exists for it ends the process.
//
// # Inputs
//
//   - path: the file; it must exist
//   - opts: bbolt's options (Timeout and OpenFile are used); nil for defaults
//
// # Outputs
//
//   - error: nil when the file reads cleanly; an error wrapping ErrCorrupt
//     when it does not; bolt.ErrTimeout when another process holds it; or the
//     open error
//
// # Example
//
//	if err := safebolt.Check(path, &bolt.Options{Timeout: 5 * time.Second}); err != nil {
//	    return err // do not open it for writing
//	}
//
// # Limitations
//
//   - Time and I/O linear in the file's key pages (about the whole file when
//     values are small).
//   - It does not cross-check the freelist against the pages in use, which
//     Tx.Check does: a freelist that names a live page passes.
//   - A passing file can still be damaged before the write that follows; the
//     guard on every call is what makes that an error too.
//
// # Assumptions
//
//   - The caller wants to hold the file's shared lock for the duration.
func Check(path string, opts *bolt.Options) error {
	var o bolt.Options
	if opts != nil {
		o = *opts
	}
	o.ReadOnly = true
	o.PreLoadFreelist = true
	db, err := Open(path, 0o600, &o)
	if err != nil {
		// bbolt noticed the damage itself, in the meta pages.
		for _, known := range []error{bolt.ErrInvalid, bolt.ErrChecksum, bolt.ErrVersionMismatch} {
			if errors.Is(err, known) {
				return fmt.Errorf("%w (%v)", ErrCorrupt, err)
			}
		}
		return err
	}
	defer db.Close()
	var fileSize int64 = -1
	db.files.mu.Lock()
	if len(db.files.files) > 0 {
		if fi, err := db.files.files[0].Stat(); err == nil {
			fileSize = fi.Size()
		}
	}
	db.files.mu.Unlock()
	return db.View(func(tx *bolt.Tx) error {
		if fileSize >= 0 && fileSize < tx.Size() {
			return fmt.Errorf("%w (the file is %d bytes, shorter than the %d its database records)",
				ErrCorrupt, fileSize, tx.Size())
		}
		budget := tx.Size()/minLeafElementBytes + 1
		return walk(tx.Cursor(), func(name []byte) *bolt.Bucket { return tx.Bucket(name) }, true, 1, &budget)
	})
}

// walk reads every key under one cursor, descending into buckets. root is the
// transaction's own cursor, whose every key names a bucket.
func walk(c *bolt.Cursor, child func(name []byte) *bolt.Bucket, root bool, depth int, budget *int64) error {
	if depth > maxBucketDepth {
		return fmt.Errorf("%w (buckets nested more than %d deep)", ErrCorrupt, maxBucketDepth)
	}
	var prev []byte
	first := true
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if *budget--; *budget < 0 {
			return fmt.Errorf("%w (more keys than the file can hold: its pages loop)", ErrCorrupt)
		}
		if !first && bytes.Compare(prev, k) >= 0 {
			return fmt.Errorf("%w (keys are out of order)", ErrCorrupt)
		}
		prev, first = k, false
		if !root && v != nil {
			continue
		}
		b := child(k)
		if b == nil {
			if root {
				return fmt.Errorf("%w (a top-level key is not a bucket)", ErrCorrupt)
			}
			continue // a key with an empty value
		}
		if err := walk(b.Cursor(), b.Bucket, false, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
}

// Checker runs Check at most once per file.
//
// The zero value is ready. Safe for concurrent use.
type Checker struct {
	mu     sync.Mutex
	done   map[fileID]bool
	failed fileSet // files that failed: refused without being read again
}

// fileID identifies a file by device and inode: a file replaced under the same
// name is a different file.
type fileID struct{ dev, ino uint64 }

// fileSet is a set of files, safe for concurrent use.
type fileSet struct {
	mu  sync.Mutex
	ids map[fileID]bool
}

func (s *fileSet) add(id fileID) {
	s.mu.Lock()
	if s.ids == nil {
		s.ids = map[fileID]bool{}
	}
	s.ids[id] = true
	s.mu.Unlock()
}

func (s *fileSet) has(id fileID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ids[id]
}

func idOf(fi os.FileInfo) (fileID, bool) {
	dev, ino, ok := osfile.Identity(fi)
	return fileID{dev: dev, ino: ino}, ok
}

// Once checks the file at path unless this Checker already passed it.
//
// # Description
//
// A file that does not exist, or is empty (bbolt initialises it), has nothing
// to check. A file that fails is refused on every later call without being
// read again, until it is replaced (another device and inode): a check that
// faults inside the storage layer abandons a handle, which keeps its memory
// map until the process exits, so re-reading a damaged file on every call, as
// a long-lived server would, would exhaust the address space.
//
// # Inputs
//
//   - path: the file about to be opened for writing
//   - opts: as [Check]'s
//
// # Outputs
//
//   - error: as [Check]'s; nil when the file is absent, empty, or already
//     passed
//
// # Example
//
//	var checked safebolt.Checker
//	if err := checked.Once(path, opts); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Once per file, not per write: damage after the check is the guard's to
//     catch.
//
// # Assumptions
//
//   - Device and inode identify a file for the life of the process.
func (c *Checker) Once(path string, opts *bolt.Options) error {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || !fi.Mode().IsRegular() {
		return nil // absent, new, or not a file bbolt will open: the open reports it
	}
	id, known := idOf(fi)
	if known {
		c.mu.Lock()
		passed := c.done[id]
		c.mu.Unlock()
		if passed {
			return nil
		}
		if c.failed.has(id) {
			return fmt.Errorf("%w (this file already failed its check in this process; it is not read "+
				"again until it is replaced)", ErrCorrupt)
		}
	}
	if err := Check(path, opts); err != nil {
		if known && errors.Is(err, ErrCorrupt) {
			c.failed.add(id)
		}
		return err
	}
	if known {
		c.mark(id)
	}
	return nil
}

// Mark records the file now at path as passed, without reading it: for a file
// this process has just written whole (a compaction's fresh copy).
//
// # Inputs
//
//   - path: the file; a missing one is ignored
//
// # Example
//
//	checked.Mark(path) // just rewritten from a copy that read cleanly
//
// # Limitations
//
//   - It trusts the caller.
//
// # Assumptions
//
//   - The file was produced by reading every key of a file that passed.
func (c *Checker) Mark(path string) {
	if fi, err := os.Stat(path); err == nil {
		if id, ok := idOf(fi); ok {
			c.mark(id)
		}
	}
}

func (c *Checker) mark(id fileID) {
	c.mu.Lock()
	if c.done == nil {
		c.done = map[fileID]bool{}
	}
	c.done[id] = true
	c.mu.Unlock()
}

// CompactFile rewrites the bbolt file at path into a fresh one, so values
// deleted from it are gone from the live file rather than left in its free
// pages (bbolt never zeroes them).
//
// # Description
//
// Leftover copies of an interrupted compaction are removed first, even when
// the file itself is gone: each is a copy of the file. The copy is written to
// a new file with an unpredictable name, created exclusively, synced and
// renamed over the original, and then the folder is synced. A crash before the
// rename leaves the original intact. A damaged original fails the copy
// (ErrCorrupt) and is left as it was.
//
// # Inputs
//
//   - path: the file. A missing file is not an error: there is nothing to rewrite.
//   - srcOpts, dstOpts: how to open the original (read-only) and the copy;
//     their OpenFile is where a caller refuses symlinks.
//
// # Outputs
//
//   - error: from opening, copying, syncing or renaming
//
// # Example
//
//	err := safebolt.CompactFile(path, &bolt.Options{ReadOnly: true}, &bolt.Options{})
//
// # Limitations
//
//   - It reaches the live file only: not SSD wear-levelled blocks, filesystem
//     snapshots or journals, or backups.
//   - The caller holds whatever lock keeps writers out; bbolt's own file lock
//     is held on the original only while it is copied.
//
// # Assumptions
//
//   - path names a regular file, or nothing.
func CompactFile(path string, srcOpts, dstOpts *bolt.Options) error {
	dir, base := filepath.Split(path)
	if err := removeCompactLeftovers(dir, base); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	tf, err := os.CreateTemp(dir, base+".compact-*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	src, err := Open(path, 0o600, srcOpts)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	dst, err := Open(tmp, 0o600, dstOpts)
	if err != nil {
		src.Close()
		_ = os.Remove(tmp)
		return err
	}
	err = Compact(dst, src)
	src.Close()
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncPath(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncPath(filepath.Clean(dir))
}

// removeCompactLeftovers removes the temporary copies an interrupted
// compaction of base left in dir.
func removeCompactLeftovers(dir, base string) error {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".compact") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove an earlier compaction's leftover: %w", err)
			}
		}
	}
	return nil
}

// syncPath fsyncs a file or a folder by name.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// LockSuffix names the lock file beside a database: path + LockSuffix.
const LockSuffix = ".lock"

// ErrLockHeld means another process held a lock file past the timeout.
var ErrLockHeld = errors.New("held by another process")

// LockFile takes the lock on path's lock file, path + [LockSuffix], creating it
// if need be.
//
// # Description
//
// bbolt locks the database file itself, so a lock on it cannot span a rewrite
// that renames a fresh copy over it ([CompactFile]): a writer that opened the
// old file in that window would write to a file that is then replaced, and
// lose what it wrote. A separate lock file is never renamed. Every writer
// takes it exclusively, and so does a compaction, from before the copy until
// after the rename.
//
// # Inputs
//
//   - path: the database the lock is for
//   - exclusive: an exclusive lock (a writer's), or a shared one
//   - timeout: how long to wait for a held lock; zero waits forever, as bbolt's
//     own lock does
//
// # Outputs
//
//   - *os.File: the held lock; release it with [UnlockFile]
//   - error: wrapping ErrLockHeld on timeout, or from opening the file
//
// # Example
//
//	lock, err := safebolt.LockFile(path, true, 5*time.Second)
//	if err != nil {
//	    return err
//	}
//	defer safebolt.UnlockFile(lock)
//
// # Limitations
//
//   - flock is advisory: only code that takes this lock is held off by it.
//   - A symlink at the lock file's name is refused, never followed.
//
// # Assumptions
//
//   - The folder is writable, or the lock file already exists.
func LockFile(path string, exclusive bool, timeout time.Duration) (*os.File, error) {
	f, err := osfile.OpenNoFollow(path+LockSuffix, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the lock file: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		got, err := osfile.TryLock(f, exclusive)
		if got {
			return f, nil
		}
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("take the lock: %w", err)
		}
		if timeout > 0 && time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("the lock file is %w (waited %s)", ErrLockHeld, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// UnlockFile releases and closes a lock taken by LockFile. nil is a no-op.
func UnlockFile(f *os.File) {
	if f == nil {
		return
	}
	osfile.Unlock(f)
	_ = f.Close()
}
