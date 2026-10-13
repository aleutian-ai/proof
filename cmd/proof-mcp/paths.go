// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ---------------------------------------------------------------------------
// Model-supplied paths
//
// Every path in a tool call is attacker-controlled under prompt injection. All
// of them go through fileRoot, and nothing else in this package opens a file a
// tool call named.
// ---------------------------------------------------------------------------

// maxEntriesFileBytes bounds a single read.
//
// A model-supplied path could point at a multi-gigabyte log. The cap turns "the
// agent hung" into a clear error. 64 MiB is far beyond any plausible export
// while remaining bounded.
const maxEntriesFileBytes = 64 << 20

// errOutsideRoot is the ONE answer for a path that is not inside the root.
//
// It carries no path, size, type or existence information, and it is the same
// for a missing file, a directory and a readable file. Anything more specific
// would let a tool call map the rest of the machine one error at a time.
var errOutsideRoot = errors.New("that path is outside the directory this server was started with (--root)")

// Distinguishable read failures, for paths INSIDE the root. A caller needs to
// know whether the path was wrong, the file was the wrong KIND, or it was too
// big (aleutianchain_55).
var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file is too large")
)

// fileRoot is the one directory tree a path in a tool call may name.
//
// The zero value has no directory and refuses every path.
type fileRoot struct {
	dir  string // absolute, as given at launch
	real string // dir with symbolic links resolved
}

// newFileRoot checks that dir is a directory and records it.
//
// Both spellings are kept because a client may send either: on macOS the
// working directory can be reported as /var/... while its real path is
// /private/var/....
func newFileRoot(dir string) (fileRoot, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fileRoot{}, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fileRoot{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fileRoot{}, err
	}
	if !info.IsDir() {
		return fileRoot{}, fmt.Errorf("%s is not a directory", abs)
	}
	return fileRoot{dir: abs, real: resolved}, nil
}

// rel turns a model-supplied path into one relative to the root.
//
// The check is lexical and touches no file. A relative path is relative to the
// root. An absolute path is accepted only when it is under the root. A path
// that passes can still name a symbolic link that leaves the root; os.Root
// refuses that when the file is opened.
func (r fileRoot) rel(path string) (string, error) {
	if r.dir == "" {
		return "", errOutsideRoot
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		if !filepath.IsLocal(clean) {
			return "", errOutsideRoot
		}
		return clean, nil
	}
	for _, base := range []string{r.dir, r.real} {
		rel, err := filepath.Rel(base, clean)
		if err == nil && filepath.IsLocal(rel) {
			return rel, nil
		}
	}
	return "", errOutsideRoot
}

// read returns the contents of a regular file inside the root, refusing
// anything over limit bytes.
//
// The file is opened ONCE, through os.Root, and every check is made on the open
// file, so the file that was checked is the file that is read. os.Root follows
// a symbolic link that stays inside the root and refuses one that leaves it.
//
// Inside the root, errors say which cause it was and name the path the caller
// sent. They never include file contents.
func (r fileRoot) read(path string, limit int64) ([]byte, error) {
	rel, err := r.rel(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(r.real)
	if err != nil {
		return nil, fmt.Errorf("open the --root directory: %w", err)
	}
	defer root.Close()

	// O_NONBLOCK so that opening a named pipe returns instead of waiting for a
	// writer. It has no effect on a regular file.
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
		case errors.Is(err, fs.ErrPermission):
			return nil, fmt.Errorf("%s: %w", path, fs.ErrPermission)
		}
		// os.Root reports a symbolic link that leaves the root with an error it
		// does not export. Every failure that is not one of the causes above gets
		// the fixed answer, so an unrecognised one fails closed.
		return nil, errOutsideRoot
	}
	defer f.Close()
	return readRegular(f, path, limit)
}

// realDir returns the real path of a directory inside the root.
//
// It is for bundle.VerifyDir, which takes a path and not an open directory. Call
// it only after a read under the same directory has succeeded: that read is what
// refuses a symbolic link leaving the root without saying whether its target
// exists.
func (r fileRoot) realDir(path string) (string, error) {
	rel, err := r.rel(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(r.real, rel))
	if err != nil {
		return "", errOutsideRoot
	}
	if back, err := filepath.Rel(r.real, resolved); err != nil || !filepath.IsLocal(back) {
		return "", errOutsideRoot
	}
	return resolved, nil
}

// readRegular reads an open file, refusing anything that is not a regular file
// or is over limit bytes. name is used in errors only.
//
// The size is not taken on trust: some files report a size of 0 and a file can
// grow after it is opened. The read itself stops one byte past the limit.
func readRegular(f *os.File, name string, limit int64) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: cannot be read", name)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is %s: %w", name, describeMode(info.Mode()), errNotRegular)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit: %w",
			name, info.Size(), limit, errTooLarge)
	}
	// Sized up front so the contents are held once and not copied as they grow.
	buf := bytes.NewBuffer(make([]byte, 0, info.Size()+bytes.MinRead))
	if _, err := buf.ReadFrom(io.LimitReader(f, limit+1)); err != nil {
		return nil, fmt.Errorf("%s: cannot be read", name)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("%s is over the %d byte limit: %w", name, limit, errTooLarge)
	}
	return buf.Bytes(), nil
}

// describeMode names what a non-regular file actually is.
//
// "not a regular file" leaves a reader guessing; "is a directory" does not.
func describeMode(m os.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&os.ModeDevice != 0:
		return "a device"
	case m&os.ModeNamedPipe != 0:
		return "a named pipe"
	case m&os.ModeSocket != 0:
		return "a socket"
	}
	return "an irregular file"
}
