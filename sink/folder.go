// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"syscall"

	"github.com/aleutian-ai/proof/anchor"
)

// A sink folder may come from someone else's archive, and the evidence file may
// have been shared and crafted. So every file under anchors/ (the only files a
// sink reads by name; event content lives in evidence.db.secrets) is reached
// through an os.Root, which no name and no symlink can escape. And every
// directory is Lstat-checked to be a real directory: a symlink that stays inside
// the root (anchors/a → anchors/b) would otherwise mix two chains' series.
//
// The four bbolt files are opened by path (bbolt takes a path), so each is
// checked to be a regular file, or absent, first.

// maxAnchorBytes caps one checkpoint file. A v6 anchor is about 5 KiB.
const maxAnchorBytes = 1 << 20

// anchorName matches a checkpoint file: a number of at least 4 digits.
var anchorName = regexp.MustCompile(`^(\d{4,})\.json$`)

// errNotRealDir marks a path that should be a directory but is something else,
// typically a symlink.
var errNotRealDir = errors.New("not a real directory (a symlink or a file)")

// errNoSink is returned when a read or erase finds no evidence file.
var errNoSink = errors.New("no sink here: the evidence file does not exist")

// afterLstat runs between readSmall's Lstat and its open. A variable only so a
// test can swap the file in exactly that window: the swap a TOCTOU attacker
// would make, which the check on the open handle must catch.
var afterLstat func(name string)

// folder is an open sink folder.
type folder struct{ root *os.Root }

// openFolder opens the sink folder, creating it only when create is set (the
// first Commit). Read verbs never create anything.
func (s *Sink) openFolder(create bool) (*folder, error) {
	if create {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, fmt.Errorf("sink: create %s: %w", s.dir, err)
		}
	}
	root, err := os.OpenRoot(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("sink: %s: %w", s.dir, errNoSink)
	}
	if err != nil {
		return nil, fmt.Errorf("sink: open %s: %w", s.dir, err)
	}
	return &folder{root: root}, nil
}

func (f *folder) Close() { f.root.Close() }

// realDir reports whether name is an existing real directory: false with no
// error when absent, errNotRealDir when it is anything else.
func (f *folder) realDir(name string) (bool, error) {
	fi, err := f.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s: %w", name, errNotRealDir)
	}
	return true, nil
}

// mkdirAll creates name and its parents inside the root, refusing any
// component that exists but is not a real directory.
func (f *folder) mkdirAll(name string, perm os.FileMode) error {
	var built string
	for _, part := range splitPath(name) {
		built = filepath.Join(built, part)
		ok, err := f.realDir(built)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		if err := f.root.Mkdir(built, perm); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if ok, err := f.realDir(built); err != nil || !ok {
			return fmt.Errorf("%s: %w", built, errNotRealDir)
		}
	}
	return nil
}

func splitPath(name string) []string {
	var parts []string
	for name != "" && name != "." {
		dir, base := filepath.Split(filepath.Clean(name))
		parts = append([]string{base}, parts...)
		name = filepath.Clean(dir)
		if name == string(filepath.Separator) {
			break
		}
	}
	return parts
}

// list returns a real directory's entries; nothing when it is absent.
func (f *folder) list(name string) ([]os.DirEntry, error) {
	ok, err := f.realDir(name)
	if err != nil || !ok {
		return nil, err
	}
	d, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}

// writeNew creates a file that must not already exist (O_EXCL also refuses a
// symlink in its place). Checkpoints are written with it.
func (f *folder) writeNew(name string, data []byte, mode os.FileMode) error {
	w, err := f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("sink: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		_ = f.root.Remove(name)
		return fmt.Errorf("sink: write %s: %w", name, err)
	}
	if err := w.Close(); err != nil {
		_ = f.root.Remove(name)
		return fmt.Errorf("sink: close %s: %w", name, err)
	}
	return nil
}

// readSmall reads a small regular file.
//
// # Outputs
//
//   - the bytes
//   - missing: the file does not exist
//   - problem: it exists but is not usable (not a regular file, a symlink, or
//     over max bytes), reported rather than read
//   - err: it could not be examined at all
//
// Checked twice, by name (Lstat: refuses a symlink) and on the open handle
// (fstat: the type and size of what was actually opened, so a swap between the
// two cannot slip a FIFO or /dev/zero past). O_NONBLOCK keeps a FIFO from
// hanging the open. The read is capped whatever the size claimed.
func (f *folder) readSmall(name string, max int64) (data []byte, missing bool, problem string, err error) {
	fi, err := f.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, "", nil
	}
	if err != nil {
		return nil, false, "", err
	}
	if p := smallFileProblem(fi, max); p != "" {
		return nil, false, p, nil
	}
	if afterLstat != nil {
		afterLstat(name)
	}
	h, err := f.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, "", nil
	}
	if err != nil {
		return nil, false, "", err
	}
	defer h.Close()
	if fi, err = h.Stat(); err != nil {
		return nil, false, "", err
	}
	if p := smallFileProblem(fi, max); p != "" {
		return nil, false, p, nil
	}
	b, err := io.ReadAll(io.LimitReader(h, max+1))
	if err != nil {
		return nil, false, "", err
	}
	if int64(len(b)) > max {
		return nil, false, fmt.Sprintf("it grew past the %d byte limit while being read", max), nil
	}
	return b, false, "", nil
}

func smallFileProblem(fi os.FileInfo, max int64) string {
	switch {
	case !fi.Mode().IsRegular():
		return "it is not a regular file"
	case fi.Size() > max:
		return fmt.Sprintf("it is %d bytes, over the %d byte limit", fi.Size(), max)
	}
	return ""
}

// readAnchors returns one chain's checkpoints, in order.
//
// The folder must hold exactly 0001.json … NNNN.json with no gaps, sorted by
// NUMBER (so 10000.json follows 9999.json), and nothing else. Anything else is
// a problem: a stray file, a gap, a symlink, an oversized or unparseable
// checkpoint. The problem string is empty when the series is well formed.
func (f *folder) readAnchors(chain string) ([]anchor.Anchor, string, error) {
	dir := filepath.Join("anchors", chain)
	ents, err := f.list(dir)
	if errors.Is(err, errNotRealDir) {
		return nil, fmt.Sprintf("anchors/%s is %v", chain, errNotRealDir), nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("sink: %w", err)
	}
	type numbered struct {
		n    int
		name string
	}
	var files []numbered
	for _, e := range ents {
		m := anchorName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Sprintf("anchors/%s holds %q, which is not a checkpoint file", chain, e.Name()), nil
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Sprintf("anchors/%s: %q is not a usable number", chain, e.Name()), nil
		}
		files = append(files, numbered{n, e.Name()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n < files[j].n })
	out := make([]anchor.Anchor, 0, len(files))
	for i, nf := range files {
		if nf.n != i+1 {
			return nil, fmt.Sprintf("anchors/%s: checkpoint %04d is missing (the series must run 1..n)", chain, i+1), nil
		}
		raw, missing, problem, err := f.readSmall(filepath.Join(dir, nf.name), maxAnchorBytes)
		if err != nil {
			return nil, "", fmt.Errorf("sink: %w", err)
		}
		if missing || problem != "" {
			return nil, fmt.Sprintf("checkpoint %s: %s", nf.name, orMissing(problem, missing)), nil
		}
		var a anchor.Anchor
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Sprintf("checkpoint %s is not a checkpoint: %v", nf.name, err), nil
		}
		out = append(out, a)
	}
	return out, "", nil
}

func orMissing(problem string, missing bool) string {
	if missing {
		return "it disappeared while being read"
	}
	return problem
}

// regularOrAbsent refuses a bbolt file path that exists but is not a regular
// file: bbolt would follow a symlink and write wherever it points.
func regularOrAbsent(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (a symlink?); refusing to open it", filepath.Base(path))
	}
	return nil
}
