// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package osfile

import (
	"errors"
	"os"
	"syscall"
)

// NonBlock is O_NONBLOCK: an open of a FIFO cannot hang, and it has no effect
// on a regular file.
const NonBlock = syscall.O_NONBLOCK

// OpenNoFollow is os.OpenFile with O_NOFOLLOW: a symlink at path fails to
// open, rather than being followed.
func OpenNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}

// TryLock takes an advisory lock on f without waiting: exclusive or shared. It
// reports false, with no error, when another holder has it.
func TryLock(f *os.File, exclusive bool) (bool, error) {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK):
		return false, nil
	}
	return false, err
}

// Unlock releases a lock TryLock took (or one bbolt took on its own file).
func Unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// Identity is the device and inode of a file, and whether they were readable.
func Identity(fi os.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true //nolint:unconvert // int32 on darwin
}

// IsNotDir reports whether err is ENOTDIR: a path component that is a file.
func IsNotDir(err error) bool { return errors.Is(err, syscall.ENOTDIR) }

// IsReadOnlyFS reports whether err is EROFS: the file system is mounted
// read-only, so nothing on it can be written by anyone.
func IsReadOnlyFS(err error) bool { return errors.Is(err, syscall.EROFS) }
