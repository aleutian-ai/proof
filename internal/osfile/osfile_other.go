// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package osfile

import "os"

// NonBlock is zero here: there is no O_NONBLOCK.
const NonBlock = 0

// OpenNoFollow returns ErrUnsupportedPlatform: there is no O_NOFOLLOW, and a
// store must never follow a symlink.
func OpenNoFollow(string, int, os.FileMode) (*os.File, error) { return nil, ErrUnsupportedPlatform }

// TryLock returns ErrUnsupportedPlatform.
func TryLock(*os.File, bool) (bool, error) { return false, ErrUnsupportedPlatform }

// Unlock does nothing: nothing was locked.
func Unlock(*os.File) {}

// Identity reports no identity.
func Identity(os.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }

// IsNotDir reports false.
func IsNotDir(error) bool { return false }

// IsReadOnlyFS reports false on an unsupported platform.
func IsReadOnlyFS(error) bool { return false }
