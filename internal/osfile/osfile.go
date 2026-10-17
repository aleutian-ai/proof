// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package osfile holds the few operating-system calls this module's stores
// need and the Go standard library does not offer portably: opening a file
// without following a symlink, advisory file locks, and a file's identity.
//
// # Description
//
// They exist on Linux and macOS, the platforms proof supports. On any other
// platform every function returns ErrUnsupportedPlatform, so a command that
// opens a store says so plainly instead of the module failing to compile, or,
// worse, quietly following a symlink a store must refuse. Verifying an
// exported file needs none of this.
//
// # Limitations
//
//   - Locks are advisory (flock): only code that takes them is held off.
//
// # Assumptions
//
//   - None.
package osfile

import "errors"

// ErrUnsupportedPlatform is returned on a platform other than Linux and macOS.
var ErrUnsupportedPlatform = errors.New("this platform is not supported: proof's stores run on Linux and macOS " +
	"(they need flock and O_NOFOLLOW); verifying an exported file works anywhere")
