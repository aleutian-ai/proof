// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package osfile

import (
	"os"
	"syscall"
)

// ChangeTime is the file's status change time (ctime) in nanoseconds since
// the epoch. Every write and every metadata change moves it, and no caller
// can set it back, so it tells a file changed in place from one left alone.
func ChangeTime(fi os.FileInfo) (int64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ctimespec.Nano(), true
}
