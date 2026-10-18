// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package osfile

import "os"

// ChangeTime reports false: this platform's ctime is not read.
func ChangeTime(os.FileInfo) (int64, bool) { return 0, false }
