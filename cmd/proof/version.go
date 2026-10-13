// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

// version is the release this binary was built as. The image build sets it
// with -ldflags "-X main.version=v1.2.3": its build context has no .git, so the
// toolchain cannot record one. Empty for `go install` and `go build`, where the
// module version and VCS revision come from the build info instead.
var version = ""

// cmdVersion prints what this binary is: the release, and the commit it was
// built from when the toolchain recorded one.
//
// A binary that cannot say what it is cannot be matched to a changelog entry,
// an advisory or a published checksum.
func cmdVersion(stdout *os.File) int {
	fmt.Fprintln(stdout, versionString())
	return exitOK
}

// versionString is "proof <version>", with the commit and a modified-tree
// marker when known. "(devel)" means a local build of an untagged tree.
func versionString() string {
	v, revision, modified := version, "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	if v == "" {
		v = "(devel)"
	}
	out := "proof " + v
	if len(revision) >= 12 {
		out += " (commit " + revision[:12]
		if modified {
			out += ", modified tree"
		}
		out += ")"
	}
	return out
}
