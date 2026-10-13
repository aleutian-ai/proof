// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import "runtime/debug"

// version is the release this binary was built as. The image build sets it
// with -ldflags "-X main.version=v1.2.3": its build context has no .git, so the
// toolchain cannot record one. Empty for `go install` and `go build`, where the
// module version comes from the build info instead.
var version = ""

// serverVersion is what the server reports as its version in the MCP
// initialize handshake: the release it was built as, else the module version
// the toolchain recorded, else "(devel)" for a local build of an untagged tree.
//
// It was a constant in the source, which a release could forget to change and
// which said nothing true about a build from any other commit.
func serverVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
