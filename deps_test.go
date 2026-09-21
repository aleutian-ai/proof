// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"os/exec"
	"strings"
	"testing"
)

// modulePath is this module's import prefix. Packages under it are our own and
// are never counted as external dependencies.
const modulePath = "github.com/aleutian-ai/proof"

// allowedDeps declares, per package, the external modules that package may
// depend on. A package absent from this table is not checked; a package present
// with an empty list must have NO external dependencies at all.
//
// # Why this exists
//
// "The crypto core has zero dependencies" is a headline property of this
// project — for a library whose purpose is letting a skeptic check the work, a
// reviewer having no transitive graph to walk is a feature, not tidiness. A
// property protected only by attention stops being true the first time someone
// adds a convenient import. This test is the enforcement.
//
// # Adding an entry
//
// Do not widen an allowlist to make a build pass. Each entry below is a
// deliberate architectural decision with a reason recorded in
// docs/AleutianChain/aleutian_chain_oss_core_design.md §3.1. Adding a dependency
// to the zero-dependency core is a design change, not a build fix.
var allowedDeps = map[string][]string{
	// The crypto core. Everything here is stdlib-only, including the
	// post-quantum KEM: crypto/mlkem, crypto/sha3, and crypto/ecdh are all in
	// the standard library as of Go 1.24, which also places these packages
	// inside Go's native FIPS 140-3 module boundary.
	"/xwing":        {},
	"/keywrap":      {},
	"/merkle":       {},
	"/fixtures":     {},
	"/bundle":       {},
	"/internal/mem": {},

	// Unicode NFC validation requires the Unicode tables, which the standard
	// library does not ship. canonical rejects non-NFC strings fail-closed
	// (ErrNotNFC) because a producer sending unnormalized text is the classic
	// cause of cross-LANGUAGE canonicalization divergence: Go, Python, and JS
	// would each hash different bytes for the same logical string. Hand-rolling
	// a normalization quick-check over a security boundary would be strictly
	// worse than depending on the Go team's implementation.
	//
	// Precedent: sdk/verification-go already requires golang.org/x/text for the
	// same check, and the two MUST agree byte-for-byte.
	//
	// chainformat and anchor inherit this transitively via canonical.
	"/canonical":   {"golang.org/x/text"},
	"/chainformat": {"golang.org/x/text"},

	// ML-DSA-65 has no standard library implementation — verified on go1.25.6,
	// crypto/mldsa and crypto/slhdsa do not exist. circl is therefore
	// unavoidable for anchor signature verification, and is confined here so a
	// caller who only wants the KEM never pulls it in.
	//
	// golang.org/x/sys is NOT a choice: circl reaches x/sys/cpu for its
	// assembly-optimised code paths. It was already in the module graph (bbolt
	// needs it), so this adds no new module — but it does mean a consumer who
	// imports only `anchor` still pulls x/sys. Listed explicitly because this
	// test caught it; the original allowlist assumed circl arrived alone.
	"/anchor": {"github.com/cloudflare/circl", "golang.org/x/sys"},

	// verify imports anchor, so circl and x/sys are reachable from it too.
	//
	// The ticket's "circl in /anchor and NOTHING ELSE" cannot hold literally once
	// verification is exposed through verify — the meaningful invariant is that
	// the FORMAT AND KEM PRIMITIVES stay clean, which the entries above enforce.
	// x/text arrives via chainformat → canonical.
	"/verify": {
		"github.com/cloudflare/circl",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// The default store. Confined so that a caller embedding the format and
	// verification logic does not inherit a storage engine.
	//
	// golang.org/x/sys is bbolt's, not ours — it needs syscalls for the file lock
	// and mmap. Listed explicitly rather than allowed implicitly so that a future
	// direct use of x/sys elsewhere in the module still fails this test.
	//
	// x/sys is also why the module's `go` directive is pinned by hand: x/sys
	// v0.45.0 requires go 1.25.0, which would raise the floor for every consumer
	// including those who only want the KEM. Held at v0.30.0 and bbolt at v1.4.3
	// (rather than v1.5.0, which itself requires 1.25) to keep the floor at 1.24.
	// If those pins are ever bumped, expect the go directive to move with them.
	"/store/bolt": {"go.etcd.io/bbolt", "golang.org/x/sys"},
}

// forbiddenEverywhere are imports that must never appear anywhere in this
// module, in any package, for any reason.
//
// A cloud import in this module would not merely be unwanted — it would make
// the module unusable, and therefore untrustworthy, to an outside auditor who
// cannot authenticate to that cloud. The whole premise is offline verification.
var forbiddenEverywhere = []string{
	"cloud.google.com/",
	"google.golang.org/api/",
	"github.com/aws/",
	"github.com/Azure/",
}

// TestDependencyIsolation enforces the per-package dependency rules above.
func TestDependencyIsolation(t *testing.T) {
	for suffix, allowed := range allowedDeps {
		pkg := modulePath + suffix
		t.Run(suffix, func(t *testing.T) {
			deps, err := externalDeps(pkg)
			if err != nil {
				t.Fatalf("resolve deps of %s: %v", pkg, err)
			}
			for _, d := range deps {
				if !isAllowed(d, allowed) {
					if len(allowed) == 0 {
						t.Errorf("%s must have NO external dependencies, but imports %q.\n"+
							"Adding a dependency to the zero-dependency core is a design change; "+
							"see docs/AleutianChain/aleutian_chain_oss_core_design.md §3.1.", pkg, d)
						continue
					}
					t.Errorf("%s imports %q, which is not in its allowlist %v.", pkg, d, allowed)
				}
			}
		})
	}
}

// TestNoCloudDependenciesAnywhere asserts no package in the module reaches a
// cloud SDK, regardless of the per-package allowlists above.
func TestNoCloudDependenciesAnywhere(t *testing.T) {
	deps, err := externalDeps(modulePath + "/...")
	if err != nil {
		t.Fatalf("resolve module deps: %v", err)
	}
	for _, d := range deps {
		for _, bad := range forbiddenEverywhere {
			if strings.HasPrefix(d, bad) {
				t.Errorf("forbidden cloud dependency %q reached from this module; "+
					"offline verifiability is the premise of the project", d)
			}
		}
	}
}

// externalDeps returns the non-stdlib, non-own-module packages that pattern
// transitively depends on.
//
// # Description
//
// Shells out to `go list -deps` rather than importing golang.org/x/tools, which
// would mean adding a module dependency in order to test that there are none.
//
// # Outputs
//
//   - []string: sorted-unique external package paths; empty if fully self-contained
//   - error: if `go list` fails
func externalDeps(pattern string) ([]string, error) {
	out, err := exec.Command("go", "list", "-deps", pattern).Output()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ext []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || isStdlib(p) || strings.HasPrefix(p, modulePath) {
			continue
		}
		if !seen[p] {
			seen[p] = true
			ext = append(ext, p)
		}
	}
	return ext, nil
}

// isStdlib reports whether p is a standard library package.
//
// The standard library is exactly the set of import paths whose first element
// contains no dot — every external module path begins with a hostname.
func isStdlib(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	return !strings.Contains(first, ".")
}

// isAllowed reports whether dep falls under one of the allowed module prefixes.
func isAllowed(dep string, allowed []string) bool {
	for _, a := range allowed {
		if dep == a || strings.HasPrefix(dep, a+"/") {
			return true
		}
	}
	return false
}
