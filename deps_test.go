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
// depend on. A package present with an empty list must have NO external
// dependencies at all.
//
// Every package in the module MUST appear here — enforced by
// TestEveryPackageIsCoveredByTheAllowlist, because a package absent from this
// table is not checked at all rather than held to zero.
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
// docs/decisions.md (D1, D2). Adding a dependency
// to the zero-dependency core is a design change, not a build fix.
var allowedDeps = map[string][]string{
	// The root package: doc.go and nothing else outside its tests. Its tests are
	// the integration tests, and what THEY reach is in allowedTestOnlyDeps.
	"": {},

	// The crypto core. Everything here is stdlib-only, including the
	// post-quantum KEM: crypto/mlkem, crypto/sha3, and crypto/ecdh are all in
	// the standard library as of Go 1.24, which also places these packages
	// inside Go's native FIPS 140-3 module boundary.
	"/xwing": {},
	// keyfile is pure encoding — ASN.1, PEM, and the SHA3 used by the ML-KEM
	// consistency check. Reading an X-Wing key must never compile in an ML-DSA
	// implementation, which is why the algorithms live elsewhere.
	"/keyfile": {},
	// mldsa needs circl: ML-DSA is not in the Go standard library. Kept out of
	// xwing/keywrap/keyfile so importing the KEM or a key file never compiles in
	// a signature implementation.
	"/mldsa": {"github.com/cloudflare/circl", "golang.org/x/sys"},
	// mlkem is pure ML-KEM from crypto/mlkem — stdlib only, like xwing. The
	// CNSA 2.0 profile must not drag in a third-party implementation.
	"/mlkem":          {},
	"/keywrap":        {},
	"/merkle":         {},
	"/fixtures":       {},
	"/bundle":         {},
	"/internal/fault": {},
	"/internal/mem":   {},
	// The operating-system calls the stores need (flock, O_NOFOLLOW): stdlib.
	"/internal/osfile": {},

	// Unicode NFC validation requires the Unicode tables, which the standard
	// library does not ship. canonical rejects non-NFC strings fail-closed
	// (ErrNotNFC) because a producer sending unnormalized text is the classic
	// cause of cross-LANGUAGE canonicalization divergence: Go, Python, and JS
	// would each hash different bytes for the same logical string. Hand-rolling
	// a normalization quick-check over a security boundary would be strictly
	// worse than depending on the Go team's implementation.
	//
	// Precedent: the Go verification SDK already requires golang.org/x/text for the
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
	// A rule of "circl in /anchor and NOTHING ELSE" cannot hold literally once
	// verification is exposed through verify — the meaningful invariant is that
	// the FORMAT AND KEM PRIMITIVES stay clean, which the entries above enforce.
	// x/text arrives via chainformat → canonical.
	"/verify": {
		"github.com/cloudflare/circl",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// The append path. x/text arrives via chainformat → canonical (Unicode NFC).
	// Notably NOT bbolt: the linker talks to the store PORT, so a caller can
	// link entries without inheriting a storage engine.
	"/linker": {"golang.org/x/text"},

	// The persistence PORT is interfaces and two structs. It must stay clean, or
	// depending on the contract would mean depending on an implementation.
	"/store": {},

	// The in-memory adapter, used by tests and by callers who want no files.
	"/store/memory": {},

	// The conformance suite an adapter runs against itself. x/text via chainformat.
	"/store/storetest": {"golang.org/x/text"},

	// The CLI is the one place allowed to assemble everything: it verifies
	// (circl, x/text), opens a bbolt database, and generates keys. A library
	// consumer inherits none of this.
	"/cmd/proof": {
		"github.com/cloudflare/circl",
		"go.etcd.io/bbolt",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// The nonce sidecar for MCP commits: bbolt (and x/sys through it), nothing else.
	"/internal/noncestore": {"go.etcd.io/bbolt", "golang.org/x/sys"},
	// The pre-flight structural check run on a bbolt file before it is opened
	// for writing: bbolt (and x/sys through it), nothing else.
	"/internal/safebolt": {"go.etcd.io/bbolt", "golang.org/x/sys"},
	// A test-only tool the container check builds (-tags sinktamper) to tamper
	// with one stored event: bbolt (and x/sys through it), nothing else. Never
	// released; a build without the tag does not include it.
	"/scripts/sinktamper": {"go.etcd.io/bbolt", "golang.org/x/sys"},

	// Salted commitments. Standard library only, and it must stay that way: it
	// is the one piece a verifier in any language re-implements from the spec.
	"/commitment": {},

	// The export-bundle verifier (docs/bundle-format.md). What a RECIPIENT of a
	// bundle runs, so it must not inherit the sink's storage engine: no bbolt.
	// circl and x/sys arrive with ML-DSA-65 (mldsa, anchor); x/text arrives with
	// the chain hash (chainformat → canonical). It imports no package sink.
	"/exportbundle": {
		"github.com/cloudflare/circl",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// An EXAMPLE, not part of the library: it shows encryption (circl's HPKE with
	// X-Wing) composed with proof from the outside. proof itself encrypts nothing;
	// circl/hpke is reachable only from here, and it brings x/crypto (HKDF,
	// ChaCha20-Poly1305) with it. x/crypto was already in go.mod as circl's
	// indirect dependency; this entry keeps it confined to the example.
	"/examples/encrypted-artifact": {
		"github.com/cloudflare/circl",
		"go.etcd.io/bbolt",
		"golang.org/x/crypto",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// The sink: one chain per key, idempotent commits, checkpoints, verification
	// and erasure over a folder. It assembles the library (verify, anchor/build,
	// the bolt store, the nonce file) and adds no dependency of its own. The
	// integrations that feed it (NATS, Redis, …) are separate modules, so their
	// clients never enter this one.
	"/sink": {
		"github.com/cloudflare/circl",
		"go.etcd.io/bbolt",
		"golang.org/x/sys",
		"golang.org/x/text",
	},

	// The anchor producer. It imports anchor AND verify — that is what a
	// producer is — so it inherits the union of their dependencies and adds
	// none of its own. Listed explicitly so that a new dependency reaching it
	// still has to be justified here.
	"/anchor/build": {
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
	// v0.42.0 requires go 1.25.0, which would raise the floor for every consumer
	// including those who only want the KEM. Held at v0.41.0 (with x/crypto at
	// v0.48.0 and x/text at v0.34.0, the last releases that declare go 1.24) and
	// bbolt at v1.4.3 (rather than v1.5.0, which itself requires 1.25) to keep
	// the floor at 1.24. If those pins are ever bumped, expect the go directive
	// to move with them.
	"/store/bolt": {"go.etcd.io/bbolt", "golang.org/x/sys"},
}

// allowedTestOnlyDeps declares, per package, the external modules that only
// that package's TESTS may reach, on top of its allowedDeps entry.
//
// # Why a second table
//
// A consumer who imports a package compiles its non-test files only, so
// allowedDeps is the promise made to consumers and stays exactly as strict as
// it was. But a test file is still code in this repository that a reviewer
// reads and CI runs, and before this table existed `go list -deps` was run
// without -test: a test could import anything and nothing noticed.
//
// Every entry is a module already in go.mod for a non-test reason. A test may
// not bring a NEW module into the module graph; that would show up here as an
// import no entry allows.
//
// An entry that no test uses any more fails TestDependencyIsolation, so this
// table cannot keep permissions nobody needs.
var allowedTestOnlyDeps = map[string][]string{
	// The integration and lifecycle tests assemble the whole library: the bolt
	// store, anchors (circl, x/sys), the chain format (x/text). x/crypto comes
	// from xwing_differential_test.go, which checks this module's X-Wing against
	// circl's, and circl's reaches x/crypto/sha3.
	"": {
		"github.com/cloudflare/circl",
		"go.etcd.io/bbolt",
		"golang.org/x/crypto",
		"golang.org/x/sys",
		"golang.org/x/text",
	},
	// example_test.go commits a salted commitment through linker and checks it
	// with verify, which is what brings circl, x/sys and x/text.
	"/commitment": {"github.com/cloudflare/circl", "golang.org/x/sys", "golang.org/x/text"},
	// consistency_test.go checks key files against keys circl generates.
	"/keyfile": {"github.com/cloudflare/circl", "golang.org/x/sys"},
	// The linker's tests run it against the bolt store and verify the result.
	"/linker": {"github.com/cloudflare/circl", "go.etcd.io/bbolt", "golang.org/x/sys"},
	// Both adapters run the storetest conformance suite, which uses chainformat.
	"/store/bolt":   {"golang.org/x/text"},
	"/store/memory": {"golang.org/x/text"},
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

// TestDependencyIsolation enforces the per-package dependency rules above: the
// package's own files against allowedDeps, and its tests against that plus
// allowedTestOnlyDeps.
func TestDependencyIsolation(t *testing.T) {
	for suffix, allowed := range allowedDeps {
		pkg := modulePath + suffix
		t.Run(suffix, func(t *testing.T) {
			deps, err := externalDeps(pkg, false)
			if err != nil {
				t.Fatalf("resolve deps of %s: %v", pkg, err)
			}
			checkTestOnlyDeps(t, pkg, deps, allowed, allowedTestOnlyDeps[suffix])
			for _, d := range deps {
				if !isAllowed(d, allowed) {
					if len(allowed) == 0 {
						t.Errorf("%s must have NO external dependencies, but imports %q.\n"+
							"Adding a dependency to the zero-dependency core is a design change; "+
							"see docs/decisions.md (D1).", pkg, d)
						continue
					}
					t.Errorf("%s imports %q, which is not in its allowlist %v.", pkg, d, allowed)
				}
			}
		})
	}
}

// checkTestOnlyDeps holds a package's TESTS to its allowedDeps entry plus its
// allowedTestOnlyDeps entry, and fails on a test-only entry nothing uses.
func checkTestOnlyDeps(t *testing.T, pkg string, nonTest, allowed, testOnly []string) {
	t.Helper()
	withTests, err := externalDeps(pkg, true)
	if err != nil {
		t.Fatalf("resolve test deps of %s: %v", pkg, err)
	}
	inNonTest := map[string]bool{}
	for _, d := range nonTest {
		inNonTest[d] = true
	}
	used := map[string]bool{}
	for _, d := range withTests {
		if inNonTest[d] {
			continue // judged against allowedDeps by the caller
		}
		// A test may reach what the package itself may, without a second entry.
		if isAllowed(d, allowed) {
			continue
		}
		matched := false
		for _, a := range testOnly {
			if isAllowed(d, []string{a}) {
				used[a], matched = true, true
			}
		}
		if !matched {
			t.Errorf("the TESTS of %s import %q, which neither its allowedDeps entry %v nor its "+
				"allowedTestOnlyDeps entry %v allows.", pkg, d, allowed, testOnly)
		}
	}
	for _, a := range testOnly {
		if !used[a] {
			t.Errorf("allowedTestOnlyDeps lets the tests of %s reach %q, and none does. "+
				"Remove the entry: a permission nobody uses is one nobody reviews.", pkg, a)
		}
	}
}

// TestTestOnlyAllowlistNamesRealPackages: an entry for a package that is not
// in allowedDeps would never be read.
func TestTestOnlyAllowlistNamesRealPackages(t *testing.T) {
	for suffix := range allowedTestOnlyDeps {
		if _, ok := allowedDeps[suffix]; !ok {
			t.Errorf("allowedTestOnlyDeps has an entry for %q, which allowedDeps does not list", suffix)
		}
	}
}

// TestNoCloudDependenciesAnywhere asserts no package in the module reaches a
// cloud SDK, regardless of the per-package allowlists above. Tests included.
func TestNoCloudDependenciesAnywhere(t *testing.T) {
	deps, err := externalDeps(modulePath+"/...", true)
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
// transitively depends on. With tests set, the packages its test files import
// are included too (`go list -deps -test`).
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
func externalDeps(pattern string, tests bool) ([]string, error) {
	// -tags sinktamper: that test-only tool is behind a build tag, and must stay
	// guarded like everything else.
	args := []string{"list", "-tags", "sinktamper", "-deps"}
	if tests {
		args = append(args, "-test")
	}
	out, err := exec.Command("go", append(args, pattern)...).Output()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ext []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// With -test, a package rebuilt for a test binary is listed as
		// "path [path.test]"; the import path is the first field.
		p, _, _ := strings.Cut(strings.TrimSpace(line), " ")
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

// TestEveryPackageIsCoveredByTheAllowlist closes a hole in the guard above.
//
// # Why this exists
//
// TestDependencyIsolation iterates over allowedDeps, so it only ever checks
// packages that someone remembered to list. A NEW package is therefore not
// "allowed nothing" — it is not checked at all, and could import a cloud SDK
// without that test noticing. (TestNoCloudDependenciesAnywhere would still
// catch a cloud SDK specifically; nothing would catch anything else.)
//
// Found on 2026-09-24 while adding anchor/build, which was silently unguarded.
//
// A guard whose coverage depends on remembering to extend it is a guard that
// decays. This makes forgetting fail.
func TestEveryPackageIsCoveredByTheAllowlist(t *testing.T) {
	out, err := exec.Command("go", "list", "-tags", "sinktamper", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		// The root package is not skipped: it holds doc.go and the integration
		// tests, and its entry is the empty suffix.
		suffix := strings.TrimPrefix(pkg, modulePath)
		if _, ok := allowedDeps[suffix]; !ok {
			t.Errorf("package %s has no entry in allowedDeps, so TestDependencyIsolation "+
				"never checks it. Add one — an empty list means \"no external "+
				"dependencies\", which is the right answer for most packages here.", pkg)
		}
	}
}
