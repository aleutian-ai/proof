// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package exportbundle verifies a sink export bundle,
// aleutian.proof.bundle.v1, as docs/bundle-format.md (revision 3.2) defines it.
//
// A bundle is one JSON file holding whole sink chains, their checkpoints, and
// whatever content the exporter chose to disclose. Verify reads it with a
// strict reader (bundle-format §3: exact member names, no duplicate names, no
// lone surrogates, depth 8), runs the checks of §7 and §8, and returns the
// structured result of §9, which every implementation must produce
// identically.
//
// This is the reference implementation: it ships with the program that writes
// bundles, so its agreement with a bundle is the writer agreeing with itself.
// The Python and JavaScript verifiers are the independent ones.
//
// The package does not import package sink, and so does not compile in the
// bbolt database: a recipient verifying a bundle needs the standard library,
// ML-DSA-65 and the format's hash functions, nothing else. It shares no logic
// with folder verification (sink.Verify); bundle-format §14 lists where the two
// differ on purpose.
//
// Trust is the caller's (§6): the two key sets are given to Verify, and a
// bundle never adds a key.
package exportbundle
