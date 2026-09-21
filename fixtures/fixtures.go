// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package fixtures serves the cross-language golden vectors as embedded bytes.
//
// # Description
//
// The golden vectors are the byte contract that every Aleutian verifier — Go,
// Python, JavaScript — must reproduce exactly. A fixture is not test data; it is
// the specification in executable form. If two implementations disagree about a
// single byte, one of them reports tamper on a chain that was never tampered with.
//
// This package makes that contract reachable two ways from ONE file on disk:
//
//   - Go callers get bytes through the module system, via the accessors below.
//     Nothing to locate, nothing to open, no path to get wrong.
//   - Non-Go callers read the file directly from fixtures/testdata/, exactly as
//     they read a shared directory today.
//
// # Why embedding rather than a path lookup
//
// A Go consumer could instead ask the toolchain where this module lives
// (`go list -m -f '{{.Dir}}'`) and open the file. That works, but it makes a
// fixture change a silent file edit. Embedding makes it a version bump visible
// in the consumer's go.mod — a reviewable event rather than an invisible one.
// A silently-edited fixture copy is the exact failure this package exists to
// prevent.
//
// # Adding a fixture
//
//  1. Put the .json in fixtures/testdata/.
//  2. Add a //go:embed line and an accessor below.
//
// Keep exactly one copy of any given fixture in this repository. A second copy
// inside the module that exists to eliminate duplication would defeat the point.
//
// # Assumptions
//
//   - Returned slices are NOT copied; they alias the embedded data. Callers must
//     treat them as read-only. Mutating one corrupts the contract for every other
//     caller in the process.
package fixtures

import _ "embed"

// merkleGolden is the Merkle tree golden vector: leaf sets paired with their
// expected roots, inclusion proofs, and consistency proofs.
//
//go:embed testdata/merkle_golden.json
var merkleGolden []byte

// chainVectors is the chain-hash golden vector: linkage inputs paired with the
// expected chain hash, including a tombstone case.
//
//go:embed testdata/chain_vectors.json
var chainVectors []byte

// ChainVectors returns the chain-hash golden vectors as raw JSON.
//
// # Description
//
// The canonical fixture for chain linkage. Each vector carries previous_hash,
// run_id, sequence_num, timestamp and content_hash alongside the expected
// chain hash, so any implementation can check itself against the same inputs.
//
// # Provenance
//
// These vectors were NOT generated from this module. They were taken from the
// JavaScript verifier and independently confirmed against the Go producer, so
// they represent agreement between two implementations rather than a module
// agreeing with itself. Regenerating them from this code would destroy that
// property — a self-derived vector proves only that the encoder is
// deterministic.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func ChainVectors() []byte { return chainVectors }

// captureRequestV3Golden is the capture.request.v3 golden vector: entry inputs
// paired with their expected canonical bytes and content hash.
//
//go:embed testdata/v3_golden_capture_request.json
var captureRequestV3Golden []byte

// CaptureRequestV3Golden returns the capture.request.v3 golden vector as raw JSON.
//
// # Description
//
// The canonical fixture for [github.com/aleutian-ai/proof/chainformat]. This is
// the highest-traffic entry type on the platform, and the vector every verifier
// — Go, Python, JavaScript — must reproduce byte-for-byte.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func CaptureRequestV3Golden() []byte { return captureRequestV3Golden }

// MerkleGolden returns the Merkle golden vector as raw JSON.
//
// # Description
//
// The canonical fixture for [github.com/aleutian-ai/proof/merkle]. Distributed
// to non-Go verifiers as fixtures/testdata/merkle_golden.json — the same bytes.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
//
// # Example
//
//	var golden struct{ Cases []merkleCase }
//	if err := json.Unmarshal(fixtures.MerkleGolden(), &golden); err != nil {
//	    t.Fatalf("decode merkle golden: %v", err)
//	}
func MerkleGolden() []byte { return merkleGolden }
