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
// These vectors are NOT generated from this module. scripts/spec-vectors.py
// computes every expected hash in Python from docs/format-spec.md §2.3, so
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
// # Provenance
//
// Written by scripts/spec-vectors.py, which encodes each input and hashes it in
// Python from docs/format-spec.md §6. The Go encoder reads this file; it does
// not write it.
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
// # Provenance
//
// Written by scripts/spec-vectors.py, which computes the roots and proofs in
// Python from RFC 9162 and docs/format-spec.md §7. The merkle package reads
// this file; it does not write it.
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

// commitmentVectors is the salted-commitment golden vector: nonce and content
// paired with the expected commitment, plus cases every implementation must
// reject. Expected values are computed with Python's hashlib by
// scripts/spec-vectors.py, independently of the Go implementation they test.
// In the wrong-length-nonce reject cases the stored commitment is what the
// formula gives without a length check, so only a refusal passes them.
//
//go:embed testdata/commitment_vectors.json
var commitmentVectors []byte

// CommitmentVectors returns the salted-commitment golden vectors as raw JSON.
//
// # Description
//
// The canonical fixture for [github.com/aleutian-ai/proof/commitment].
// Distributed to non-Go implementations as
// fixtures/testdata/commitment_vectors.json — the same bytes.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
//
// # Example
//
//	type vector struct {
//	    NonceHex   string `json:"nonce_hex"`
//	    ContentHex string `json:"content_hex"`
//	    Commitment string `json:"commitment"`
//	}
//	var v struct {
//	    Vectors []vector `json:"vectors"` // must reproduce exactly
//	    Reject  []vector `json:"reject"`  // must all fail verification
//	}
//	if err := json.Unmarshal(fixtures.CommitmentVectors(), &v); err != nil {
//	    t.Fatalf("decode commitment vectors: %v", err)
//	}
func CommitmentVectors() []byte { return commitmentVectors }

// chainV3Vectors, anchorV6Vectors and keyIDVectors were computed independently
// in Python by scripts/independent-vectors.py, from docs/format-spec.md alone.
//
//go:embed testdata/chain_v3_vectors.json
var chainV3Vectors []byte

//go:embed testdata/anchor_v6_canonical_vectors.json
var anchorV6Vectors []byte

//go:embed testdata/keyid_vectors.json
var keyIDVectors []byte

// ChainV3Vectors returns the chain hash v3 vectors as raw JSON: cases that must
// reproduce, and cases that must be refused. global_seq is a decimal STRING.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func ChainV3Vectors() []byte { return chainV3Vectors }

// AnchorV6Vectors returns the anchor v6 canonical-form vectors as raw JSON.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func AnchorV6Vectors() []byte { return anchorV6Vectors }

// KeyIDVectors returns the key-id vectors as raw JSON.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func KeyIDVectors() []byte { return keyIDVectors }

// recordV1Vectors holds the sink record-signing envelope vectors.
//
//go:embed testdata/record_v1_vectors.json
var recordV1Vectors []byte

// RecordV1Vectors returns the sink record-signing envelope vectors as raw JSON.
//
// # Description
//
// Each vector pairs the seven signed fields of an aleutian.proof.record.v1
// envelope with the exact envelope bytes (hex) and their SHA-512. An
// implementation builds the envelope from the fields and must produce those
// bytes exactly: they are what an ML-DSA-65 record signature covers.
//
// # Provenance
//
// Computed independently in Python by scripts/independent-vectors.py, from
// docs/sink-format.md alone, not by the Go encoder they test.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
//
// # Example
//
//	var f struct{ Vectors []struct{ EnvelopeHex string `json:"envelope_hex"` } }
//	err := json.Unmarshal(fixtures.RecordV1Vectors(), &f)
//
// # Limitations
//
//   - Envelope bytes only. ML-DSA-65 signatures over them are covered by the
//     mldsa package's ACVP vectors, not here.
//
// # Assumptions
//
//   - None.
func RecordV1Vectors() []byte { return recordV1Vectors }

// bundleV1Vectors holds the sink export bundle conformance vectors.
//
//go:embed testdata/bundle_v1_vectors.json
var bundleV1Vectors []byte

// BundleV1Vectors returns the bundle conformance vectors as raw JSON.
//
// # Description
//
// Each case is a whole bundle (base64), the trust a verifier is given, and the
// exact result of docs/bundle-format.md §9 it must produce. Fixed key seeds
// make every signature deterministic.
//
// # Provenance
//
// Built in Python by scripts/bundle-vectors.py from docs/bundle-format.md:
// each case is a valid bundle with one stated defect, its result declared from
// that construction. One case is a real `proof sink export`
// (scripts/bundlefixture). Not produced by any verifier.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
//
// # Example
//
//	var f struct{ Cases []struct{ Name string `json:"name"` } `json:"cases"` }
//	err := json.Unmarshal(fixtures.BundleV1Vectors(), &f)
//
// # Limitations
//
//   - No `too-large` case: the limits are impractical in a vector file.
//
// # Assumptions
//
//   - None.
func BundleV1Vectors() []byte { return bundleV1Vectors }

// verifyVerdictVectors was written by scripts/verdict-vectors.py from
// docs/format-spec.md alone (§4, §5.5, §9.4, §9.8).
//
//go:embed testdata/verify_verdict_vectors.json
var verifyVerdictVectors []byte

// VerifyVerdictVectors returns the verifier verdict vectors as raw JSON: what a
// verifier concludes about whole chains, entries files, anchor text and keyless
// binds, where the other vectors pin single hashes.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func VerifyVerdictVectors() []byte { return verifyVerdictVectors }

// chainV4Vectors, anchorV7Vectors and verifyVerdictV4Vectors were written by
// scripts/v4-vectors.py and scripts/verdict-vectors.py from docs/format-spec.md
// alone (§2.0, §2.5, §5.0, §9).
//
//go:embed testdata/chain_v4_vectors.json
var chainV4Vectors []byte

//go:embed testdata/anchor_v7_canonical_vectors.json
var anchorV7Vectors []byte

//go:embed testdata/verify_verdict_v4_vectors.json
var verifyVerdictV4Vectors []byte

// ChainV4Vectors returns the chain format v4 vectors as raw JSON: leaf hashes
// and chain hashes, erased entries, a chain continued from v3, and inputs that
// must be refused.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func ChainV4Vectors() []byte { return chainV4Vectors }

// AnchorV7Vectors returns the anchor v7 vectors as raw JSON: canonical bytes,
// anchor chain hashes, signatures made with the v7 context, and anchor texts
// that must be refused.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func AnchorV7Vectors() []byte { return anchorV7Vectors }

// VerifyVerdictV4Vectors returns the verdict vectors for v4 chains, chains
// continued from v3, and keyless binds of v7 anchors.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func VerifyVerdictV4Vectors() []byte { return verifyVerdictV4Vectors }

// bundleV2Vectors and recordV2Vectors were written by scripts/bundle-vectors.py
// and scripts/v4-vectors.py from docs/bundle-format.md §16 and
// docs/sink-format.md §9.1 alone.
//
//go:embed testdata/bundle_v2_vectors.json
var bundleV2Vectors []byte

//go:embed testdata/record_v2_vectors.json
var recordV2Vectors []byte

// BundleV2Vectors returns the aleutian.proof.bundle.v2 conformance cases, in
// the shape of BundleV1Vectors.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func BundleV2Vectors() []byte { return bundleV2Vectors }

// RecordV2Vectors returns the aleutian.proof.record.v2 envelope vectors, in
// the shape of RecordV1Vectors, with signatures made with its context.
//
// # Outputs
//
//   - []byte: the fixture JSON. Read-only; see the package Assumptions.
func RecordV2Vectors() []byte { return recordV2Vectors }
