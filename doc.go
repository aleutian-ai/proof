// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package proof is an open protocol and toolkit for creating independently
// verifiable histories of digital evidence.
//
// # Description
//
// Evidence is committed to a chain: an append-only sequence in which each
// entry's hash covers its predecessor's. Any retroactive edit breaks every link
// after it, which makes tampering detectable without trusting the storage layer
// or the party that wrote it. Signed anchors checkpoint the chain.
//
// proof is the integrity layer, not the confidentiality layer. It commits a
// fingerprint of the evidence, never the evidence itself, and it neither
// encrypts nor stores content. Encryption is composed from outside; see
// examples/encrypted-artifact.
//
// This module contains the format and the math — the parts a third party needs
// in order to check the work — and the tools that produce it: a linker, a bbolt
// store, the sink, and the proof CLI. The subpackages are:
//
//   - [chainformat], [canonical]:     chain formats v4 (current), v3 and v2
//     (frozen), and deterministic encoding
//   - [commitment]:                   salted commitments for unencrypted content
//   - [linker]:                       commit entries to a chain
//   - [anchor], [anchor/build]:       sign and check chain checkpoints (ML-DSA-65)
//   - [verify]:                       the verdicts
//   - [merkle]:                       Merkle roots and inclusion proofs
//   - [bundle]:                       directory bundles with a manifest root
//   - [sink], [exportbundle]:         per-subject evidence folders; verifying
//     a sink export bundle
//   - [fixtures]:                     the cross-language conformance vectors
//   - [store]:                        the persistence port and its adapters
//   - [keyfile], [mldsa]:             standard key files; ML-DSA signatures
//   - [xwing], [mlkem], [keywrap]:    post-quantum KEM primitives and the
//     platform's wrapped-key format. The chain does not use them.
//
// # What is public
//
// The compatibility promise covers the packages above and their exported
// identifiers, the error values and the codes a result reports
// ([verify.BreakType], [verify.BindOutcome], the [exportbundle] problem codes),
// the formats in docs/, the proof CLI's verbs, flags and exit codes, and the
// proof-mcp tools' names and argument schemas. Tests pin the codes, the exit
// codes and the MCP tool list. Not covered: everything under internal/,
// store/storetest (a test suite for adapter authors, which may grow), and
// examples/. While the major version is 0 a minor release may still break the
// promise, and the changelog says how.
//
// # Platforms
//
// Linux and macOS. The stores need flock and O_NOFOLLOW; on other platforms
// the operations that open a store return an error saying so, and verifying an
// exported file works anywhere.
//
// # Scope of the guarantee
//
// A chain built entirely with this module proves INTERNAL CONSISTENCY: no entry
// was altered after the fact without breaking the hash linkage. It does NOT
// prove EXISTENCE AT A TIME — that requires an anchor signed by a third party
// the verifier already trusts. A locally anchored chain is self-attested, and
// verification results say so explicitly rather than leaving the distinction
// to the reader.
//
// # Assumptions
//
//   - Callers persist entries in the order this package assigns them.
//   - Timestamps used as hash input are stored verbatim, never re-derived
//     from a lower-precision representation.
package proof
