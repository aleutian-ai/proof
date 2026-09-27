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
// in order to check the work — and nothing operational. The subpackages are:
//
//   - [chainformat], [canonical]:     hash linkage and deterministic encoding
//   - [commitment]:                   salted commitments for unencrypted content
//   - [linker]:                       commit entries to a chain
//   - [anchor], [anchor/build]:       sign and check chain checkpoints (ML-DSA-65)
//   - [verify]:                       the verdicts
//   - [merkle], [bundle]:             inclusion proofs and export bundles
//   - [store]:                        the persistence port and its adapters
//   - [keyfile], [mldsa]:             standard key files; ML-DSA signatures
//   - [xwing], [mlkem], [keywrap]:    post-quantum KEM primitives and the
//     platform's wrapped-key format. The chain does not use them.
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
