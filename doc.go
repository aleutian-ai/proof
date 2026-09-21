// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package proof implements Aleutian's verifiable audit chain.
//
// # Description
//
// An audit chain is an append-only sequence of entries in which each entry's
// hash covers its predecessor's hash. Any retroactive edit breaks every link
// after it, which makes tampering detectable without trusting the storage
// layer or the party that wrote it.
//
// This module contains the format and the math — the parts a third party needs
// in order to check the work — and nothing operational. The subpackages are:
//
//   - [xwing], [keywrap], [kdf]:      the hybrid post-quantum KEM that seals payloads
//   - [canonical], [chainformat]:     deterministic encoding and hash linkage
//   - [merkle], [anchor]:             inclusion proofs and signed chain anchors
//   - [store]:                        the persistence port and its adapters
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
