// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package chainformat defines leaf encoding and hash linkage.
//
// # Description
//
// This is the heart of the tamper-evidence claim. Each entry is canonicalized to
// a leaf, hashed under a domain-separated prefix, and linked by including its
// predecessor's chain hash in its own preimage. Verification recomputes the same
// values from stored data and compares.
//
//	entry n-1                     entry n                     entry n+1
//	┌──────────────┐              ┌──────────────┐            ┌──────────────┐
//	│ chain_hash ──┼── prev ────► │ chain_hash ──┼── prev ───►│ chain_hash   │
//	│ content_hash │              │ content_hash │            │ content_hash │
//	└──────────────┘              └──────────────┘            └──────────────┘
//
// # Two chain hash formats, and why zero means v2
//
// An entry records WHICH preimage produced its hash, because two formats cannot
// be told apart by looking at a digest — a verifier that guesses is a verifier
// that reports false breaks.
//
//	v3  SHA-512("aleutian.chain.v3:" ‖ prev|global_seq|ts|content)   ← default
//	v2  SHA-512("aleutian.chain.v2:" ‖ prev|run_id|sequence_num|ts|content)
//
// v2 bound run_id and a BATCH-LOCAL sequence_num, so the same entries in the
// same order hashed differently depending on how they were grouped into append
// calls. The batch boundaries were part of the artefact and recorded nowhere,
// which made a chain impossible to rebuild from its own entries. v3 binds
// global_seq — the entry's chain-wide position, which v2 never hashed at all —
// and is batch-independent.
//
// **FormatVersion zero means v2**, deliberately. Every entry written before v3
// existed has no version field, and an absent field decodes as zero; treating
// zero as "the format that was current when versions were not recorded" is what
// keeps those entries verifiable without rewriting them. See
// [NormalizeFormatVersion], and the module's docs/decisions.md D15.
//
// v2 is NOT deprecated and NOT rewritten. Existing v2 chains verify as v2
// forever.
//
// # What this proves, precisely
//
// Because each hash covers the one before it, altering an entry changes its
// hash, so the next entry's stored predecessor no longer matches and the
// mismatch cascades forward. The guarantee is therefore:
//
//	an entry cannot be changed by anyone who cannot ALSO rewrite
//	every entry that follows it.
//
// That is real and useful — an operator who quietly edits one row is caught —
// but it is conditional, and the condition matters.
//
// # What this does NOT prove
//
// Truncation is undetectable from the chain alone. Removing entries from the
// front is not an edit-with-the-rest-intact; it is presenting a valid suffix as
// though it were the whole. An attacker who deletes entries 0..k, clears entry
// k+1's previous hash, and recomputes the remainder produces a chain that
// verifies perfectly:
//
//	ORIGINAL   [0]→[1]→[2]→[3]→[4]→[5]
//	PRESENTED            [3]→[4]→[5]      internally flawless
//
// Nothing inside a chain records how long it should be or where it began; the
// first entry is simply the one whose previous hash is empty. Closing this
// requires something OUTSIDE the chain — an anchor, a signed statement that at a
// given time the chain's head was H over a stated entry range. A verifier
// holding an anchor can reject a chain that no longer contains it.
//
//	chain hash alone    → "nothing was edited under me"    (consistency)
//	chain hash + anchor → "…and this is the same chain"    (existence)
//
// Callers reporting results MUST keep those two apart. Reporting a locally
// verified chain as simply "verified" invites a reader to believe the second
// claim, which this package cannot support.
//
// # Tombstones must be special-cased
//
// When an entry's content is erased the entry stays in position and its content
// hash is replaced by a random tombstone value, so the linkage survives and a
// lawful erasure stays distinguishable from a row that merely vanished.
//
// Crucially the tombstone RETAINS the original entry's chain hash, which was
// computed from the real content hash. A tombstone's chain hash is therefore not
// reproducible from its own fields, and a verifier that recomputes it will
// report a false break on every erased entry.
//
// That is deliberate, and the reason is worth stating: anchors sign the chain
// hash. Recomputing it on erasure would invalidate every anchor covering that
// range — so exercising a right to erasure would destroy the proof that the data
// ever existed. Preserving the hash is what keeps erasure and provability
// compatible.
//
//	VERIFIERS MUST skip hash recomputation for tombstones and validate
//	format only. See ValidateTombstoneContentHash and IsTombstone.
//
// # Temporal authority
//
// The chain's sequence numbers and previous-hash pointers are the authoritative
// LOGICAL clock. Wall-clock timestamps are hash INPUT, never an ordering or
// validity decision.
//
// WHICH sequence the hash binds depends on the format, and the difference is the
// whole reason v3 exists: v3 binds global_seq, the chain-wide position. v2 binds
// sequence_num, the position within a run, and does not hash the global sequence
// at all — under v2 the chain-wide position is checked separately and is
// protected only by the previous-hash linkage.
//
// # The subject is free text
//
// A leaf's subject names whatever the chain is ABOUT — a hostname, a project, an
// opaque id. Any non-empty string that passes the shared field rules.
//
// It was called company_id until 2026-09-23 and had to match a private
// platform's tenant scheme, which meant an adopter had to mint one of someone
// else's identifiers to describe their own data. The JSON key "company_id" is
// still accepted on read. **No content hash changed in the rename**: the leaf
// canonical form encodes values positionally and never writes a key name.
//
// # Limitations
//
//   - Detects that a chain was altered; cannot identify who altered it.
//   - Proves internal consistency only, not existence at a time.
//   - The preimage is '|'-delimited and not self-delimiting; safety depends on
//     input validation. See [ComputeChainHash] and [ComputeChainHashV3].
//   - Neither format carries an algorithm identifier. SHA-512 is fixed.
//
// # Assumptions
//
//   - A timestamp that feeds a hash is stored in the exact form it was hashed
//     in. Re-deriving it from a lower-precision value silently breaks
//     verification for entries with sub-millisecond resolution.
package chainformat
