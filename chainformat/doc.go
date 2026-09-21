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
// validity decision. Note also that the hash binds sequenceNum — position within
// a run — and not the chain-wide global sequence, which is checked separately.
//
// # Limitations
//
//   - Detects that a chain was altered; cannot identify who altered it.
//   - Proves internal consistency only, not existence at a time.
//   - The preimage is '|'-delimited and not self-delimiting; safety depends on
//     input validation. See [ComputeChainHash].
//
// # Assumptions
//
//   - A timestamp that feeds a hash is stored in the exact form it was hashed
//     in. Re-deriving it from a lower-precision value silently breaks
//     verification for entries with sub-millisecond resolution.
package chainformat
