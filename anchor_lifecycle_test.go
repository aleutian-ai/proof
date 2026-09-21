// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/verify"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Anchors, end to end.
//
// The per-entry chain hash proves nothing was EDITED. It cannot prove the chain
// is COMPLETE — TestLifecycle_TruncationIsNOTDetected demonstrates that a
// front-truncated, re-linked chain walks clean.
//
// These tests are the other half: the same truncation, now caught, because an
// anchor commits to WHERE the range started and WHAT the head was.

const (
	anchorTestCompanyID = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"
	anchorTestRunID     = "run_550e8400-e29b-41d4-a716-446655440000"
)

// anchoredEntry is a chain entry with the identity fields an anchor commits to.
type anchoredEntry struct {
	EntryID     string
	RunID       string
	SequenceNum int64
	Timestamp   time.Time
	ContentHash string
	ChainHash   string
}

// buildAnchoredChain links n entries with producer-shaped UUID entry ids.
func buildAnchoredChain(t *testing.T, n int) []anchoredEntry {
	t.Helper()

	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	out := make([]anchoredEntry, 0, n)
	previousHash := ""

	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)

		chainHash, err := chainformat.ComputeChainHash(previousHash, anchorTestRunID, int64(i), ts, contentHash)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		out = append(out, anchoredEntry{
			// Producer shape: a bare UUID v7, not a prefixed label.
			EntryID:     "0192f3a1-0000-7000-8000-" + hex.EncodeToString([]byte{0, 0, 0, 0, 0, byte(i)}),
			RunID:       anchorTestRunID,
			SequenceNum: int64(i),
			Timestamp:   ts,
			ContentHash: contentHash,
			ChainHash:   chainHash,
		})
		previousHash = chainHash
	}
	return out
}

// walkAndReturnHead re-derives every chain hash and returns the head, or the
// index of the first break.
//
// A TOMBSTONE MUST NOT BE RECOMPUTED. Its content hash is 32 random bytes, so
// nothing can derive it, and its chain hash is deliberately the ORIGINAL — the
// value anchors were signed over. A walker that recomputes tombstones reports a
// lawfully erased chain as tampered.
//
// This is not a hypothetical: the first draft of this helper omitted the skip
// and failed TestAnchor_ErasureDoesNotBreakTheAnchor, reproducing by hand the
// exact bug that shipped in three published SDKs. Any independent implementation
// of this walk needs the rule stated to it — see docs/format-spec.md §5.
func walkAndReturnHead(t *testing.T, entries []anchoredEntry) (head string, firstBreak int) {
	t.Helper()

	previousHash := ""
	for i, e := range entries {
		if chainformat.IsTombstoneContentHash(e.ContentHash) {
			previousHash = e.ChainHash // erasure is not tampering
			continue
		}
		want := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, e.Timestamp, e.ContentHash)
		if want != e.ChainHash {
			return "", i
		}
		previousHash = want
	}
	return previousHash, -1
}

// anchorOver builds an anchor committing to a chain's full range.
func anchorOver(t *testing.T, entries []anchoredEntry, previousAnchorHash string) anchor.Anchor {
	t.Helper()

	head, brk := walkAndReturnHead(t, entries)
	if brk != -1 {
		t.Fatalf("refusing to anchor a chain that breaks at %d", brk)
	}
	first, last := entries[0], entries[len(entries)-1]

	// Producer-side: strict validation before minting.
	if err := anchor.ValidateChainHashInputs(
		previousAnchorHash, anchorTestCompanyID, first.EntryID, last.EntryID, head); err != nil {
		t.Fatalf("producer guard rejected well-formed inputs: %v", err)
	}
	chainHash, err := anchor.ChainHash(
		previousAnchorHash, anchorTestCompanyID, first.EntryID, last.EntryID, head)
	if err != nil {
		t.Fatalf("anchor chain hash: %v", err)
	}

	return anchor.Anchor{
		Version:          3,
		AnchorID:         "anchor_01234567-8901-2345-6789-012345678901",
		CompanyID:        anchorTestCompanyID,
		ChainHash:        chainHash,
		Range:            anchor.EntryRange{StartEntryID: first.EntryID, EndEntryID: last.EntryID},
		EntryCount:       int64(len(entries)),
		SigningKeyID:     "aleutian-ml-dsa-65-2026-v1",
		CreatedAtMs:      time.Date(2026, 1, 20, 13, 0, 0, 0, time.UTC).UnixMilli(),
		PreviousAnchorID: anchor.SeedAnchorID,
	}
}

// bindAnchor calls the SHIPPED binder, verify.BindAnchor.
//
// This used to be a local reimplementation, which meant the repository's most
// important integration tests validated a verifier that was not part of the
// library. aleutianchain_08 exported the real one; this adapter exists only to
// convert the test's entry shape.
func bindAnchor(t *testing.T, a anchor.Anchor, entries []anchoredEntry) error {
	t.Helper()

	rows := make([]verify.Entry, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, verify.Entry{
			EntryID:     e.EntryID,
			EntryType:   "request",
			Timestamp:   e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			RunID:       e.RunID,
			SequenceNum: e.SequenceNum,
			GlobalSeq:   e.SequenceNum,
			ContentHash: e.ContentHash,
			ChainHash:   e.ChainHash,
		})
	}
	res, err := verify.BindAnchor(a, rows)
	if err != nil {
		return err
	}
	if !res.Bound {
		return fmt.Errorf("%s: %s", res.Outcome, res.Detail)
	}
	return nil
}

// =============================================================================

// TestAnchor_TruncationIsDetected is the counterpart to
// TestLifecycle_TruncationIsNOTDetected, and the reason anchors exist.
//
// Same attack, same re-linking, same clean linkage walk — but the anchor
// committed to where the range STARTED, so the truncated chain no longer
// describes what was signed.
func TestAnchor_TruncationIsDetected(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	if err := bindAnchor(t, a, full); err != nil {
		t.Fatalf("the untouched chain must bind to its own anchor: %v", err)
	}

	// The attack: discard entries 0-1, re-link the rest as though it were whole.
	truncated := append([]anchoredEntry(nil), full[2:]...)
	previousHash := ""
	for i := range truncated {
		truncated[i].SequenceNum = int64(i)
		truncated[i].ChainHash = chainformat.ComputeChainHashUnchecked(
			previousHash, truncated[i].RunID, int64(i),
			truncated[i].Timestamp, truncated[i].ContentHash)
		previousHash = truncated[i].ChainHash
	}

	// Linkage alone still sees nothing wrong — that is the whole problem.
	if _, brk := walkAndReturnHead(t, truncated); brk != -1 {
		t.Fatalf("the truncated chain should walk CLEAN (that is the premise); broke at %d", brk)
	}

	// The anchor catches it — and specifically via the RANGE START, not merely
	// because the height happens to differ too. Asserting only "it failed" let a
	// mutation that deleted the range-start check survive: truncation also trips
	// the height check, so the test passed while the guard it names was gone.
	rows := toVerifyEntries(truncated)
	res, err := verify.BindAnchor(a, rows)
	if err != nil {
		t.Fatalf("BindAnchor: %v", err)
	}
	if res.Bound {
		t.Fatal("truncation survived anchor binding — the anchor proves nothing")
	}
	if res.Outcome != verify.BindRangeStartMismatch {
		t.Fatalf("truncation must be reported as %q (the anchor's committed start is gone), got %q: %s",
			verify.BindRangeStartMismatch, res.Outcome, res.Detail)
	}
	t.Logf("truncation detected: %s: %s", res.Outcome, res.Detail)
}

// TestAnchor_ErasureDoesNotBreakTheAnchor is the cross-feature case.
//
// A tombstone retains the original chain_hash (D6), so a lawful erasure inside
// an anchored range must leave the anchor intact. If it did not, exercising a
// right to erasure would destroy the proof that the data ever existed — the
// exact bug that shipped in three SDKs.
func TestAnchor_ErasureDoesNotBreakTheAnchor(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	// Erase entry 2 the producer's way: content replaced, chain hash PRESERVED.
	tombstoneHash, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("generate tombstone: %v", err)
	}
	erased := append([]anchoredEntry(nil), full...)
	erased[2].ContentHash = tombstoneHash
	// ChainHash deliberately NOT recomputed.

	// The entry-level walk cannot re-derive a tombstone, so a verifier must skip
	// recomputation for it and carry the stored hash forward. Model that here.
	previousHash := ""
	for i, e := range erased {
		if chainformat.IsTombstoneContentHash(e.ContentHash) {
			previousHash = e.ChainHash
			continue
		}
		want := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, e.Timestamp, e.ContentHash)
		if want != e.ChainHash {
			t.Fatalf("erasure broke linkage at entry %d — a tombstone is not tampering", i)
		}
		previousHash = want
	}

	// And the head the anchor committed to is unchanged.
	if previousHash != erased[len(erased)-1].ChainHash {
		t.Fatal("the chain head moved after erasure; every anchor over it would be invalidated")
	}
	if err := bindAnchor(t, a, erased); err != nil {
		t.Fatalf("a lawful erasure invalidated the anchor: %v", err)
	}
}

// TestAnchor_ChainOfAnchorsLinks exercises the anchor-of-anchors chain: a second
// anchor commits to the first, so anchors cannot be reordered or dropped
// silently either.
func TestAnchor_ChainOfAnchorsLinks(t *testing.T) {
	t.Parallel()

	first := buildAnchoredChain(t, 3)
	a1 := anchorOver(t, first, anchor.SeedAnchorHash)

	// A second anchor over a longer chain, chained to the first.
	second := buildAnchoredChain(t, 6)
	head, brk := walkAndReturnHead(t, second)
	if brk != -1 {
		t.Fatalf("chain broke at %d", brk)
	}
	a2Hash, err := anchor.ChainHash(
		a1.ChainHash, anchorTestCompanyID,
		second[0].EntryID, second[len(second)-1].EntryID, head)
	if err != nil {
		t.Fatalf("second anchor hash: %v", err)
	}

	// Recomputing a2 with the SEED instead of a1 must not reproduce it —
	// otherwise the anchor chain carries no history and a1 could be dropped.
	spoofed, err := anchor.ChainHash(
		anchor.SeedAnchorHash, anchorTestCompanyID,
		second[0].EntryID, second[len(second)-1].EntryID, head)
	if err != nil {
		t.Fatalf("spoofed hash: %v", err)
	}
	if spoofed == a2Hash {
		t.Fatal("the second anchor does not actually commit to the first")
	}
}

// TestAnchor_CanonicalBytesAreSignable is the handoff to _08.
//
// Signing happens in aleutianchain_08; what _07 must guarantee is that the bytes
// exist, are stable, exclude the signature, and carry every field a verifier
// needs to reconstruct the binding.
func TestAnchor_CanonicalBytesAreSignable(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 4)
	a := anchorOver(t, full, anchor.SeedAnchorHash)
	a.Signature = "NOT_YET_SIGNED"

	canonical, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if strings.Contains(string(canonical), "NOT_YET_SIGNED") {
		t.Error("canonical bytes must exclude the signature")
	}
	for _, field := range []string{
		a.ChainHash, a.Range.StartEntryID, a.Range.EndEntryID, a.CompanyID, a.SigningKeyID,
	} {
		if !strings.Contains(string(canonical), field) {
			t.Errorf("canonical bytes omit a field the binding depends on: %q", field)
		}
	}
}

// TestAnchor_CannotBeReplayedAcrossTenants pins that company_id is load-bearing
// in the binding, not decoration.
//
// An anchor commits to its tenant. Without that, an anchor legitimately signed
// for tenant A could be presented as evidence about tenant B's chain — the
// operator would hold one valid anchor and could vouch for anyone.
func TestAnchor_CannotBeReplayedAcrossTenants(t *testing.T) {
	t.Parallel()

	tenantA := buildAnchoredChain(t, 4)
	anchorA := anchorOver(t, tenantA, anchor.SeedAnchorHash)

	// Tenant B's chain: same length and timestamps, DIFFERENT entry ids.
	tenantB := buildAnchoredChain(t, 4)
	for i := range tenantB {
		tenantB[i].EntryID = "0192f3a1-1111-7000-8000-" +
			hex.EncodeToString([]byte{0, 0, 0, 0, 0, byte(i)})
	}

	if err := bindAnchor(t, anchorA, tenantB); err == nil {
		t.Fatal("tenant A's anchor bound to tenant B's chain — anchors are replayable")
	}

	// And the hash itself must differ purely on company_id, holding all else equal.
	head, brk := walkAndReturnHead(t, tenantA)
	if brk != -1 {
		t.Fatalf("chain broke at %d", brk)
	}
	asA, err := anchor.ChainHash(anchor.SeedAnchorHash, "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		tenantA[0].EntryID, tenantA[len(tenantA)-1].EntryID, head)
	if err != nil {
		t.Fatal(err)
	}
	asB, err := anchor.ChainHash(anchor.SeedAnchorHash, "comp_01HZX9K2M3N4P5Q6R7S8T9V0WB",
		tenantA[0].EntryID, tenantA[len(tenantA)-1].EntryID, head)
	if err != nil {
		t.Fatal(err)
	}
	if asA == asB {
		t.Fatal("the anchor chain hash does not commit to company_id")
	}
}

// =============================================================================
// Adversarial: manipulations that leave the chain superficially plausible
// =============================================================================

// TestAnchor_ReorderingIsDetected covers swapping two entries in place.
//
// Distinct from tampering: no content changes, only position. A verifier that
// checked hashes without checking the ORDER they were derived in would pass this.
func TestAnchor_ReorderingIsDetected(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	reordered := append([]anchoredEntry(nil), full...)
	reordered[1], reordered[3] = reordered[3], reordered[1]

	if _, brk := walkAndReturnHead(t, reordered); brk == -1 {
		t.Fatal("reordering left the chain walking clean")
	}
	if err := bindAnchor(t, a, reordered); err == nil {
		t.Fatal("reordering survived anchor binding")
	}
}

// TestAnchor_SequenceGapIsDetected covers dropping an entry from the middle.
func TestAnchor_SequenceGapIsDetected(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	// Remove entry 2, leaving 0,1,3,4 — the range bounds are UNCHANGED, so this
	// specifically probes whether anything beyond the bounds is checked.
	gapped := append([]anchoredEntry(nil), full[:2]...)
	gapped = append(gapped, full[3:]...)

	if err := bindAnchor(t, a, gapped); err == nil {
		t.Fatal("a chain missing a middle entry bound successfully to its anchor")
	}
}

// TestAnchor_EntryCountMismatchIsDetected covers an anchor whose committed
// height disagrees with the chain it is presented with, while the range bounds
// still match.
func TestAnchor_EntryCountMismatchIsDetected(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)
	a.EntryCount = 99 // the range still names the right first and last entries

	if err := bindAnchor(t, a, full); err == nil {
		t.Fatal("entry count is not checked; an anchor can claim any height")
	}
}

// TestAnchor_DuplicateSequenceIsDetected covers a replayed entry.
func TestAnchor_DuplicateSequenceIsDetected(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 5)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	duped := append([]anchoredEntry(nil), full[:3]...)
	duped = append(duped, full[2]) // entry 2 twice
	duped = append(duped, full[3:]...)

	if err := bindAnchor(t, a, duped); err == nil {
		t.Fatal("a duplicated entry bound successfully to its anchor")
	}
}

// TestAnchor_SubMillisecondTimestampChangeBreaksTheBinding is the precision case.
//
// The chain hash is computed over a microsecond-precision timestamp. A change
// below millisecond resolution is invisible in any millisecond-based
// representation, so a round-trip through UnixMilli would silently produce a
// different chain — and therefore a different anchor binding. This pins that the
// anchor path inherits that sensitivity rather than rounding it away.
func TestAnchor_SubMillisecondTimestampChangeBreaksTheBinding(t *testing.T) {
	t.Parallel()

	full := buildAnchoredChain(t, 4)
	a := anchorOver(t, full, anchor.SeedAnchorHash)

	shifted := append([]anchoredEntry(nil), full...)
	shifted[2].Timestamp = shifted[2].Timestamp.Add(1 * time.Microsecond)

	if _, brk := walkAndReturnHead(t, shifted); brk == -1 {
		t.Fatal("a one-microsecond shift did not change the chain — precision was lost")
	}
	if err := bindAnchor(t, a, shifted); err == nil {
		t.Fatal("a one-microsecond shift survived anchor binding")
	}
}

// =============================================================================
// Signed, end to end
// =============================================================================

// TestAnchor_SignedVerificationEndToEnd is the complete chain of custody:
// build → link → anchor → SIGN → verify signature + bind → tamper → fail.
func TestAnchor_SignedVerificationEndToEnd(t *testing.T) {
	t.Parallel()

	entries := buildAnchoredChain(t, 5)
	a := anchorOver(t, entries, anchor.SeedAnchorHash)

	// Sign it for real.
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	canonical, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(priv, canonical, nil, false, sig)
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustPlatform,
		map[string][]byte{a.SigningKeyID: pubBytes})
	if err != nil {
		t.Fatalf("key ring: %v", err)
	}

	rows := toVerifyEntries(entries)

	res, err := verify.VerifyAnchor(a, rows, ring)
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !res.Bound || !res.SignatureVerified {
		t.Fatalf("expected a bound, signature-verified result: %+v", res)
	}
	if res.Trust != anchor.TrustPlatform {
		t.Errorf("trust = %q, want platform", res.Trust)
	}
	t.Logf("PROVEN:     %s", res.Proven)
	t.Logf("NOT PROVEN: %s", res.NotProven)

	// Truncate, and the signed anchor still catches it.
	truncated := append([]anchoredEntry(nil), entries[2:]...)
	previousHash := ""
	for i := range truncated {
		truncated[i].SequenceNum = int64(i)
		truncated[i].ChainHash = chainformat.ComputeChainHashUnchecked(
			previousHash, truncated[i].RunID, int64(i),
			truncated[i].Timestamp, truncated[i].ContentHash)
		previousHash = truncated[i].ChainHash
	}
	bad, err := verify.VerifyAnchor(a, toVerifyEntries(truncated), ring)
	if err != nil {
		t.Fatalf("VerifyAnchor on a truncated chain should return a result, not an error: %v", err)
	}
	if bad.Bound {
		t.Fatal("a truncated chain bound to a signed anchor")
	}
	// The signature is STILL valid — the anchor is genuine, it just describes a
	// different chain. A caller must be able to tell those apart.
	if !bad.SignatureVerified {
		t.Error("the anchor is genuine; only the binding failed. Both facts must be reported.")
	}
}

// TestAnchor_KeylessAndKeyedClaimsDiffer pins that the two entry points do not
// make the same promise.
//
// If a keyless bind reported the same claim as a signature-verified one, the
// whole Trust apparatus would be decorative.
func TestAnchor_KeylessAndKeyedClaimsDiffer(t *testing.T) {
	t.Parallel()

	entries := buildAnchoredChain(t, 4)
	a := anchorOver(t, entries, anchor.SeedAnchorHash)

	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := anchor.Canonicalize(a)
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(priv, canonical, nil, false, sig)
	a.Signature = base64.StdEncoding.EncodeToString(sig)
	pubBytes, _ := pub.MarshalBinary()
	ring, _ := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{a.SigningKeyID: pubBytes})

	rows := toVerifyEntries(entries)

	keyless, err := verify.BindAnchor(a, rows)
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := verify.VerifyAnchor(a, rows, ring)
	if err != nil {
		t.Fatal(err)
	}

	if keyless.SignatureVerified {
		t.Error("BindAnchor must never report a verified signature")
	}
	if keyless.Proven == keyed.Proven {
		t.Error("keyless and keyed results make the same claim; the distinction is decorative")
	}
	if keyless.Trust != "" {
		t.Errorf("a keyless bind must not assert a trust level, got %q", keyless.Trust)
	}
}

// toVerifyEntries converts the test entry shape to the exported one.
func toVerifyEntries(entries []anchoredEntry) []verify.Entry {
	rows := make([]verify.Entry, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, verify.Entry{
			EntryID:     e.EntryID,
			EntryType:   "request",
			Timestamp:   e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			RunID:       e.RunID,
			SequenceNum: e.SequenceNum,
			GlobalSeq:   e.SequenceNum,
			ContentHash: e.ContentHash,
			ChainHash:   e.ChainHash,
		})
	}
	return rows
}
