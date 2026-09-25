// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/mldsa"
)

// These are the first tests to live in this package. Until now every test of
// `verify` sat in the root package, so `go test ./...` printed "[no test files]"
// beside the package that does the verifying — which is very likely why
// BindAnchor's genesis-only assumption survived as long as it did.

const testSubject = "my-project"

// buildChain returns n linked v3 entries and the head hash.
func buildChain(t *testing.T, n int) ([]Entry, string) {
	t.Helper()
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	entries := make([]Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e := Entry{
			EntryID:       "ent_" + string(rune('a'+i)),
			EntryType:     "capture.request.v3",
			Timestamp:     ts.Format("2006-01-02T15:04:05.000000Z"),
			GlobalSeq:     int64(i),
			FormatVersion: chainformat.FormatV3,
			ContentHash:   strings.Repeat("0123456789abcdef", 8),
		}
		e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, e.ContentHash)
		prev = e.ChainHash
		entries = append(entries, e)
	}
	return entries, prev
}

// anchorOver mints a v6 anchor over entries, chaining from previousAnchorHash.
func anchorOver(t *testing.T, entries []Entry, head, previousAnchorHash string) anchor.Anchor {
	t.Helper()
	first, last := entries[0], entries[len(entries)-1]
	ch, err := anchor.ChainHash(previousAnchorHash, testSubject, first.EntryID, last.EntryID, head)
	if err != nil {
		t.Fatalf("anchor chain hash: %v", err)
	}
	return anchor.Anchor{
		Version:          anchor.SubjectVersion,
		AnchorID:         "anchor_01234567-8901-2345-6789-012345678901",
		Subject:          testSubject,
		ChainHash:        ch,
		Range:            anchor.EntryRange{StartEntryID: first.EntryID, EndEntryID: last.EntryID},
		EntryCount:       int64(len(entries)),
		VerifiedThrough:  int64(len(entries)),
		SigningKeyID:     "test-key",
		CreatedAtMs:      base().UnixMilli(),
		PreviousAnchorID: anchor.SeedAnchorID,
	}
}

func base() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }

// TestBindAnchor_BindsANonGenesisAnchor is the regression test for the bug this
// package shipped: BindAnchor defaulted the predecessor to the genesis sentinel,
// so every anchor after the first reported BindHeadMismatch — which reads as
// tamper evidence and is not. The predecessor is now a required argument.
func TestBindAnchor_BindsANonGenesisAnchor(t *testing.T) {
	entries, head := buildChain(t, 4)

	// Control first. If a genesis anchor does not bind, the fixture is wrong and
	// nothing below means anything.
	genesis := anchorOver(t, entries, head, anchor.SeedAnchorHash)
	res, err := BindAnchor(genesis, entries, anchor.SeedAnchorHash)
	if err != nil {
		t.Fatalf("genesis bind: %v", err)
	}
	if !res.Bound {
		t.Fatalf("CONTROL FAILED — genesis anchor did not bind: %s", res.Detail)
	}

	// The anchor under test: chained from the genesis anchor.
	chained := anchorOver(t, entries, head, genesis.ChainHash)
	chained.PreviousAnchorID = genesis.AnchorID

	got, err := BindAnchor(chained, entries, genesis.ChainHash)
	if err != nil {
		t.Fatalf("chained bind: %v", err)
	}
	if !got.Bound {
		t.Errorf("a chained anchor did not bind: %s — %s", got.Outcome, got.Detail)
	}
}

// TestBindAnchor_WrongPredecessorFails: the previous anchor's hash is
// inside the anchor's own chain hash, so binding against the wrong predecessor
// must fail. Otherwise an anchor could be lifted out of its history.
func TestBindAnchor_WrongPredecessorFails(t *testing.T) {
	entries, head := buildChain(t, 4)
	genesis := anchorOver(t, entries, head, anchor.SeedAnchorHash)
	chained := anchorOver(t, entries, head, genesis.ChainHash)

	cases := map[string]string{
		"the seed sentinel (the original bug)": anchor.SeedAnchorHash,
		"a different anchor's hash":            strings.Repeat("ab", 64),
	}
	for name, wrong := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := BindAnchor(chained, entries, wrong)
			if err != nil {
				t.Fatalf("bind: %v", err)
			}
			if res.Bound {
				t.Error("bound against the wrong predecessor; the anchor chain carries no history")
			}
			if res.Outcome != BindHeadMismatch {
				t.Errorf("outcome = %v, want %v", res.Outcome, BindHeadMismatch)
			}
		})
	}
}

// TestBindAnchor_RejectsAMalformedPredecessor: a bad ARGUMENT must be an
// error, not a mismatch. Reporting it as BindHeadMismatch would tell the caller
// their chain was tampered with when in fact they passed the wrong string —
// which sends someone hunting an attacker who does not exist.
func TestBindAnchor_RejectsAMalformedPredecessor(t *testing.T) {
	entries, head := buildChain(t, 3)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)

	cases := map[string]string{
		"empty":          "",
		"too short":      "abc",
		"uppercase hex":  strings.Repeat("AB", 64),
		"not hex at all": strings.Repeat("zz", 64),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := BindAnchor(a, entries, bad)
			if err == nil {
				t.Fatalf("accepted a malformed predecessor hash; got outcome %v", res.Outcome)
			}
			if !strings.Contains(err.Error(), "previousAnchorHash") {
				t.Errorf("error %q does not name the offending argument", err)
			}
			if res.Bound {
				t.Error("returned Bound with an error")
			}
		})
	}
}

// TestBindAnchor_StillCatchesTampering: the fix must not weaken what the
// binder already detected.
func TestBindAnchor_StillCatchesTampering(t *testing.T) {
	entries, head := buildChain(t, 5)
	genesis := anchorOver(t, entries, head, anchor.SeedAnchorHash)
	prev := genesis.ChainHash
	a := anchorOver(t, entries, head, prev)

	cases := []struct {
		name    string
		mutate  func([]Entry) []Entry
		outcome BindOutcome
	}{
		{"an entry is edited", func(e []Entry) []Entry {
			c := append([]Entry(nil), e...)
			c[2].ContentHash = strings.Repeat("ff", 64)
			return c
		}, BindChainBroken},
		// The REAL truncation attack: drop entries from the front and RE-LINK, so
		// what remains is internally flawless and linkage alone cannot object.
		// Catching this is the whole reason anchors exist — see the README's
		// "Why linkage alone cannot see truncation".
		{"entries removed from the front, then re-linked", func(e []Entry) []Entry {
			kept := append([]Entry(nil), e[1:]...)
			prev := ""
			for i := range kept {
				ts, err := time.Parse(time.RFC3339Nano, kept[i].Timestamp)
				if err != nil {
					t.Fatalf("parse ts: %v", err)
				}
				kept[i].ChainHash = chainformat.ComputeChainHashV3Unchecked(
					prev, kept[i].GlobalSeq, ts, kept[i].ContentHash)
				prev = kept[i].ChainHash
			}
			return kept
		}, BindRangeStartMismatch},
		{"entries removed from the end", func(e []Entry) []Entry {
			return append([]Entry(nil), e[:len(e)-1]...)
		}, BindRangeEndMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := BindAnchor(a, tc.mutate(entries), prev)
			if err != nil {
				t.Fatalf("bind: %v", err)
			}
			if res.Bound {
				t.Fatal("bound a tampered chain")
			}
			if res.Outcome != tc.outcome {
				t.Errorf("outcome = %v, want %v (detail: %s)", res.Outcome, tc.outcome, res.Detail)
			}
		})
	}
}

// TestBindAnchor_RequiresEntries.
func TestBindAnchor_RequiresEntries(t *testing.T) {
	entries, head := buildChain(t, 2)
	a := anchorOver(t, entries, head, anchor.SeedAnchorHash)
	if _, err := BindAnchor(a, nil, anchor.SeedAnchorHash); err == nil {
		t.Error("accepted an empty chain")
	}
}

// TestBindAnchor_RejectsFormatMisuseAndUnknownFormats covers the two things the
// shared dispatch does beyond picking a preimage.
//
// Both matter for the same reason the original bug did: an entry this build
// cannot recompute is NOT evidence of tampering, and reporting it as a broken
// chain sends someone hunting an attacker who does not exist. They must come
// back as errors that say what is actually wrong.
func TestBindAnchor_RejectsFormatMisuseAndUnknownFormats(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Entry)
		wantErr string
	}{
		{
			// v3 binds neither field. Carrying them anyway invites a reader to
			// treat them as attested when they are free to change.
			name:    "a v3 entry carrying run_id",
			mutate:  func(e *Entry) { e.RunID = "run-1" },
			wantErr: "must not carry run_id",
		},
		{
			name:    "a v3 entry carrying sequence_num",
			mutate:  func(e *Entry) { e.SequenceNum = 7 },
			wantErr: "must not carry run_id",
		},
		{
			// A format from the future must be refused by name, never guessed
			// at. Guessing would recompute it as v2, fail, and report the
			// chain as broken.
			name:    "a format version this build does not implement",
			mutate:  func(e *Entry) { e.FormatVersion = 99 },
			wantErr: "format version 99 is not implemented",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, head := buildChain(t, 3)
			a := anchorOver(t, entries, head, anchor.SeedAnchorHash)
			tc.mutate(&entries[1])

			res, err := BindAnchor(a, entries, anchor.SeedAnchorHash)
			if err == nil {
				t.Fatalf("accepted a malformed entry; got outcome %v", res.Outcome)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
			if res.Bound {
				t.Error("returned Bound alongside an error")
			}
		})
	}
}

// TestVerifyAnchor_ForwardsThePredecessor: VerifyAnchor is the function the
// README points readers at, so if it ignored previousAnchorHash the original
// genesis-only bug would come back through the front door — with a valid
// signature attached, which makes it read even more like tamper evidence.
func TestVerifyAnchor_ForwardsThePredecessor(t *testing.T) {
	seed := make([]byte, mldsa.MLDSA65.SeedSize())
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	defer signer.Close()

	entries, head := buildChain(t, 4)
	genesis := anchorOver(t, entries, head, anchor.SeedAnchorHash)

	// A chained anchor, properly signed.
	chained := anchorOver(t, entries, head, genesis.ChainHash)
	chained.PreviousAnchorID = genesis.AnchorID
	chained.SigningKeyID = ""
	signed, err := anchor.SignAnchor(context.Background(), signer, chained)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}

	pub, err := signer.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{signed.SigningKeyID: pub})
	if err != nil {
		t.Fatalf("key ring: %v", err)
	}

	// With the right predecessor it binds AND the signature verifies.
	ok, err := VerifyAnchor(signed, entries, genesis.ChainHash, ring)
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !ok.Bound || !ok.SignatureVerified {
		t.Fatalf("a correctly signed chained anchor did not verify: %+v", ok)
	}

	// With the seed sentinel — what the old code always used — it must NOT bind,
	// even though the signature is perfectly good.
	bad, err := VerifyAnchor(signed, entries, anchor.SeedAnchorHash, ring)
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if bad.Bound {
		t.Error("VerifyAnchor ignored previousAnchorHash; the genesis-only bug is back")
	}
}
