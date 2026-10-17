// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/verify"
)

// v4Chain builds n linked v4 entries, as the linker would, with fixed salts.
func v4Chain(t *testing.T, contents ...string) []verify.Entry {
	t.Helper()
	var out []verify.Entry
	prev := ""
	for i, c := range contents {
		ts := time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		e := verify.Entry{EntryID: fmt.Sprintf("e%d", i), EntryType: "x", Timestamp: ts.Format(verify.TimestampLayout),
			FormatVersion: chainformat.FormatV4, GlobalSeq: int64(i), ContentHash: strings.Repeat(c, 128),
			Salt: fmt.Sprintf("%064x", i+1)}
		leaf, err := chainformat.ComputeLeafHashV4(e.EntryID, e.EntryType, e.ContentHash, e.Salt)
		if err != nil {
			t.Fatal(err)
		}
		e.LeafHash = leaf
		if e.ChainHash, err = chainformat.ComputeChainHashV4(prev, e.GlobalSeq, ts, leaf); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		prev = e.ChainHash
	}
	return out
}

func erase(e verify.Entry) verify.Entry {
	e.EntryID, e.EntryType, e.ContentHash, e.Salt, e.Erased = "", "", "", "", true
	return e
}

// TestTombstoneForgery_V4 is review round 1, finding 1, against v4: rewrite
// every entry before an erased one, under a valid signed anchor. In v3 the
// forged chain verified and the anchor bound (verify_verdict_vectors.json,
// entries_before_a_tombstone_rewritten). In v4 the erased entry is recomputed
// from its leaf hash, so the forgery breaks the chain; relinking the rest too
// makes it consistent again, and then the signed head no longer binds.
func TestTombstoneForgery_V4(t *testing.T) {
	orig := v4Chain(t, "a", "b", "c", "d", "e")
	a, err := build.Anchor(context.Background(), build.Input{Subject: "acme", Entries: orig})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := anchor.NewMLDSA65Signer(make([]byte, 32))
	if a, err = anchor.SignAnchor(context.Background(), s, a); err != nil {
		t.Fatal(err)
	}
	_, pub, _ := anchor.KeyIDOf(s)
	kr, _ := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{a.SigningKeyID: pub})

	// The lawful state: entry 2 erased. Still intact, still bound.
	lawful := append([]verify.Entry(nil), orig...)
	lawful[2] = erase(lawful[2])
	res, err := verify.VerifyAnchor(a, lawful, verify.Expect{PreviousAnchorHash: anchor.SeedAnchorHash}, kr)
	if err != nil || !res.Bound || !res.SignatureVerified || res.EntriesNotBound != 0 {
		t.Fatalf("a lawful erasure: bound %v, sig %v, not bound %d, %v", res.Bound, res.SignatureVerified, res.EntriesNotBound, err)
	}

	// The attack: entries 0 and 1 replaced and linked among themselves, the
	// erased entry and everything after it left as stored.
	forged := v4Chain(t, "1", "2", "c", "d", "e")
	forged[2], forged[3], forged[4] = lawful[2], lawful[3], lawful[4]
	r, _ := verify.Chain(forged, verify.Options{})
	if r.Verdict != verify.VerdictBroken || r.FirstBreak != 2 || r.Breaks[0].Type != verify.BreakHashMismatch {
		t.Fatalf("the forgery verified: %s, first break %d %+v", r.Verdict, r.FirstBreak, r.Breaks)
	}
	if res, _ := verify.VerifyAnchor(a, forged, verify.Expect{PreviousAnchorHash: anchor.SeedAnchorHash}, kr); res.Bound {
		t.Fatal("the anchor bound the forged chain")
	}

	// Relinked to the end, it is consistent; the anchor is what catches it.
	relinked := v4Chain(t, "1", "2", "c", "d", "e")
	relinked[2] = erase(relinked[2])
	if r, _ := verify.Chain(relinked, verify.Options{}); r.Verdict != verify.VerdictIntact {
		t.Fatalf("control: the relinked chain should be consistent: %+v", r)
	}
	res, _ = verify.VerifyAnchor(a, relinked, verify.Expect{PreviousAnchorHash: anchor.SeedAnchorHash}, kr)
	if res.Bound || res.Outcome != verify.BindHeadMismatch {
		t.Fatalf("the anchor bound a rewritten chain: %s", res.Outcome)
	}

	// Finding 2: entry_id and entry_type are in the leaf hash.
	for name, edit := range map[string]func(*verify.Entry){
		"entry_id":   func(e *verify.Entry) { e.EntryID = "e9" },
		"entry_type": func(e *verify.Entry) { e.EntryType = "tombstone-ish" },
	} {
		m := append([]verify.Entry(nil), orig...)
		edit(&m[1])
		if r, _ := verify.Chain(m, verify.Options{}); r.Verdict != verify.VerdictBroken || r.FirstBreak != 1 {
			t.Errorf("a changed %s went unnoticed: %+v", name, r)
		}
	}
}

// TestRound2AnchorFindings_V7 is review round 2's anchor findings against v7.
// A v6 anchor signed a predecessor id that nothing checked, a
// verified_through nothing compared, and bound for any subject; a v7 anchor
// over the same chain is refused or reported for each.
func TestRound2AnchorFindings_V7(t *testing.T) {
	es := v4Chain(t, "a", "b", "c", "d", "e", "f")
	s, _ := anchor.NewMLDSA65Signer(make([]byte, 32))
	_, pub, _ := anchor.KeyIDOf(s)
	sign := func(a anchor.Anchor) (anchor.Anchor, error) { return anchor.SignAnchor(context.Background(), s, a) }

	genesis, err := build.Anchor(context.Background(), build.Input{Subject: "subj", Entries: es})
	if err != nil {
		t.Fatal(err)
	}

	// A first anchor naming a predecessor that is not the seed: malformed.
	bad := genesis
	bad.PreviousAnchorID = "anchor_not-the-seed"
	if _, err := sign(bad); err == nil {
		t.Error("signed a first anchor that names a non-seed predecessor")
	}
	// verified_through no longer exists in v7.
	bad = genesis
	bad.VerifiedThrough = 999999
	if _, err := sign(bad); err == nil {
		t.Error("signed a v7 anchor carrying verified_through")
	}

	// A second anchor that claims the seed id while chaining on the first.
	first, err := build.Anchor(context.Background(), build.Input{Subject: "subj", Entries: es[:3]})
	if err != nil {
		t.Fatal(err)
	}
	if first, err = sign(first); err != nil {
		t.Fatal(err)
	}
	second, err := build.Anchor(context.Background(), build.Input{Subject: "subj", Entries: es, Previous: &first})
	if err != nil {
		t.Fatal(err)
	}
	bad = second
	bad.PreviousAnchorID = anchor.SeedAnchorID
	if _, err := sign(bad); err == nil {
		t.Error("signed a later anchor claiming the seed id")
	}
	// Bound against an expected predecessor that is not its own.
	signed2, err := sign(second)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{signed2.SigningKeyID: pub})
	res, err := verify.VerifyAnchor(signed2, es, verify.Expect{Subject: "subj", PreviousAnchorHash: anchor.SeedAnchorHash}, keys)
	if err != nil || res.Outcome != verify.BindPredecessorMismatch {
		t.Errorf("a wrong expected predecessor: %s, %v", res.Outcome, err)
	}

	// The subject is checked when given, and the result says when it was not.
	res, err = verify.VerifyAnchor(signed2, es, verify.Expect{Subject: "tenant-B"}, keys)
	if err != nil || res.Outcome != verify.BindTenantMismatch || res.Bound {
		t.Errorf("another subject: %s, bound %v, %v", res.Outcome, res.Bound, err)
	}
	res, err = verify.VerifyAnchor(signed2, es, verify.Expect{}, keys)
	if err != nil || !res.Bound || res.SubjectChecked || !strings.Contains(res.NotProven, "subject was not checked") {
		t.Errorf("no subject given: bound %v, checked %v, %q, %v", res.Bound, res.SubjectChecked, res.NotProven, err)
	}

	// Erasing the first and the last entry of the range changes nothing it binds.
	erased := append([]verify.Entry(nil), es...)
	erased[0], erased[len(erased)-1] = erase(erased[0]), erase(erased[len(erased)-1])
	res, err = verify.VerifyAnchor(signed2, erased, verify.Expect{Subject: "subj"}, keys)
	if err != nil || !res.Bound || !res.SignatureVerified {
		t.Errorf("after erasing the range's ends: %s, sig %v, %v", res.Outcome, res.SignatureVerified, err)
	}
}
