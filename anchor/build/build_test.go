// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package build

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/mldsa"
	"github.com/aleutian-ai/proof/verify"
)

const testSubject = "my-project"

// chainOf returns n linked v3 entries.
func chainOf(t *testing.T, n int) []verify.Entry {
	t.Helper()
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	out := make([]verify.Entry, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e := verify.Entry{
			EntryID:       "ent_" + string(rune('a'+i)),
			EntryType:     "capture.request.v3",
			Timestamp:     ts.Format("2006-01-02T15:04:05.000000Z"),
			GlobalSeq:     int64(i),
			FormatVersion: chainformat.FormatV3,
			ContentHash:   strings.Repeat("0123456789abcdef", 8),
		}
		e.ChainHash = chainformat.ComputeChainHashV3Unchecked(prev, e.GlobalSeq, ts, e.ContentHash)
		prev = e.ChainHash
		out = append(out, e)
	}
	return out
}

func testSigner(t *testing.T) *anchor.MLDSA65Signer {
	t.Helper()
	seed := make([]byte, mldsa.MLDSA65.SeedSize())
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func ringFor(t *testing.T, s *anchor.MLDSA65Signer, keyID string) *anchor.KeyRing {
	t.Helper()
	pub, err := s.Public().(*anchor.PublicKey).MarshalBinary()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustSelf, map[string][]byte{keyID: pub})
	if err != nil {
		t.Fatalf("key ring: %v", err)
	}
	return ring
}

// TestAnchor_BuildSignVerify_Genesis is the round trip the ticket asks for, for
// the first anchor in a chain.
func TestAnchor_BuildSignVerify_Genesis(t *testing.T) {
	entries := chainOf(t, 5)
	signer := testSigner(t)

	a, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if a.Version != anchor.SubjectVersion {
		t.Errorf("version = %d, want %d (v6)", a.Version, anchor.SubjectVersion)
	}
	if a.PreviousAnchorID != anchor.SeedAnchorID {
		t.Errorf("PreviousAnchorID = %q, want the seed sentinel", a.PreviousAnchorID)
	}
	if a.EntryCount != 5 || a.VerifiedThrough != 5 {
		t.Errorf("EntryCount=%d VerifiedThrough=%d, want 5/5", a.EntryCount, a.VerifiedThrough)
	}
	if a.Signature != "" {
		t.Error("Anchor returned a signature; it produces UNSIGNED anchors")
	}

	signed, err := anchor.SignAnchor(context.Background(), signer, a)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	res, err := verify.VerifyAnchor(signed, entries, anchor.SeedAnchorHash,
		ringFor(t, signer, signed.SigningKeyID))
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !res.Bound || !res.SignatureVerified {
		t.Fatalf("built anchor did not verify: %+v", res)
	}
}

// TestAnchor_BuildSignVerify_Chained is the same round trip for an anchor that
// follows another — which is every anchor but the first, and which nothing in
// this module could verify until `_51`.
func TestAnchor_BuildSignVerify_Chained(t *testing.T) {
	signer := testSigner(t)

	firstEntries := chainOf(t, 3)
	first, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: firstEntries})
	if err != nil {
		t.Fatalf("first anchor: %v", err)
	}

	laterEntries := chainOf(t, 6)
	second, err := Anchor(context.Background(), Input{
		Subject: testSubject, Entries: laterEntries, Previous: &first,
	})
	if err != nil {
		t.Fatalf("second anchor: %v", err)
	}
	if second.PreviousAnchorID != first.AnchorID {
		t.Errorf("PreviousAnchorID = %q, want %q", second.PreviousAnchorID, first.AnchorID)
	}
	if second.AnchorID == first.AnchorID {
		t.Error("two anchors were minted with the same id")
	}

	signed, err := anchor.SignAnchor(context.Background(), signer, second)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	res, err := verify.VerifyAnchor(signed, laterEntries, first.ChainHash,
		ringFor(t, signer, signed.SigningKeyID))
	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if !res.Bound || !res.SignatureVerified {
		t.Fatalf("a chained built anchor did not verify: %+v", res)
	}

	// And it must NOT bind against the seed — otherwise it carries no history
	// and the first anchor could be dropped.
	spoofed, err := verify.BindAnchor(signed, laterEntries, anchor.SeedAnchorHash)
	if err != nil {
		t.Fatalf("BindAnchor: %v", err)
	}
	if spoofed.Bound {
		t.Error("the chained anchor bound against the seed; it does not commit to its predecessor")
	}
}

// TestAnchor_RefusesABrokenChain is the reason this package exists. An anchor
// asserting verified_through over a broken chain is a lie its own signature
// then authenticates.
func TestAnchor_RefusesABrokenChain(t *testing.T) {
	entries := chainOf(t, 4)
	entries[2].ContentHash = strings.Repeat("ff", 64) // edit an entry

	_, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if !errors.Is(err, ErrChainBroken) {
		t.Fatalf("Anchor over a broken chain returned %v, want ErrChainBroken", err)
	}
	// The refusal must say WHERE, or the operator has nowhere to start.
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("the refusal does not locate the break: %v", err)
	}
}

// TestAnchor_ChainHashIsRecomputed: copying the tip entry's hash would make the
// anchor agree with the chain by construction and detect nothing.
func TestAnchor_ChainHashIsRecomputed(t *testing.T) {
	entries := chainOf(t, 4)
	a, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	tip := entries[len(entries)-1].ChainHash
	if a.ChainHash == tip {
		t.Fatal("the anchor's chain hash equals the tip entry's; it was copied, not recomputed")
	}

	want, err := anchor.ChainHash(anchor.SeedAnchorHash, testSubject,
		entries[0].EntryID, entries[len(entries)-1].EntryID, tip)
	if err != nil {
		t.Fatalf("expected hash: %v", err)
	}
	if a.ChainHash != want {
		t.Errorf("chain hash = %s…, want %s…", a.ChainHash[:16], want[:16])
	}
}

// TestAnchor_ValidatesItsInput.
func TestAnchor_ValidatesItsInput(t *testing.T) {
	entries := chainOf(t, 2)

	t.Run("no entries", func(t *testing.T) {
		if _, err := Anchor(context.Background(), Input{Subject: testSubject}); !errors.Is(err, ErrNoEntries) {
			t.Errorf("got %v, want ErrNoEntries", err)
		}
	})
	t.Run("no subject", func(t *testing.T) {
		_, err := Anchor(context.Background(), Input{Entries: entries})
		if err == nil {
			t.Fatal("built a v6 anchor with no subject; it is the replay protection")
		}
		if !strings.Contains(err.Error(), "subject") {
			t.Errorf("error %q does not mention the subject", err)
		}
	})
	t.Run("the subject is checked BEFORE the chain is verified", func(t *testing.T) {
		// ValidateVersionInvariants would also reject an empty v6 subject at the
		// end, so a test that only asserts "an error mentioning subject" passes
		// with the early check deleted — a mutation proved exactly that. The
		// distinguishing question is ORDER: given input that is wrong in BOTH
		// ways, a caller should be told about the argument they got wrong, not
		// sent to investigate a chain break, and should not pay for a full
		// verification first.
		broken := chainOf(t, 4)
		broken[2].ContentHash = strings.Repeat("ff", 64)

		_, err := Anchor(context.Background(), Input{Entries: broken}) // no subject
		if err == nil {
			t.Fatal("accepted input with neither a subject nor an intact chain")
		}
		if errors.Is(err, ErrChainBroken) {
			t.Errorf("reported the chain break before the missing subject: %v", err)
		}
		if !strings.Contains(err.Error(), "subject") {
			t.Errorf("error %q does not name the missing subject", err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Anchor(ctx, Input{Subject: testSubject, Entries: entries}); !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want context.Canceled", err)
		}
	})
}

// TestAnchor_RefusesEntriesItCannotRecompute: an unknown format is not tamper
// evidence, and must not be silently anchored either.
func TestAnchor_RefusesEntriesItCannotRecompute(t *testing.T) {
	entries := chainOf(t, 3)
	entries[1].FormatVersion = 99

	if _, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries}); err == nil {
		t.Fatal("anchored a chain containing an entry this build cannot verify")
	}
}

// TestAnchor_IDShapeMatchesTheSentinel: the sentinel and a real id must be the
// same KIND of value, distinguishable only by value.
func TestAnchor_IDShapeMatchesTheSentinel(t *testing.T) {
	shape := regexp.MustCompile(`^anchor_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sentinelShape := regexp.MustCompile(`^anchor_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	if !sentinelShape.MatchString(anchor.SeedAnchorID) {
		t.Fatalf("the sentinel itself does not match the expected shape: %q", anchor.SeedAnchorID)
	}

	entries := chainOf(t, 2)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		a, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
		if err != nil {
			t.Fatalf("Anchor: %v", err)
		}
		if !shape.MatchString(a.AnchorID) {
			t.Fatalf("anchor id %q is not anchor_<uuidv4>", a.AnchorID)
		}
		if a.AnchorID == anchor.SeedAnchorID {
			t.Fatal("minted the genesis sentinel as a real anchor id")
		}
		if seen[a.AnchorID] {
			t.Fatalf("anchor id %q was minted twice in 50 draws", a.AnchorID)
		}
		seen[a.AnchorID] = true
	}
}

// TestAnchor_DoesNotMutateItsInput.
func TestAnchor_DoesNotMutateItsInput(t *testing.T) {
	entries := chainOf(t, 3)
	before := append([]verify.Entry(nil), entries...)

	first, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	prevCopy := first
	if _, err := Anchor(context.Background(), Input{
		Subject: testSubject, Entries: entries, Previous: &first,
	}); err != nil {
		t.Fatalf("Anchor: %v", err)
	}

	for i := range entries {
		if entries[i] != before[i] {
			t.Errorf("entry %d was mutated", i)
		}
	}
	if first != prevCopy {
		t.Error("the Previous anchor was mutated")
	}
}

// TestAnchor_CreatedAtIsOverridable: an anchor's time is descriptive, and a test
// or a replay needs to pin it. Zero must still mean now.
func TestAnchor_CreatedAtIsOverridable(t *testing.T) {
	entries := chainOf(t, 2)
	pinned := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	a, err := Anchor(context.Background(), Input{
		Subject: testSubject, Entries: entries, CreatedAt: pinned,
	})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if a.CreatedAtMs != pinned.UnixMilli() {
		t.Errorf("CreatedAtMs = %d, want %d", a.CreatedAtMs, pinned.UnixMilli())
	}

	b, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if b.CreatedAtMs < time.Now().Add(-time.Minute).UnixMilli() {
		t.Errorf("a zero CreatedAt did not default to now: %d", b.CreatedAtMs)
	}
}

// TestAnchor_TamperingIsCaughtEndToEnd: build, sign, then attack.
func TestAnchor_TamperingIsCaughtEndToEnd(t *testing.T) {
	entries := chainOf(t, 6)
	signer := testSigner(t)

	a, err := Anchor(context.Background(), Input{Subject: testSubject, Entries: entries})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	signed, err := anchor.SignAnchor(context.Background(), signer, a)
	if err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	ring := ringFor(t, signer, signed.SigningKeyID)

	t.Run("an entry is edited", func(t *testing.T) {
		bad := append([]verify.Entry(nil), entries...)
		bad[3].ContentHash = strings.Repeat("ff", 64)
		res, err := verify.VerifyAnchor(signed, bad, anchor.SeedAnchorHash, ring)
		if err != nil {
			t.Fatalf("VerifyAnchor: %v", err)
		}
		if res.Bound {
			t.Error("bound a chain with an edited entry")
		}
	})

	t.Run("truncated from the front and re-linked", func(t *testing.T) {
		kept := append([]verify.Entry(nil), entries[2:]...)
		prev := ""
		for i := range kept {
			ts, perr := time.Parse(time.RFC3339Nano, kept[i].Timestamp)
			if perr != nil {
				t.Fatalf("parse: %v", perr)
			}
			kept[i].ChainHash = chainformat.ComputeChainHashV3Unchecked(
				prev, kept[i].GlobalSeq, ts, kept[i].ContentHash)
			prev = kept[i].ChainHash
		}
		res, err := verify.VerifyAnchor(signed, kept, anchor.SeedAnchorHash, ring)
		if err != nil {
			t.Fatalf("VerifyAnchor: %v", err)
		}
		if res.Bound {
			t.Error("bound a truncated, re-linked chain — this is what anchors are for")
		}
	})

	t.Run("an anchor field is edited", func(t *testing.T) {
		for _, m := range []struct {
			name   string
			mutate func(*anchor.Anchor)
		}{
			{"subject", func(x *anchor.Anchor) { x.Subject = "someone-else" }},
			{"entry count", func(x *anchor.Anchor) { x.EntryCount = 99 }},
			{"verified through", func(x *anchor.Anchor) { x.VerifiedThrough = 99 }},
			{"range end", func(x *anchor.Anchor) { x.Range.EndEntryID = "ent_z" }},
		} {
			t.Run(m.name, func(t *testing.T) {
				tampered := signed
				m.mutate(&tampered)
				res, err := verify.VerifyAnchor(tampered, entries, anchor.SeedAnchorHash, ring)

				// Either outcome is acceptable — a malformed anchor errors, a
				// well-formed but altered one fails the signature. What is NOT
				// acceptable is coming back verified. Asserted explicitly so
				// this cannot pass merely because an error happened somewhere.
				if err != nil {
					return // refused outright; the field never reached verification
				}
				if res.SignatureVerified {
					t.Error("a tampered anchor field still verified under the signature")
				}
				if res.Bound {
					t.Error("a tampered anchor still bound to the chain")
				}
			})
		}
	})
}

// TestAnchor_SignedBytesAreStable: the same anchor must canonicalize identically
// twice, or a signature could not be checked against a re-read copy.
func TestAnchor_SignedBytesAreStable(t *testing.T) {
	entries := chainOf(t, 3)
	a, err := Anchor(context.Background(), Input{
		Subject: testSubject, Entries: entries, CreatedAt: time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	a.SigningKeyID = "fixed-key"

	first, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	second, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(first) != string(second) {
		t.Error("canonical bytes are not stable across calls")
	}
	if strings.Contains(string(first), base64.StdEncoding.EncodeToString([]byte("sig"))) {
		t.Error("the signature leaked into the canonical form")
	}
}
