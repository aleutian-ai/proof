// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	chCompanyID = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"
	chStartID   = "0192f3a1-1111-7000-8000-aaaaaaaaaaaa"
	chEndID     = "0192f3a1-2222-7000-8000-bbbbbbbbbbbb"
)

func hash128(c string) string { return strings.Repeat(c, 128) }

// TestSeedAnchorHash_IsExactlyTheDocumentedDigest pins the genesis constant.
//
// Recomputed rather than copied: a wrong seed makes every genesis anchor
// unverifiable, and a typo in a 128-char constant is invisible on review.
func TestSeedAnchorHash_IsExactlyTheDocumentedDigest(t *testing.T) {
	sum := sha512.Sum512([]byte("aleutian.anchor.seed.v2"))
	if got := hex.EncodeToString(sum[:]); got != SeedAnchorHash {
		t.Fatalf("SeedAnchorHash does not equal SHA-512(\"aleutian.anchor.seed.v2\")\n got: %s\nwant: %s",
			SeedAnchorHash, got)
	}
}

// TestChainHash_MatchesTheDocumentedFormula pins the preimage independently.
func TestChainHash_MatchesTheDocumentedFormula(t *testing.T) {
	prev, tip := hash128("a"), hash128("b")

	sum := sha512.Sum512([]byte(
		"aleutian.anchor.v2:" + prev + "|" + chCompanyID + "|" + chStartID + "|" + chEndID + "|" + tip))
	want := hex.EncodeToString(sum[:])

	got, err := ChainHash(prev, chCompanyID, chStartID, chEndID, tip)
	if err != nil {
		t.Fatalf("ChainHash: %v", err)
	}
	if got != want {
		t.Fatalf("digest does not match the documented formula\n got: %s\nwant: %s", got, want)
	}
}

// TestChainHash_DomainSeparationFromTheEntryChain is the domain guard.
//
// If the anchor domain ever equalled the entry domain, an anchor hash and an
// entry hash would be interchangeable — an anchor could be presented as an entry
// link, or vice versa.
func TestChainHash_DomainSeparationFromTheEntryChain(t *testing.T) {
	if ChainDomainV2 == "aleutian.chain.v2:" {
		t.Fatal("the anchor domain must differ from the entry-chain domain")
	}
	prev, tip := hash128("a"), hash128("b")

	anchorHash := ChainHashUnchecked(prev, chCompanyID, chStartID, chEndID, tip)
	sum := sha512.Sum512([]byte(
		"aleutian.chain.v2:" + prev + "|" + chCompanyID + "|" + chStartID + "|" + chEndID + "|" + tip))

	if anchorHash == hex.EncodeToString(sum[:]) {
		t.Fatal("anchor and entry domains produce the same digest")
	}
}

// TestChainHash_IsNotTheTipChainHash pins the most common wrong mental model.
//
// An anchor's chain_hash is NOT the tip entry's chain_hash. Code that
// byte-compares them will appear to work on hand-built fixtures and fail on
// every real anchor.
func TestChainHash_IsNotTheTipChainHash(t *testing.T) {
	tip := hash128("b")
	got := ChainHashUnchecked(hash128("a"), chCompanyID, chStartID, chEndID, tip)
	if got == tip {
		t.Fatal("the anchor chain hash must not equal the tip entry's chain hash")
	}
}

// =============================================================================
// Delimiter injection
// =============================================================================

// TestChainHash_DelimiterCollisionIsReal reproduces the finding the guard exists
// for. If this ever stops colliding, the preimage construction changed — which
// is a bigger event than the guard, because the digest is a persisted contract.
func TestChainHash_DelimiterCollisionIsReal(t *testing.T) {
	prev, tip := hash128("a"), hash128("b")

	a := ChainHashUnchecked(prev, chCompanyID, "entry_aaa|entry_bbb", "entry_ccc", tip)
	b := ChainHashUnchecked(prev, chCompanyID, "entry_aaa", "entry_bbb|entry_ccc", tip)
	if a != b {
		t.Fatalf("expected the shifted-boundary tuples to collide:\n  %s\n  %s", a, b)
	}

	// The result that is easy to get backwards: a VALID company id does not help.
	// The ambiguity is between the two entry IDs.
	if !companyIDRe.MatchString(chCompanyID) {
		t.Fatalf("the collision must use a well-formed company id, but %q is not", chCompanyID)
	}
}

// TestChainHash_RejectsPipeInEveryField pins the guard on all five positions.
func TestChainHash_RejectsPipeInEveryField(t *testing.T) {
	prev, tip := hash128("a"), hash128("b")
	base := [5]string{prev, chCompanyID, chStartID, chEndID, tip}

	for i, name := range chainHashFields {
		t.Run(name, func(t *testing.T) {
			f := base
			f[i] += "|x"
			if _, err := ChainHash(f[0], f[1], f[2], f[3], f[4]); err == nil {
				t.Fatalf("ChainHash accepted a '|' in %s", name)
			}
			if err := ValidateChainHashDelimiters(f[0], f[1], f[2], f[3], f[4]); err == nil {
				t.Fatalf("delimiter guard accepted a '|' in %s", name)
			}
		})
	}
}

// TestChainHash_PipeFreeInputsAreInjective is the sufficiency argument.
//
// Banning '|' is necessary AND sufficient: with no pipe in any field, splitting
// the preimage on '|' recovers the tuple uniquely. This exercises that claim
// over the whole cross product rather than asserting it.
func TestChainHash_PipeFreeInputsAreInjective(t *testing.T) {
	alphabet := []string{"", "a", "ab", "entry_x", "comp_1", "0"}
	seen := map[string][5]string{}

	var f [5]string
	for _, f0 := range alphabet {
		for _, f1 := range alphabet {
			for _, f2 := range alphabet {
				for _, f3 := range alphabet {
					for _, f4 := range alphabet {
						f = [5]string{f0, f1, f2, f3, f4}
						h := ChainHashUnchecked(f[0], f[1], f[2], f[3], f[4])
						if prev, ok := seen[h]; ok && prev != f {
							t.Fatalf("collision between pipe-free tuples %q and %q", prev, f)
						}
						seen[h] = f
					}
				}
			}
		}
	}
	if len(seen) != 6*6*6*6*6 {
		t.Fatalf("expected %d distinct digests, got %d", 6*6*6*6*6, len(seen))
	}
}

// TestChainHash_ErrorDoesNotEchoTheValue keeps the error from becoming a
// confirmation oracle for attacker-supplied content.
func TestChainHash_ErrorDoesNotEchoTheValue(t *testing.T) {
	_, err := ChainHash(hash128("a"), chCompanyID,
		"entry|CANARY_SHOULD_NOT_APPEAR", chEndID, hash128("b"))
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "CANARY_SHOULD_NOT_APPEAR") {
		t.Errorf("error echoed the offending value: %v", err)
	}
	if !strings.Contains(err.Error(), "startEntryID") {
		t.Errorf("error must name the offending field: %v", err)
	}
}

// =============================================================================
// The producer/verifier asymmetry
// =============================================================================

// TestChainHash_VerifierGuardAcceptsNonUUIDEntryIDs is the false-break guard.
//
// ChainHash applies the DELIMITER check, never the strict shape check, because
// it must verify anchors signed long ago. Tightening it to full shape validation
// would flip historical anchors with non-UUID entry IDs from passing to broken —
// reporting a valid chain as invalid, which is the failure mode that shipped in
// three SDKs.
func TestChainHash_VerifierGuardAcceptsNonUUIDEntryIDs(t *testing.T) {
	legacy := []string{"legacy-entry-0001", "entry_2024_archive_00042", "ent_a", ""}
	for _, id := range legacy {
		if _, err := ChainHash(hash128("a"), chCompanyID, id, chEndID, hash128("b")); err != nil {
			t.Errorf("ChainHash rejected pipe-free legacy entry id %q: %v\n"+
				"It must NOT enforce shape — that false-breaks historical anchors.", id, err)
		}
	}
}

// TestValidateChainHashInputs covers the producer-side guard.
func TestValidateChainHashInputs(t *testing.T) {
	prev, tip := hash128("a"), hash128("b")

	tests := []struct {
		name                          string
		prev, company, start, end, ti string
		wantErr                       bool
	}{
		{"all valid", prev, chCompanyID, chStartID, chEndID, tip, false},
		{"seed hash as prev", SeedAnchorHash, chCompanyID, chStartID, chEndID, tip, false},
		{"tombstone entry id", prev, chCompanyID, "tomb_" + chStartID, chEndID, tip, false},
		{"short prev", prev[:127], chCompanyID, chStartID, chEndID, tip, true},
		{"uppercase prev", strings.ToUpper(prev), chCompanyID, chStartID, chEndID, tip, true},
		{"empty tip", prev, chCompanyID, chStartID, chEndID, "", true},
		{"malformed company", prev, "acme-corp", chStartID, chEndID, tip, true},
		{"lowercase ulid", prev, "comp_01hzx9k2m3n4p5q6r7s8t9v0wa", chStartID, chEndID, tip, true},
		{"legacy entry id", prev, chCompanyID, "legacy-entry-0001", chEndID, tip, true},
		{"pipe in end id", prev, chCompanyID, chStartID, "a|b", tip, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateChainHashInputs(tc.prev, tc.company, tc.start, tc.end, tc.ti)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}

// TestValidateChainHashInputs_SubsumesDelimiters pins the documented
// relationship: anything the producer guard accepts is pipe-free, so a producer
// cannot mint an ambiguous anchor while believing it had validated.
func TestValidateChainHashInputs_SubsumesDelimiters(t *testing.T) {
	prev, tip := hash128("a"), hash128("b")
	cases := [][5]string{
		{prev, chCompanyID, chStartID, chEndID, tip},
		{SeedAnchorHash, chCompanyID, "tomb_" + chStartID, chEndID, tip},
	}
	for _, c := range cases {
		if err := ValidateChainHashInputs(c[0], c[1], c[2], c[3], c[4]); err != nil {
			continue
		}
		if err := ValidateChainHashDelimiters(c[0], c[1], c[2], c[3], c[4]); err != nil {
			t.Errorf("strict validation accepted a tuple the delimiter guard rejects: %v", err)
		}
	}
}

// FuzzChainHash_NeverPanicsAndAlwaysGuards asserts the guard holds for arbitrary
// input, and that a returned digest is always well-formed.
func FuzzChainHash_NeverPanicsAndAlwaysGuards(f *testing.F) {
	f.Add(hash128("a"), chCompanyID, chStartID, chEndID, hash128("b"))
	f.Add("", "", "", "", "")
	f.Add("|", "|", "|", "|", "|")

	f.Fuzz(func(t *testing.T, prev, company, start, end, tip string) {
		got, err := ChainHash(prev, company, start, end, tip)
		if err != nil {
			for _, v := range []string{prev, company, start, end, tip} {
				if strings.ContainsRune(v, '|') {
					return // correctly rejected
				}
			}
			t.Fatalf("rejected an input with no '|' anywhere: %v", err)
		}
		if len(got) != 128 {
			t.Fatalf("digest length %d, want 128", len(got))
		}
		if !hash128Re.MatchString(got) {
			t.Fatalf("digest is not lowercase hex: %s", got)
		}
	})
}

// TestChainHash_MatchesTheProducerVectors is the independent-implementation check.
//
// These vectors were generated by the PRODUCER's own ComputeAnchorChainHash, not
// by this package. Every other test here checks this implementation against
// itself or against the formula as I understood it; this one checks it against
// the code that actually mints anchors in production.
//
// If this drifts, anchors minted by the producer stop verifying here — which is
// the failure that has no symptom until a customer cannot verify their chain.
func TestChainHash_MatchesTheProducerVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "testdata", "anchor_chain_hash_vectors.json"))
	if err != nil {
		t.Fatalf("read producer vectors: %v", err)
	}
	var f struct {
		Vectors []struct {
			Name         string `json:"name"`
			PreviousHash string `json:"previous_anchor_hash"`
			CompanyID    string `json:"company_id"`
			StartEntryID string `json:"start_entry_id"`
			EndEntryID   string `json:"end_entry_id"`
			TipChainHash string `json:"tip_chain_hash"`
			Expected     string `json:"expected_chain_hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse producer vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors — a silently empty contract is worse than none")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got := ChainHashUnchecked(v.PreviousHash, v.CompanyID,
				v.StartEntryID, v.EndEntryID, v.TipChainHash)
			if got != v.Expected {
				t.Errorf("digest differs from the producer:\n got: %s\nwant: %s", got, v.Expected)
			}
		})
	}
}
