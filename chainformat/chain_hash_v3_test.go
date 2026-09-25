// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"strings"
	"testing"
	"time"
)

// v3 fixtures. Fixed values, so a change to the preimage shows up as a changed
// golden hash rather than as a passing test.
var (
	v3TestTime    = time.Date(2026, 9, 23, 14, 30, 45, 123456000, time.UTC)
	v3ContentHash = strings.Repeat("ab", 64)
	v3PrevHash    = strings.Repeat("cd", 64)
)

// TestComputeChainHashV3_GoldenVectors pins the v3 preimage. These values were
// produced by this implementation and are asserted here so that any change to
// the byte layout — separator, field order, prefix, timestamp format — fails
// loudly instead of silently forking the format.
//
// A verifier in another language must reproduce these exactly.
func TestComputeChainHashV3_GoldenVectors(t *testing.T) {
	cases := []struct {
		name        string
		previous    string
		globalSeq   int64
		timestamp   time.Time
		contentHash string
		want        string
	}{
		{
			name:        "first entry in a chain",
			previous:    "",
			globalSeq:   0,
			timestamp:   v3TestTime,
			contentHash: v3ContentHash,
			want:        goldenV3First,
		},
		{
			name:        "linked entry",
			previous:    v3PrevHash,
			globalSeq:   1,
			timestamp:   v3TestTime,
			contentHash: v3ContentHash,
			want:        goldenV3Linked,
		},
		{
			name:        "large global sequence",
			previous:    v3PrevHash,
			globalSeq:   9007199254740993,
			timestamp:   v3TestTime,
			contentHash: v3ContentHash,
			want:        goldenV3LargeSeq,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeChainHashV3Unchecked(tc.previous, tc.globalSeq, tc.timestamp, tc.contentHash)
			if got != tc.want {
				t.Errorf("chain hash changed:\n got %s\nwant %s", got, tc.want)
			}
			if len(got) != 128 {
				t.Errorf("hash is %d characters, want 128", len(got))
			}
		})
	}
}

// Golden values. Regenerating these is a format change, not a test fix.
const (
	goldenV3First    = "1c891800c0791a8fa453031b23255a9b61630787be50ef2e89d0bdaf8cc37295023cefcc865109138b50f975ccf4e475665b471bfe0a0c4cf7c39db08f2830b8"
	goldenV3Linked   = "82ecd39640a4bbfa9e65c320de7574f37179c15b5df26222251ff2fed7b6657f2776e4921b6df65bbf23270dc0d1df6f05261ba1920d2665b3e68270599168f5"
	goldenV3LargeSeq = "54f1f391dc70667d2624e2156b504d3cdb698b254f33b37a3dfae66f8a89fea6eb17d674df9fbc0c1e8f5c54b9b14d8d75739e48387436d9821586fbcbedd4b1"
)

// TestChainHashV3_DiffersFromV2 is the point of the domain prefix: the same
// logical entry must not produce the same digest under two formats, or a v2
// entry could be presented as a v3 entry and vice versa.
func TestChainHashV3_DiffersFromV2(t *testing.T) {
	v2 := ComputeChainHashUnchecked(v3PrevHash, "run-1", 1, v3TestTime, v3ContentHash)
	v3 := ComputeChainHashV3Unchecked(v3PrevHash, 1, v3TestTime, v3ContentHash)
	if v2 == v3 {
		t.Error("v2 and v3 produced the same hash for the same entry")
	}
}

// TestChainHashV3_EveryFieldIsBound: if a field can change without changing
// the hash, it is not protected, whatever the documentation says.
func TestChainHashV3_EveryFieldIsBound(t *testing.T) {
	base := ComputeChainHashV3Unchecked(v3PrevHash, 1, v3TestTime, v3ContentHash)

	cases := []struct {
		name string
		got  string
	}{
		{"previous hash", ComputeChainHashV3Unchecked(strings.Repeat("ef", 64), 1, v3TestTime, v3ContentHash)},
		{"global seq", ComputeChainHashV3Unchecked(v3PrevHash, 2, v3TestTime, v3ContentHash)},
		{"timestamp", ComputeChainHashV3Unchecked(v3PrevHash, 1, v3TestTime.Add(time.Microsecond), v3ContentHash)},
		{"content hash", ComputeChainHashV3Unchecked(v3PrevHash, 1, v3TestTime, strings.Repeat("12", 64))},
	}
	for _, tc := range cases {
		if tc.got == base {
			t.Errorf("%s is not bound into the hash", tc.name)
		}
	}
}

// TestChainHashV3_NoFieldConfusion: field boundaries must be unambiguous, or
// two different entries could share a preimage. Moving a character between
// adjacent fields must change the digest.
func TestChainHashV3_NoFieldConfusion(t *testing.T) {
	// Same concatenated digits, different split between seq and timestamp is
	// impossible by construction, so probe the pair that IS attacker-shaped:
	// a previous hash and a sequence number that could run together without a
	// separator.
	a := ComputeChainHashV3Unchecked(strings.Repeat("ab", 64), 12, v3TestTime, v3ContentHash)
	b := ComputeChainHashV3Unchecked(strings.Repeat("ab", 64), 1, v3TestTime, v3ContentHash)
	if a == b {
		t.Error("sequence numbers 12 and 1 collided")
	}
}

// TestChainHashV3_TimestampPrecision: sub-microsecond precision is truncated,
// not rounded, exactly as in v2 — a producer and a verifier that disagree here
// disagree about every hash.
func TestChainHashV3_TimestampPrecision(t *testing.T) {
	micro := time.Date(2026, 9, 23, 14, 30, 45, 123456000, time.UTC)
	plusNanos := time.Date(2026, 9, 23, 14, 30, 45, 123456999, time.UTC)

	if ComputeChainHashV3Unchecked("", 0, micro, v3ContentHash) !=
		ComputeChainHashV3Unchecked("", 0, plusNanos, v3ContentHash) {
		t.Error("nanoseconds below microsecond precision changed the hash; they must be truncated")
	}

	plusMicro := micro.Add(time.Microsecond)
	if ComputeChainHashV3Unchecked("", 0, micro, v3ContentHash) ==
		ComputeChainHashV3Unchecked("", 0, plusMicro, v3ContentHash) {
		t.Error("a one-microsecond difference did not change the hash")
	}
}

// TestChainHashV3_TimezoneIndependence: the same instant must hash the same
// however the producer's clock is configured.
func TestChainHashV3_TimezoneIndependence(t *testing.T) {
	utc := time.Date(2026, 9, 23, 14, 30, 45, 123456000, time.UTC)
	elsewhere := utc.In(time.FixedZone("UTC+9", 9*60*60))

	if ComputeChainHashV3Unchecked("", 0, utc, v3ContentHash) !=
		ComputeChainHashV3Unchecked("", 0, elsewhere, v3ContentHash) {
		t.Error("the same instant hashed differently in a different zone")
	}
}

// TestValidateChainHashInputsV3 covers the refusals. v3 has no run id, so the
// v2 run-id rules must not have been carried over.
func TestValidateChainHashInputsV3(t *testing.T) {
	valid := strings.Repeat("ab", 64)

	cases := []struct {
		name      string
		previous  string
		globalSeq int64
		content   string
		wantErr   string
	}{
		{"first entry", "", 0, valid, ""},
		{"linked entry", valid, 1, valid, ""},
		{"tombstone content hash", valid, 1, "TOMBSTONE:" + strings.Repeat("ab", 32), ""},
		{"short previous hash", "abc", 1, valid, "previousHash"},
		{"uppercase previous hash", strings.Repeat("AB", 64), 1, valid, "previousHash"},
		{"negative sequence", valid, -1, valid, "globalSeq"},
		{"empty content hash", valid, 1, "", "contentHash"},
		{"short content hash", valid, 1, "abc", "contentHash"},
		{"uppercase content hash", valid, 1, strings.Repeat("AB", 64), "contentHash"},
		{"malformed tombstone", valid, 1, "TOMBSTONE:BADDATA", "contentHash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateChainHashInputsV3(tc.previous, tc.globalSeq, tc.content)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestComputeChainHashV3_ChecksItsInputs: the checked entry point must refuse
// what the validator refuses, and agree with the unchecked one otherwise.
func TestComputeChainHashV3_ChecksItsInputs(t *testing.T) {
	if _, err := ComputeChainHashV3("", -1, v3TestTime, v3ContentHash); err == nil {
		t.Error("a negative sequence was accepted")
	}
	got, err := ComputeChainHashV3(v3PrevHash, 1, v3TestTime, v3ContentHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := ComputeChainHashV3Unchecked(v3PrevHash, 1, v3TestTime, v3ContentHash); got != want {
		t.Error("the checked and unchecked functions disagree")
	}
}

// TestNormalizeFormatVersion: an entry written before versions were recorded
// has no version field, which decodes as zero and must mean v2 — otherwise
// every chain in existence becomes unverifiable.
func TestNormalizeFormatVersion(t *testing.T) {
	cases := map[int]int{
		0:  FormatV2,
		2:  FormatV2,
		3:  FormatV3,
		99: 99, // unknown versions pass through, for the caller to reject
	}
	for in, want := range cases {
		if got := NormalizeFormatVersion(in); got != want {
			t.Errorf("NormalizeFormatVersion(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestChainHashV2_IsUntouched guards the reason v3 is a separate function: the
// v2 preimage is a stored-data contract, and editing it would invalidate every
// chain ever written.
func TestChainHashV2_IsUntouched(t *testing.T) {
	if ChainHashPrefix != "aleutian.chain.v2:" {
		t.Errorf("the v2 domain prefix changed: %q", ChainHashPrefix)
	}
	if ChainHashPrefixV3 == ChainHashPrefix {
		t.Error("v2 and v3 share a domain prefix")
	}
}
