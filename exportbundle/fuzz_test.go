// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"
)

// checkAnyResult verifies data and requires what every input must give: a
// result, not a panic or an internal error, that is one of the two shapes of
// §9 and obeys §9.2's invariants.
func checkAnyResult(t testing.TB, data []byte, trust Trust) {
	t.Helper()
	res, err := VerifyWithLimits(data, trust, Limits{})
	if err != nil {
		t.Fatalf("internal error: %v", err)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("the result does not encode: %v", err)
	}
	if !res.Readable {
		switch res.Reason {
		case ReasonTooLarge, ReasonJSON, ReasonDuplicateKey, ReasonFormat, ReasonStructure:
			return
		}
		t.Fatalf("unknown reason %q", res.Reason)
	}
	worst := VerdictOK
	if len(res.Chains) == 0 {
		worst = VerdictUnauthenticated
	}
	for _, c := range res.Chains {
		n := c.Counts
		if n.Authenticated+n.Unauthenticated != n.Entries || n.CheckpointAuthenticated > n.Authenticated ||
			n.RecordAuthenticated > n.Authenticated || n.Opened+n.Committed+n.Erased > n.Events ||
			n.Events+n.Erasures > n.Entries || n.Unanchored > n.Entries || n.Entries == 0 {
			t.Fatalf("counts break an invariant: %+v", n)
		}
		if (c.Verdict == VerdictFailed) != (len(c.Problems) > 0) || (c.Verdict == VerdictOK) != (len(c.Problems) == 0 && n.Unauthenticated == 0) {
			t.Fatalf("verdict %q with %d problems and %d unauthenticated", c.Verdict, len(c.Problems), n.Unauthenticated)
		}
		worst = worse(worst, c.Verdict)
	}
	if len(res.BundleProblems) > 0 {
		worst = VerdictFailed
	}
	if res.Verdict != worst {
		t.Fatalf("bundle verdict %q, want %q", res.Verdict, worst)
	}
}

// Every prefix of a bundle, and a bundle with bytes changed, inserted or
// removed at random, gives a result and never a crash. The seed is fixed.
func TestVerify_DamagedInputNeverCrashes(t *testing.T) {
	vf, keys := loadVectors(t)
	trust := Trust{Checkpoint: []PublicKey{keys["checkpoint"]}, Record: []PublicKey{keys["record"]}}
	small := encodeBundle(t, rawChain{id: testChainID(1), entries: eventEntries(2), checkpoints: [][]byte{[]byte(`{"version":6}`)}})
	for cut := 0; cut <= len(small); cut++ {
		checkAnyResult(t, small[:cut], Trust{})
	}
	interesting := []byte(`"\{}[]:,0-.eEu 	` + "\x00\x80\xc0\xed\xa0\xff")
	rng := rand.New(rand.NewSource(72))
	for _, name := range []string{"ok_both_trusts", "real_export", "ok_two_erasures", "checkpoint_series_second_fails"} {
		original, _ := vectorBundle(t, vf, keys, name)
		for i := 0; i < 400; i++ {
			data := append([]byte(nil), original...)
			for edits := 1 + rng.Intn(3); edits > 0; edits-- {
				at := rng.Intn(len(data))
				b := interesting[rng.Intn(len(interesting))]
				switch rng.Intn(3) {
				case 0:
					data[at] = b
				case 1:
					data = append(data[:at], append([]byte{b}, data[at:]...)...)
				default:
					data = append(data[:at], data[at+1:]...)
				}
			}
			// Signatures are only verified on a few: the rest check the
			// reader and the chain checks, which is where damage lands.
			if i%20 == 0 {
				checkAnyResult(t, data, trust)
			} else {
				checkAnyResult(t, data, Trust{})
			}
		}
	}
}

// FuzzVerify holds Verify to the same property under the fuzzer. Its seeds,
// every conformance bundle, run as an ordinary test.
func FuzzVerify(f *testing.F) {
	vf, _ := loadVectors(f)
	for _, c := range vf.Cases {
		data, err := base64.StdEncoding.DecodeString(c.BundleB64)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkAnyResult(t, data, Trust{})
	})
}
