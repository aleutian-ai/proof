// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Bundle v2 as the v0.5.0 pre-tag review attacked it, built on the v2
// conformance vectors.

package exportbundle

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/fixtures"
)

// v2Bundle decodes one v2 vector case into a generic structure.
func v2Bundle(t *testing.T, name string) (map[string]any, Trust) {
	t.Helper()
	vf, keys := loadVectorsFrom(t, fixtures.BundleV2Vectors())
	data, trust := vectorBundle(t, vf, keys, name)
	var b map[string]any
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return b, trust
}

func entriesOf(b map[string]any, chain int) []any {
	return b["chains"].([]any)[chain].(map[string]any)["entries"].([]any)
}

func encodeAny(t *testing.T, b any) []byte {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// resealEntry recomputes the leaf hash and chain hash of entry i from its
// stored strings, and relinks the entries after it.
func resealEntry(t *testing.T, entries []any, i int) {
	t.Helper()
	prev := ""
	if i > 0 {
		prev = entries[i-1].(map[string]any)["chain_hash"].(string)
	}
	for ; i < len(entries); i++ {
		e := entries[i].(map[string]any)
		e["previous_hash"] = prev
		leaf := chainformat.ComputeLeafHashV4Unchecked(e["entry_id"].(string), e["entry_type"].(string),
			e["content_hash"].(string), e["salt"].(string))
		e["leaf_hash"] = leaf
		seq, _ := parseGlobalSeq(e["global_seq"].(string))
		ts, _ := time.Parse("2006-01-02T15:04:05.000000Z", e["timestamp"].(string))
		e["chain_hash"] = chainformat.ComputeChainHashV4Unchecked(prev, seq, ts, leaf)
		prev = e["chain_hash"].(string)
	}
}

// TestReview_LongEntryTypeIsHashedAsStored: bundle-format §16 hashes
// entry_type "as the stored string, whatever it is". The reader once capped it
// at 12 bytes and hashed a placeholder for a longer one, so an entry whose leaf
// hash is correct over its real type was reported as chain-hash too.
func TestReview_LongEntryTypeIsHashedAsStored(t *testing.T) {
	for _, typ := range []string{"sink.other", "sink.event.x", "sink.event.xx", "sink.event.long.type"} {
		b, _ := v2Bundle(t, "ok_both_trusts")
		chain := b["chains"].([]any)[0].(map[string]any)
		chain["checkpoints"] = []any{}
		entries := entriesOf(b, 0)
		last := entries[len(entries)-1].(map[string]any)
		last["entry_type"] = typ
		delete(last, "record_signature")
		delete(last, "disclosed")
		resealEntry(t, entries, len(entries)-1)
		res := mustVerify(t, encodeAny(t, b), Trust{}, Limits{})
		if !res.Readable {
			t.Fatalf("%q: unreadable %s", typ, res.Reason)
		}
		got := problemCodes(res.Chains[0].Problems)
		t.Logf("entry_type %q (%d bytes): problems %q", typ, len(typ), got)
		if strings.Contains(got, CodeChainHash) {
			t.Errorf("entry_type %q (%d bytes): leaf hash is correct over the stored type, yet chain-hash was reported", typ, len(typ))
		}
	}
}

// Under checkpoint trust alone, a swapped inner entry id is caught in v2
// (bundle-format §16 §1). The checkpoint is left untouched and valid.
func TestReview_SwappedInnerIDUnderCheckpointTrust(t *testing.T) {
	b, trust := v2Bundle(t, "ok_checkpoint_trust_only")
	entries := entriesOf(b, 0)
	if len(entries) < 3 {
		t.Fatalf("want 3 entries, have %d", len(entries))
	}
	e0, e1 := entries[0].(map[string]any), entries[1].(map[string]any)
	e0["entry_id"], e1["entry_id"] = e1["entry_id"], e0["entry_id"]
	res := mustVerify(t, encodeAny(t, b), trust, Limits{})
	if !res.Readable || res.Verdict != VerdictFailed {
		t.Fatalf("swapped ids: readable=%v verdict=%q", res.Readable, res.Verdict)
	}
	got := problemCodes(res.Chains[0].Problems)
	t.Logf("swapped inner ids, checkpoint-only trust: %s -> %q", res.Verdict, got)
	if !strings.Contains(got, CodeChainHash+":2:0") {
		t.Errorf("want chain-hash at both swapped entries, got %q", got)
	}
	// And the control: the untouched bundle is ok.
	b2, trust2 := v2Bundle(t, "ok_checkpoint_trust_only")
	if res := mustVerify(t, encodeAny(t, b2), trust2, Limits{}); res.Verdict != VerdictOK {
		t.Fatalf("control: %s", res.Verdict)
	}
}

// The value limit depends on `format`, which a verifier must accept in any
// member order. With format LAST, a v2 bundle of 16M values is readable up to
// the structure check and a v1 one is too-large: the reader reconciles after
// the pass. (Documents the hazard for a streaming implementation.)
func TestReview_ValueLimitWithFormatLast(t *testing.T) {
	if testing.Short() {
		t.Skip("32 MB inputs")
	}
	build := func(format string, values int) []byte {
		in := []byte(`{"x":[`)
		in = append(in, bytes.Repeat([]byte("0,"), values-3)...)
		in = append(in[:len(in)-1], `],"format":"`+format+`"}`...)
		return in
	}
	if got := reasonOf(mustVerify(t, build(FormatV2, 16_000_000), Trust{}, Limits{})); got != ReasonStructure {
		t.Errorf("v2, format last, 16M values: %q, want structure", got)
	}
	if got := reasonOf(mustVerify(t, build(FormatV1, 16_000_000), Trust{}, Limits{})); got != ReasonTooLarge {
		t.Errorf("v1, format last, 16M values: %q, want too-large", got)
	}
	if got := reasonOf(mustVerify(t, build("aleutian.proof.bundle.v3", 16_000_000), Trust{}, Limits{})); got != ReasonTooLarge {
		t.Errorf("unknown format, 16M values: %q, want too-large", got)
	}
	// An explicit Values applies to every format: Limits{Values: valuesV1}
	// holds a v2 bundle to 15M.
	if got := reasonOf(mustVerify(t, build(FormatV2, 16_000_000), Trust{}, Limits{Values: valuesV1})); got != ReasonTooLarge {
		t.Errorf("v2 under explicit 15M: %q, want too-large", got)
	}
}

// One spelling per member: Unicode-folded, case-folded and escaped spellings
// of the new v2 members are unknown names (structure) or duplicates.
func TestReview_V2MemberSpellings(t *testing.T) {
	b, trust := v2Bundle(t, "ok_both_trusts")
	good := encodeAny(t, b)
	cases := []struct{ name, from, to, want string }{
		{"salt case", `"salt":`, `"Salt":`, ReasonStructure},
		{"leaf_hash case", `"leaf_hash":`, `"Leaf_Hash":`, ReasonStructure},
		{"salt long-s", `"salt":`, `"ſalt":`, ReasonStructure},
		{"leaf kelvin", `"leaf_hash":`, `"leaf_hasK":`, ReasonStructure},
		{"salt plain dup", `"salt":`, `"salt":"","salt":`, ReasonDuplicateKey},
		{"salt escaped dup", `"salt":`, "\"s\\u0061lt\":\"\",\"salt\":", ReasonDuplicateKey},
		{"salt escaped long-s", `"salt":`, "\"\\u017falt\":", ReasonStructure},
		{"format v2 uppercase", `"format":"aleutian.proof.bundle.v2"`, `"format":"aleutian.proof.bundle.V2"`, ReasonFormat},
		{"format escaped v2", `"format":"aleutian.proof.bundle.v2"`, "\"format\":\"aleutian.proof.bundle.v\\u0032\"", ""},
		{"format NFKC digit", `"format":"aleutian.proof.bundle.v2"`, `"format":"aleutian.proof.bundle.v２"`, ReasonFormat},
		{"erased member", `"salt":`, `"erased":true,"salt":`, ReasonStructure},
		{"format_version member", `"salt":`, `"format_version":4,"salt":`, ReasonStructure},
	}
	for _, c := range cases {
		data := bytes.Replace(good, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(data, good) {
			t.Fatalf("%s: pattern not found", c.name)
		}
		res := mustVerify(t, data, trust, Limits{})
		if got := reasonOf(res); got != c.want {
			t.Errorf("%s: reason %q, want %q (verdict %s)", c.name, got, c.want, res.Verdict)
		}
	}
}

// Hex case: an uppercase salt, leaf hash or checkpoint previous_anchor_hash
// is out of shape, never folded.
func TestReview_HexCaseNotFolded(t *testing.T) {
	b, trust := v2Bundle(t, "ok_both_trusts")
	entries := entriesOf(b, 0)
	e := entries[0].(map[string]any)
	e["salt"] = strings.ToUpper(e["salt"].(string))
	res := mustVerify(t, encodeAny(t, b), trust, Limits{})
	if got := problemCodes(res.Chains[0].Problems); !strings.Contains(got, "field-shape:1:0") {
		t.Errorf("uppercase salt: %q", got)
	}
}

// Resource bounds on v2: counts are enforced per bundle with v2 members
// present, and duplicate chains are reported by position.
func TestReview_V2Bounds(t *testing.T) {
	b, trust := v2Bundle(t, "ok_both_trusts")
	chains := b["chains"].([]any)
	// Three copies of the same chain.
	b["chains"] = []any{chains[0], chains[0], chains[0]}
	res := mustVerify(t, encodeAny(t, b), trust, Limits{})
	if res.Verdict != VerdictFailed || problemCodes(res.BundleProblems) != "duplicate-chain:2:1" {
		t.Errorf("duplicate chains: verdict %s, bundle problems %q", res.Verdict, problemCodes(res.BundleProblems))
	}
	for _, c := range res.Chains {
		if !strings.HasPrefix(c.Key, "#") {
			t.Errorf("duplicate chain keyed by id %q, want position", c.Key)
		}
	}
	// Entry limit, lowered: readable at the limit, too-large one over.
	b, trust = v2Bundle(t, "ok_both_trusts")
	n := len(entriesOf(b, 0)) + len(entriesOf(b, 1))
	if got := reasonOf(mustVerify(t, encodeAny(t, b), trust, Limits{Entries: n})); got != "" {
		t.Errorf("at entry limit: %q", got)
	}
	if got := reasonOf(mustVerify(t, encodeAny(t, b), trust, Limits{Entries: n - 1})); got != ReasonTooLarge {
		t.Errorf("one over entry limit: %q", got)
	}
	// Depth: an entry object is at depth 5. Depth 8 is the limit, so an
	// unknown member's value nested 4 deep inside an entry is json (depth 9),
	// 3 deep is structure.
	data := bytes.Replace(encodeAny(t, b), []byte(`"salt":`), []byte(`"z":[[[[0]]]],"salt":`), 1)
	if got := reasonOf(mustVerify(t, data, trust, Limits{})); got != ReasonJSON {
		t.Errorf("depth 9 inside an entry: %q, want json", got)
	}
	data = bytes.Replace(encodeAny(t, b), []byte(`"salt":`), []byte(`"z":[[[0]]],"salt":`), 1)
	if got := reasonOf(mustVerify(t, data, trust, Limits{})); got != ReasonStructure {
		t.Errorf("depth 8 inside an entry: %q, want structure", got)
	}
}

// FuzzVerifyV2 is FuzzVerify seeded with the v2 conformance bundles.
func FuzzVerifyV2(f *testing.F) {
	vf, _ := loadVectorsFrom(f, fixtures.BundleV2Vectors())
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
