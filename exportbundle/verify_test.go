// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/fixtures"
	"github.com/aleutian-ai/proof/mldsa"
)

// A chain built here from the specification's formulas verifies: OK under the
// signing key, UNAUTHENTICATED without a key, and a checkpoint by a key that
// is not trusted is its own problem.
func TestVerify_BuiltChain(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, 32)
	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, keys := loadVectors(t)
	id := testChainID(3)
	entries := eventEntries(5)
	first, firstID, firstHash := testCheckpoint(t, id, entries, 2, 0, seedAnchorID, seedAnchorHash, seed)
	second, _, _ := testCheckpoint(t, id, entries, 5, 1, firstID, firstHash, seed)
	data := encodeBundle(t, rawChain{id: id, entries: entries, checkpoints: [][]byte{[]byte(first), []byte(second)}})

	for _, c := range []struct {
		name     string
		trust    Trust
		verdict  string
		problems string
		authed   int
	}{
		{"the signing key", Trust{Checkpoint: []PublicKey{key}}, VerdictOK, "", 5},
		{"no key", Trust{}, VerdictUnauthenticated, "", 0},
		{"another key", Trust{Checkpoint: []PublicKey{keys["other"]}}, VerdictFailed, "checkpoint-unknown-key:1:0", 0},
		{"record trust only", Trust{Record: []PublicKey{key}}, VerdictFailed, "unsigned:5:0", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := mustVerify(t, data, c.trust, Limits{})
			if !res.Readable || res.Verdict != c.verdict || len(res.Chains) != 1 || res.Chains[0].Key != id {
				t.Fatalf("result %+v", res)
			}
			ch := res.Chains[0]
			if got := problemCodes(ch.Problems); got != c.problems {
				t.Fatalf("problems %q, want %q", got, c.problems)
			}
			if ch.Counts.Authenticated != c.authed || ch.Counts.Committed != 5 || ch.Counts.Entries != 5 {
				t.Fatalf("counts %+v", ch.Counts)
			}
		})
	}
}

// Step e of §7.6: a checkpoint whose range holds a malformed entry does not
// bind, and one that ends before it does.
func TestCheckpoints_MalformedEntryInRange(t *testing.T) {
	id := testChainID(4)
	entries := eventEntries(6)
	first, firstID, firstHash := testCheckpoint(t, id, entries, 3, 0, seedAnchorID, seedAnchorHash, nil)
	second, _, _ := testCheckpoint(t, id, entries, 4, 1, firstID, firstHash, nil)
	entries[3].timestamp = "2026-02-30T00:00:00.000000Z"
	data := encodeBundle(t, rawChain{id: id, entries: entries, checkpoints: [][]byte{[]byte(first), []byte(second)}})
	res := mustVerify(t, data, Trust{}, Limits{})
	ch := res.Chains[0]
	if got, want := problemCodes(ch.Problems), "checkpoint-binding:1:1 field-shape:1:3"; got != want {
		t.Fatalf("problems %q, want %q", got, want)
	}
	if ch.Counts.Checkpoints != 1 || ch.Counts.Unanchored != 3 {
		t.Fatalf("counts %+v", ch.Counts)
	}
}

// Step e must not cost one pass over the covered entries per checkpoint: with
// 2,000 checkpoints each covering nearly all of a million entries, that would
// be two thousand million steps. The series over a million entries must cost
// about what it costs over two thousand.
func TestCheckpoints_StepEDoesNotScanEntries(t *testing.T) {
	const checkpoints = 2000
	id := testChainID(5)
	run := func(n int) time.Duration {
		// checkCheckpoints reads only ids and chain hashes; what makes an
		// entry well-formed reaches it as the first malformed index.
		entries := make([]rawEntry, n)
		for i := range entries {
			entries[i].entryID = "sink-00000000000000000000000000000000"
			entries[i].chainHash = seedAnchorHash
		}
		c := rawChain{id: id, entries: entries}
		previousID, previousHash := seedAnchorID, seedAnchorHash
		for k := 0; k < checkpoints; k++ {
			var text string
			text, previousID, previousHash = testCheckpoint(t, id, entries, n-checkpoints+k+1, k, previousID, previousHash, nil)
			c.checkpoints = append(c.checkpoints, []byte(text))
		}
		var v verifier
		var problems tally
		var counts Counts
		start := time.Now()
		covered, err := v.checkCheckpoints(&c, true, n, &problems, &counts)
		elapsed := time.Since(start)
		if err != nil || covered != n || counts.Checkpoints != checkpoints || len(problems.problems) != 0 {
			t.Fatalf("n=%d: covered %d, %d checkpoints, problems %q, err %v",
				n, covered, counts.Checkpoints, problemCodes(problems.problems), err)
		}
		// The same series with entry 0 malformed: the first checkpoint
		// covers it and fails, whatever its size.
		problems, counts = tally{}, Counts{}
		if _, err := v.checkCheckpoints(&c, true, 0, &problems, &counts); err != nil ||
			problemCodes(problems.problems) != "checkpoint-binding:1:0" {
			t.Fatalf("n=%d: with entry 0 malformed: %q, err %v", n, problemCodes(problems.problems), err)
		}
		return elapsed
	}
	small := run(checkpoints)
	large := run(1_000_000)
	t.Logf("%d checkpoints: over %d entries %v, over 1,000,000 entries %v", checkpoints, checkpoints,
		small.Round(time.Millisecond), large.Round(time.Millisecond))
	if large > 3*small+250*time.Millisecond {
		t.Fatalf("the checkpoint series took %v over a million entries and %v over %d: it scales with the entries",
			large, small, checkpoints)
	}
}

// The chain hash this package computes through chainformat, from a parsed
// sequence and instant, is format-spec §2.1 over the stored strings, at the
// edges of each shape.
func TestChainHash_OverStoredStrings(t *testing.T) {
	content := strings.Repeat("ab", 64)
	for _, c := range []struct{ previous, seq, timestamp string }{
		{"", "0", "0001-01-01T00:00:00.000000Z"},
		{strings.Repeat("0f", 64), "9223372036854775807", "9999-12-31T23:59:59.999999Z"},
		{strings.Repeat("0f", 64), "9007199254740993", "2024-02-29T12:00:01.123456Z"},
		{strings.Repeat("0f", 64), "41", "1582-10-10T00:00:00.000001Z"},
	} {
		e := rawEntry{entryID: "sink-" + strings.Repeat("0", 32), globalSeq: c.seq, previousHash: c.previous,
			timestamp: c.timestamp, contentHash: content, chainHash: content}
		seq, ts, ok := entryShape(&e)
		if !ok {
			t.Fatalf("%+v is not well-formed", c)
		}
		want := hashHex("aleutian.chain.v3:" + c.previous + "|" + c.seq + "|" + c.timestamp + "|" + content)
		if got := chainformat.ComputeChainHashV3Unchecked(c.previous, seq, ts, content); got != want {
			t.Fatalf("%+v: chain hash %s, want %s", c, got, want)
		}
	}
}

// §4.3's timestamp: one spelling, and a real instant.
func TestTimestampShape(t *testing.T) {
	for in, want := range map[string]bool{
		"2026-10-01T09:00:00.000000Z":      true,
		"2024-02-29T23:59:59.999999Z":      true,
		"2000-02-29T00:00:00.000000Z":      true,
		"0001-01-01T00:00:00.000000Z":      true,
		"9999-12-31T23:59:59.999999Z":      true,
		"1900-02-29T00:00:00.000000Z":      false, // 1900 is not a leap year
		"2023-02-29T00:00:00.000000Z":      false,
		"2026-02-30T00:00:00.000000Z":      false,
		"2026-04-31T00:00:00.000000Z":      false,
		"2026-13-01T00:00:00.000000Z":      false,
		"2026-00-10T00:00:00.000000Z":      false,
		"2026-01-00T00:00:00.000000Z":      false,
		"0000-01-01T00:00:00.000000Z":      false,
		"2026-10-01T24:00:00.000000Z":      false,
		"2026-10-01T09:60:00.000000Z":      false,
		"2026-10-01T09:00:60.000000Z":      false,
		"2026-10-01T09:00:00.00000Z":       false,
		"2026-10-01T09:00:00.0000000Z":     false,
		"2026-10-01T09:00:00Z":             false,
		"2026-10-01T09:00:00.000000":       false,
		"2026-10-01t09:00:00.000000z":      false,
		"2026-10-01T09:00:00.000000Z ":     false,
		"2026-10-01T09:00:00.000000Z\n":    false,
		"2026-10-01T09:00:00.000000+00:00": false,
		"٢٠٢٦-10-01T09:00:00.000000Z":      false,
		"":                                 false,
		oversize:                           false,
	} {
		if _, got := parseTimestamp(in); got != want {
			t.Errorf("timestamp %q: in shape %v, want %v", in, got, want)
		}
	}
}

// The record envelope is sink-format §9.1's: the vectors were computed from
// that section in Python, independently of proof's signer.
func TestRecordEnvelope_Vectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name   string `json:"name"`
			Fields struct {
				ChainID      string `json:"chain_id"`
				EntryID      string `json:"entry_id"`
				EntryType    string `json:"entry_type"`
				GlobalSeq    string `json:"global_seq"`
				PreviousHash string `json:"previous_hash"`
				Timestamp    string `json:"timestamp"`
				ContentHash  string `json:"content_hash"`
				SigningKeyID string `json:"signing_key_id"`
			} `json:"fields"`
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixtures.RecordV1Vectors(), &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no record vectors")
	}
	for _, v := range file.Vectors {
		f := v.Fields
		got := recordEnvelope(f.ChainID, &rawEntry{entryID: f.EntryID, entryType: f.EntryType, globalSeq: f.GlobalSeq,
			previousHash: f.PreviousHash, timestamp: f.Timestamp, contentHash: f.ContentHash}, f.SigningKeyID)
		if hex.EncodeToString(got) != v.EnvelopeHex {
			t.Errorf("%s: envelope differs", v.Name)
		}
	}
}

// §10: the text names the verdict, both trust dimensions, each failing
// chain's codes and the limits, says whose implementation this is, and prints
// no value from the bundle but a valid chain id.
func TestWriteText(t *testing.T) {
	vf, keys := loadVectors(t)
	text := func(res Result) string {
		var b strings.Builder
		if err := res.WriteText(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	always := []string{"writer's own implementation", "not an independent one", "Limits (docs/bundle-format.md §1)",
		"does not show", "historical artifact"}
	for _, c := range []struct {
		vector string
		want   []string
	}{
		{"ok_checkpoint_trust_only", []string{"verdict: OK\n", "checkpoint trust: checked", "record trust: not checked"}},
		{"unauthenticated_no_trust", []string{"verdict: UNAUTHENTICATED\n", "checkpoint trust: not checked", "provenance is not established"}},
		{"unauthenticated_empty_bundle", []string{"verdict: UNAUTHENTICATED\n", "holds no chains"}},
		{"modified", []string{"verdict: FAILED\n", "FAILED, erasure", "problems: modified (count 1, first at index"}},
		{"duplicate_chain", []string{"verdict: FAILED\n", "bundle problems: duplicate-chain (count 1, first at chain", "chain #0:"}},
		{"invalid_chain_id", []string{"verdict: FAILED\n", "invalid-chain-id (count 1)", "chain #"}},
		{"unreadable_duplicate_key", []string{"UNREADABLE: duplicate-key\n", "checkpoint keys: ", "record keys: "}},
	} {
		t.Run(c.vector, func(t *testing.T) {
			data, trust := vectorBundle(t, vf, keys, c.vector)
			out := text(mustVerify(t, data, trust, Limits{}))
			for _, want := range append(always, c.want...) {
				if !strings.Contains(out, want) {
					t.Fatalf("the text lacks %q:\n%s", want, out)
				}
			}
		})
	}

	// Every value in this bundle is marked, and none is a valid chain id.
	entries := eventEntries(2)
	entries[0].entryID = "LEAK-entry-id"
	entries[1].entryType = "LEAK-type"
	entries[1].timestamp = "LEAK-timestamp"
	entries[1].disclosed = &rawPair{a: "LEAK-content", b: "LEAK-nonce"}
	entries[1].sig = &rawPair{a: "LEAK-key-id", b: "LEAK-signature"}
	data := encodeBundle(t, rawChain{id: "LEAK-chain-id", entries: entries, checkpoints: [][]byte{[]byte(`{"subject":"LEAK-subject"}`)}})
	res := mustVerify(t, data, Trust{Record: []PublicKey{keys["record"]}}, Limits{})
	asJSON, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text(res), "JSON": string(asJSON)} {
		if strings.Contains(out, "LEAK") {
			t.Fatalf("the %s prints a value from the bundle:\n%s", name, out)
		}
		if !strings.Contains(out, "#0") || !strings.Contains(out, CodeInvalidChainID) {
			t.Fatalf("the %s does not key the chain by position:\n%s", name, out)
		}
	}
}

// §11's exit codes, one per outcome.
func TestExitCode(t *testing.T) {
	for _, c := range []struct {
		res  Result
		want int
	}{
		{Result{Readable: true, Verdict: VerdictOK}, 0},
		{Result{Readable: true, Verdict: VerdictFailed}, 1},
		{Result{Readable: false, Reason: ReasonJSON}, 3},
		{Result{Readable: true, Verdict: VerdictUnauthenticated}, 4},
		{Result{Readable: true}, 5},
	} {
		if got := c.res.ExitCode(); got != c.want {
			t.Errorf("%+v: exit %d, want %d", c.res, got, c.want)
		}
	}
}

// A problem's `first` is the lowest index, whatever order it was met in, and
// problems are sorted by code in byte order (§9.2).
func TestTally(t *testing.T) {
	var tl tally
	for _, p := range []struct {
		code  string
		index int
	}{{"unsigned", 4}, {"field-shape", 7}, {"unsigned", 2}, {"chain-hash", 0}, {"field-shape", 9}} {
		tl.add(p.code, p.index)
	}
	tl.addNoIndex(CodeInvalidChainID)
	if got, want := problemCodes(tl.sorted()), "chain-hash:1:0 field-shape:2:7 invalid-chain-id:1:null unsigned:2:2"; got != want {
		t.Fatalf("tally %q, want %q", got, want)
	}
	out, err := json.Marshal(tl.sorted()[2])
	if err != nil || string(out) != `{"code":"invalid-chain-id","count":1,"first":null}` {
		t.Fatalf("invalid-chain-id encodes as %s (%v)", out, err)
	}
}
