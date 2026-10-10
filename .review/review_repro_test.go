package zzreview

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/bundle"
	"github.com/aleutian-ai/proof/canonical"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keywrap"
	"github.com/aleutian-ai/proof/merkle"
	"github.com/aleutian-ai/proof/verify"
)

func ch(s string) string { return strings.Repeat(s, 128) }

func mk(n int, contents []string) []verify.Entry {
	var out []verify.Entry
	prev := ""
	for i := 0; i < n; i++ {
		ts := time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		h, err := chainformat.ComputeChainHashV3(prev, int64(i), ts, contents[i])
		if err != nil {
			panic(err)
		}
		out = append(out, verify.Entry{EntryID: fmt.Sprintf("e%d", i), EntryType: "x", Timestamp: ts.Format(time.RFC3339Nano),
			FormatVersion: 3, GlobalSeq: int64(i), ContentHash: contents[i], ChainHash: h})
		prev = h
	}
	return out
}

func TestTombstoneForgery(t *testing.T) {
	orig := mk(5, []string{ch("a"), ch("b"), ch("c"), ch("d"), ch("e")})
	a, err := build.Anchor(context.Background(), build.Input{Subject: "acme", Entries: orig})
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	s, _ := anchor.NewMLDSA65Signer(seed)
	a, err = anchor.SignAnchor(context.Background(), s, a)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, _ := anchor.KeyIDOf(s)
	kr, _ := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{a.SigningKeyID: pub})

	// attacker: rewrite entries 0..3 with entirely different content, keep ids;
	// turn LAST entry into "tombstone" retaining original chain hash.
	forged := mk(5, []string{ch("1"), ch("2"), ch("3"), ch("4"), ch("5")})
	forged[4].ChainHash = orig[4].ChainHash
	forged[4].ContentHash = "TOMBSTONE:" + strings.Repeat("0", 64)
	res, err := verify.VerifyAnchor(a, forged, anchor.SeedAnchorHash, kr)
	t.Logf("VerifyAnchor(forged, content-hash-only tombstone): bound=%v sig=%v outcome=%s err=%v", res.Bound, res.SignatureVerified, res.Outcome, err)

	// Walker path: needs type+id prefix; the anchor's EndEntryID is e4, so tombstone a middle entry instead
	forged2 := mk(5, []string{ch("1"), ch("2"), ch("c"), ch("d"), ch("e")})
	forged2[2] = orig[2]
	forged2[2].EntryType = "tombstone"
	forged2[2].EntryID = "tomb_00000000-0000-0000-0000-000000000000"
	forged2[2].ContentHash = "TOMBSTONE:" + strings.Repeat("0", 64)
	forged2[3], forged2[4] = orig[3], orig[4]
	r, _ := verify.Chain(forged2, verify.Options{})
	t.Logf("Chain(forged2): %s breaks=%d", r.Verdict, len(r.Breaks))
	w := verify.NewWalker(verify.Options{})
	for _, e := range forged2 {
		w.Add(e)
	}
	res, err = w.VerifyAnchor(a, anchor.SeedAnchorHash, kr)
	t.Logf("Walker.VerifyAnchor(forged2): bound=%v sig=%v outcome=%s err=%v proven=%q", res.Bound, res.SignatureVerified, res.Outcome, err, res.Proven)
	res, err = verify.VerifyAnchor(a, forged2, anchor.SeedAnchorHash, kr)
	t.Logf("VerifyAnchor(forged2): bound=%v outcome=%s err=%v", res.Bound, res.Outcome, err)

	// predicate disagreement: content-hash tombstone w/o type
	r, _ = verify.Chain(forged, verify.Options{})
	t.Logf("Chain(forged content-hash-only): %s", r.Verdict)

	// timestamp malleability
	m := append([]verify.Entry(nil), orig...)
	m[1].Timestamp = "2026-01-01T05:30:01.000000999+05:30"
	m[1].EntryID = "e1" ; m[1].EntryType = "totally-different-type"
	r, _ = verify.Chain(m, verify.Options{})
	t.Logf("Chain(ts string + entry_type altered): %s", r.Verdict)
	// entry id swap among middle entries
	m[1].EntryID, m[2].EntryID = m[2].EntryID, m[1].EntryID
	res, err = verify.VerifyAnchor(a, m, anchor.SeedAnchorHash, kr)
	t.Logf("VerifyAnchor(middle entry_ids swapped, type changed): bound=%v err=%v", res.Bound, err)

	// garbage content hash accepted by verifier
	g := []verify.Entry{{EntryID: "g", Timestamp: "2026-01-01T00:00:00Z", FormatVersion: 3, GlobalSeq: -7, ContentHash: "not|a|hash"}}
	g[0].ChainHash = chainformat.ComputeChainHashV3Unchecked("", -7, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "not|a|hash")
	r, _ = verify.Chain(g, verify.Options{})
	t.Logf("Chain(garbage content hash, seq -7): %s", r.Verdict)
}

func TestFrontier(t *testing.T) {
	h := strings.Repeat("ab", 64)
	f, err := merkle.UnmarshalFrontier("0|64:" + h)
	t.Logf("size0 with level64: f!=nil %v err=%v", f != nil, err)
	f, err = merkle.UnmarshalFrontier("1|0:" + h + "|64:" + h)
	t.Logf("size1 with extra level64: %v err=%v", f != nil, err)
	if f != nil {
		g, _ := merkle.UnmarshalFrontier("1|0:" + h)
		t.Logf("roots equal? %v", string(f.Root()) == string(g.Root()))
	}
	_, err = merkle.UnmarshalFrontier("0|50000000:" + h)
	t.Logf("level 5e7 err=%v (allocated 5e7 slice headers = 1.2GB)", err)
}

func TestMerkle(t *testing.T) {
	bad := 0
	for n := 1; n <= 40; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte{byte(i), 1}
		}
		root := merkle.RootFromLeaves(leaves)
		if string(merkle.FrontierFromLeaves(leaves).Root()) != string(root) {
			t.Fatal("frontier mismatch", n)
		}
		for m := 0; m < n; m++ {
			p, _ := merkle.InclusionProof(m, leaves)
			if !merkle.VerifyInclusion(merkle.LeafHash(leaves[m]), m, n, p, root) {
				t.Fatal("incl", m, n)
			}
			for m2 := 0; m2 < n; m2++ {
				if m2 != m && merkle.VerifyInclusion(merkle.LeafHash(leaves[m]), m2, n, p, root) {
					bad++
				}
			}
		}
		for m := 0; m <= n; m++ {
			p, _ := merkle.ConsistencyProof(m, leaves)
			ra := merkle.RootFromLeaves(leaves[:m])
			if !merkle.VerifyConsistency(m, n, ra, root, p) {
				t.Fatal("cons", m, n)
			}
			for m2 := 1; m2 < n; m2++ {
				if m2 != m && merkle.VerifyConsistency(m2, n, ra, root, p) {
					bad++
					t.Logf("consistency proof for m=%d accepted as m=%d n=%d", m, m2, n)
				}
			}
			// truncated / extended proofs
			if len(p) > 0 && merkle.VerifyConsistency(m, n, ra, root, p[:len(p)-1]) {
				t.Fatal("trunc accepted")
			}
			if merkle.VerifyConsistency(m, n, ra, root, append(append([][]byte{}, p...), root)) {
				t.Fatal("ext accepted")
			}
		}
	}
	t.Logf("wrong-index acceptances: %d", bad)
	// node-as-leaf
	l := [][]byte{[]byte("a"), []byte("b")}
	fake := append(merkle.LeafHash(l[0]), merkle.LeafHash(l[1])...)
	t.Logf("second preimage: %v", string(merkle.RootFromLeaves([][]byte{fake})) == string(merkle.RootFromLeaves(l)))
}

func TestKeywrap(t *testing.T) {
	b := make([]byte, 512)
	b[0] = 1
	_, err := keywrap.UnmarshalV3(b)
	t.Logf("v1 512B blob: %v", err)
	b = make([]byte, keywrap.V3Size)
	b[0] = 1
	_, err = keywrap.UnmarshalV3(b)
	t.Logf("v1 1169B blob: %v", err)
}

func TestCanonical(t *testing.T) {
	for _, v := range []any{
		map[string]any{"a": "x y<&>\b\f\x7f"},
		map[string]any{"n": json.Number("-0")},
		map[string]any{"\U0001F600": 1, "�": 2},
		json.RawMessage(`{"a":1,"a":2}`),
		json.RawMessage(`{"a":1.0}`),
		json.RawMessage(`{"a":10000000000000000000000000000}`),
	} {
		b, err := canonical.MarshalJSON(v)
		t.Logf("%q err=%v", b, err)
	}
}

func TestBundle(t *testing.T) {
	d := t.TempDir()
	r, err := bundle.VerifyDir(d, nil, "", 0)
	t.Logf("empty: intact=%v err=%v", r.Intact, err)
	out := t.TempDir()
	os.WriteFile(out+"/secret", []byte("hi"), 0o600)
	os.Symlink(out, d+"/sub")
	r, err = bundle.VerifyDir(d, []bundle.FileEntry{{Path: "sub/secret", SHA512: ch("a")}}, "", 0)
	t.Logf("symlinked dir: %+v err=%v", r.Problems, err)
}

func TestYear(t *testing.T) {
	a := chainformat.ComputeChainHashV3Unchecked("", 0, time.Date(-5, 1, 1, 0, 0, 0, 0, time.UTC), ch("a"))
	b := chainformat.ComputeChainHashV3Unchecked("", 0, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), ch("a"))
	t.Logf("year -5 == year 0: %v", a == b)
}
