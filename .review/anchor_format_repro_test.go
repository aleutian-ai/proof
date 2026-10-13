package zzfmt

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/verify"
)

var ctx = context.Background()

func chain(n int, salt string) []verify.Entry {
	var out []verify.Entry
	prev := ""
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * time.Second)
		ch := strings.Repeat(fmt.Sprintf("%02x", (i+len(salt))%251), 64)
		h := chainformat.ComputeChainHashV3Unchecked(prev, int64(i), ts, ch)
		out = append(out, verify.Entry{EntryID: fmt.Sprintf("e%s%d", salt, i), EntryType: "event",
			Timestamp: ts.Format("2006-01-02T15:04:05.000000Z"), FormatVersion: 3, GlobalSeq: int64(i), ContentHash: ch, ChainHash: h})
		prev = h
	}
	return out
}

func signer(t *testing.T, b byte) (*anchor.MLDSA65Signer, *anchor.KeyRing) {
	s, err := anchor.NewMLDSA65Signer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, pub, _ := anchor.KeyIDOf(s)
	r, err := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{id: pub})
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func mk(t *testing.T, s anchor.ContextSigner, subj string, es []verify.Entry, prev *anchor.Anchor) anchor.Anchor {
	a, err := build.Anchor(ctx, build.Input{Subject: subj, Entries: es, Previous: prev})
	if err != nil {
		t.Fatal(err)
	}
	sa, err := anchor.SignAnchor(ctx, s, a)
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

func TestBoundWithSigError(t *testing.T) {
	es := chain(5, "")
	s, _ := signer(t, 1)
	_, other := signer(t, 2)
	a := mk(t, s, "subj", es, nil)
	// attacker-minted anchor: valid shape, garbage signature, key id of trusted key
	_, ring := signer(t, 1)
	a.Signature = strings.Repeat("A", 4412)
	res, err := verify.VerifyAnchor(a, es, anchor.SeedAnchorHash, ring)
	t.Logf("garbage sig: Bound=%v Outcome=%s SigVerified=%v Proven=%q err=%v", res.Bound, res.Outcome, res.SignatureVerified, res.Proven, err)
	res, err = verify.VerifyAnchor(a, es, anchor.SeedAnchorHash, other)
	t.Logf("unknown key: Bound=%v err=%v", res.Bound, err)
}

func TestPrevIDAndVerifiedThrough(t *testing.T) {
	es := chain(10, "")
	s, ring := signer(t, 1)
	a, _ := build.Anchor(ctx, build.Input{Subject: "subj", Entries: es})
	a.PreviousAnchorID = "anchor_not-the-seed"
	a.VerifiedThrough = 999999
	a.CreatedAtMs = -5
	sa, err := anchor.SignAnchor(ctx, s, a)
	if err != nil {
		t.Fatal(err)
	}
	res, err := verify.VerifyAnchor(sa, es, anchor.SeedAnchorHash, ring)
	t.Logf("genesis w/ non-seed prev id, verified_through=999999 (count 10), created_at<0: Bound=%v sig=%v err=%v", res.Bound, res.SignatureVerified, err)

	// second anchor that says its predecessor is the SEED id but chains on a1's hash, and is older
	a1 := mk(t, s, "subj", es[:5], nil)
	a2, _ := build.Anchor(ctx, build.Input{Subject: "subj", Entries: es, Previous: &a1, CreatedAt: time.Unix(1, 0)})
	a2.PreviousAnchorID = anchor.SeedAnchorID
	a2.VerifiedThrough = 1
	sa2, _ := anchor.SignAnchor(ctx, s, a2)
	res, err = verify.VerifyAnchor(sa2, es, a1.ChainHash, ring)
	t.Logf("a2 claims seed id, prev hash=a1: Bound=%v sig=%v err=%v", res.Bound, res.SignatureVerified, err)

	// build: Previous of another subject, and regressing range
	other := mk(t, s, "OTHER", chain(20, "x"), nil)
	a3, err := build.Anchor(ctx, build.Input{Subject: "subj", Entries: es[:3], Previous: &other})
	t.Logf("build chains 'subj'(3 entries) onto anchor of OTHER(20 entries): err=%v prevID=%s", err, a3.PreviousAnchorID)
	sa3, _ := anchor.SignAnchor(ctx, s, a3)
	res, err = verify.VerifyAnchor(sa3, es[:3], other.ChainHash, ring)
	t.Logf("  verifies: Bound=%v err=%v", res.Bound, err)
}

func TestSubjectNotChecked(t *testing.T) {
	// same entries served as two different "chains": anchor for subject A binds anywhere
	es := chain(4, "")
	s, ring := signer(t, 1)
	a := mk(t, s, "tenant-A", es, nil)
	res, err := verify.VerifyAnchor(a, es, anchor.SeedAnchorHash, ring)
	t.Logf("no expected-subject input exists; Bound=%v outcome=%s err=%v", res.Bound, res.Outcome, err)
}

func TestSegmentAnchor(t *testing.T) {
	es := chain(10, "")
	s, ring := signer(t, 1)
	w := verify.NewWalker(verify.Options{PreviousHash: es[4].ChainHash})
	for _, e := range es[5:] {
		w.Add(e)
	}
	a, err := build.FromWalker(ctx, "subj", w, nil, time.Time{})
	t.Logf("build over mid-chain segment: err=%v entry_count=%d start=%s", err, a.EntryCount, a.Range.StartEntryID)
	if err != nil {
		return
	}
	sa, _ := anchor.SignAnchor(ctx, s, a)
	res, err := w.VerifyAnchor(sa, anchor.SeedAnchorHash, ring)
	t.Logf("walker verify of segment anchor: Bound=%v err=%v proven=%q", res.Bound, err, res.Proven)
}

func TestAnchorWire(t *testing.T) {
	es := chain(3, "")
	s, ring := signer(t, 1)
	a := mk(t, s, "subj", es, nil)
	raw, _ := json.Marshal(a)
	try := func(name string, b []byte) {
		var x anchor.Anchor
		if err := json.Unmarshal(b, &x); err != nil {
			t.Logf("%s: parse err %v", name, err)
			return
		}
		res, err := verify.VerifyAnchor(x, es, anchor.SeedAnchorHash, ring)
		t.Logf("%s: Bound=%v sig=%v err=%v", name, res.Bound, res.SignatureVerified, err)
	}
	try("baseline", raw)
	try("v6 with company_id key", bytes.Replace(raw, []byte(`"subject"`), []byte(`"company_id"`), 1))
	try("unknown unsigned fields root_hash/tree_size", bytes.Replace(raw, []byte(`{`), []byte(`{"root_hash":"deadbeef","tree_size":99999,"revoked":false,`), 1))
	try("uppercase keys", bytes.Replace(bytes.Replace(raw, []byte(`"version"`), []byte(`"VERSION"`), 1), []byte(`"entry_count"`), []byte(`"Entry_Count"`), 1))
	try("dup key first=bogus", bytes.Replace(raw, []byte(`{`), []byte(`{"entry_count":777,"chain_hash":"00",`), 1))
	// signature base64 malleability
	sig := a.Signature
	b := a
	b.Signature = sig[:100] + "\n" + sig[100:]
	res, err := verify.VerifyAnchor(b, es, anchor.SeedAnchorHash, ring)
	t.Logf("signature with embedded newline: sig=%v err=%v", res.SignatureVerified, err)
	// versions
	for _, v := range []int{0, -1, 1, 2, 3, 4, 5, 6, 7} {
		c := a
		c.Version = v
		_, err := anchor.VerifySignature(c, ring)
		t.Logf("relabel v6 sig as v%d: err=%v", v, err != nil)
	}
	// v1 anchor with empty subject signs+verifies
	u, _ := build.Anchor(ctx, build.Input{Subject: "x", Entries: es})
	u.Version, u.VerifiedThrough, u.Subject = 1, 0, ""
	u.ChainHash, _ = anchor.ChainHash(anchor.SeedAnchorHash, "", es[0].EntryID, es[2].EntryID, es[2].ChainHash)
	su, err := anchor.SignAnchor(ctx, s, u)
	t.Logf("sign v1 empty subject: err=%v", err)
	res, err = verify.VerifyAnchor(su, es, anchor.SeedAnchorHash, ring)
	t.Logf("verify v1 empty-subject: Bound=%v sig=%v err=%v", res.Bound, res.SignatureVerified, err)
}

func TestEntryFormat(t *testing.T) {
	es := chain(6, "")
	run := func(name string, f func(e []verify.Entry)) {
		c := append([]verify.Entry(nil), es...)
		f(c)
		r, _ := verify.Chain(c, verify.Options{})
		_, berr := verify.BindAnchor(anchor.Anchor{Version: 6, Subject: "s", VerifiedThrough: 1}, c, anchor.SeedAnchorHash)
		ty := ""
		if len(r.Breaks) > 0 {
			ty = string(r.Breaks[0].Type)
		}
		t.Logf("%-40s verdict=%s first=%d %s bindErr=%v", name, r.Verdict, r.FirstBreak, ty, berr)
	}
	run("baseline", func(e []verify.Entry) {})
	run("relabel v3->v2", func(e []verify.Entry) { e[2].FormatVersion = 2 })
	run("relabel v3->absent", func(e []verify.Entry) { e[2].FormatVersion = 0 })
	run("v99", func(e []verify.Entry) { e[2].FormatVersion = 99 })
	run("v-1", func(e []verify.Entry) { e[2].FormatVersion = -1 })
	run("tombstone with format 99", func(e []verify.Entry) {
		e[2].FormatVersion = 99
		e[2].EntryType, e[2].EntryID = "tombstone", "tomb_x"
		e[2].ContentHash = "TOMBSTONE:" + strings.Repeat("ab", 32)
	})
	run("tombstone carrying run_id/seq (v3)", func(e []verify.Entry) {
		e[2].RunID, e[2].SequenceNum = "r", 7
		e[2].EntryType, e[2].EntryID = "tombstone", "tomb_x"
		e[2].ContentHash = "TOMBSTONE:" + strings.Repeat("ab", 32)
	})
	// forged v2 tail appended to v3 chain w/ arbitrary global_seq continuing
	run("mixed: v2 entry appended after v3", func(e []verify.Entry) {})
	c := append([]verify.Entry(nil), es...)
	ts, _ := time.Parse(time.RFC3339Nano, es[5].Timestamp)
	h := chainformat.ComputeChainHashUnchecked(es[5].ChainHash, "run|x", -3, ts, "junk")
	c = append(c, verify.Entry{EntryID: "f", EntryType: "event", Timestamp: es[5].Timestamp, RunID: "run|x", SequenceNum: -3, GlobalSeq: 6, ContentHash: "junk", ChainHash: h})
	r, _ := verify.Chain(c, verify.Options{})
	t.Logf("v3 chain + v2 entry (older, weaker format) appended: %s", r.Verdict)
	// v2 chain: shift every global_seq
	var v2 []verify.Entry
	prev := ""
	for i := 0; i < 4; i++ {
		h := chainformat.ComputeChainHashUnchecked(prev, "run", int64(i), ts, es[i].ContentHash)
		v2 = append(v2, verify.Entry{EntryID: fmt.Sprint("v", i), Timestamp: es[5].Timestamp, RunID: "run", SequenceNum: int64(i), GlobalSeq: int64(i + 5000), ContentHash: es[i].ContentHash, ChainHash: h})
		prev = h
	}
	r, _ = verify.Chain(v2, verify.Options{})
	t.Logf("v2 chain with global_seq shifted by 5000: %s", r.Verdict)
	// JSON duplicate format_version
	var e verify.Entry
	err := json.Unmarshal([]byte(`{"format_version":3,"format_version":2,"Format_Version":3}`), &e)
	t.Logf("dup format_version keys: fv=%d err=%v", e.FormatVersion, err)
}

func TestKeyRing(t *testing.T) {
	es := chain(3, "")
	s, _ := signer(t, 1)
	_, pub, _ := anchor.KeyIDOf(s)
	// ring id unrelated to key; empty id
	r, err := anchor.NewKeyRing(anchor.TrustPlatform, map[string][]byte{"": pub, "some-other-keys-id": pub})
	t.Logf("ring with empty id + mislabelled id: err=%v", err)
	a, _ := build.Anchor(ctx, build.Input{Subject: "s", Entries: es})
	a.SigningKeyID = "some-other-keys-id"
	sa, err := anchor.SignAnchor(ctx, s, a)
	t.Logf("SignAnchor keeps foreign id: %v id=%s", err, sa.SigningKeyID)
	res, err := verify.VerifyAnchor(sa, es, anchor.SeedAnchorHash, r)
	t.Logf("verifies: %v %v trust=%s", res.Bound, err, res.Trust)
	// key ids across algs
	seen := map[string]string{}
	for _, alg := range []keyfile.Algorithm{keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87, keyfile.MLKEM512, keyfile.MLKEM768, keyfile.MLKEM1024, keyfile.XWing} {
		for l := 0; l < 3000; l += 16 {
			id, err := keyfile.KeyIDHex(alg, make([]byte, l))
			if err == nil {
				if o, ok := seen[id]; ok {
					t.Logf("COLLISION %s %v", o, alg)
				}
				seen[id] = fmt.Sprint(alg, l)
			}
		}
	}
	t.Logf("distinct ids for zero keys: %d", len(seen))
}

func TestKeyfile(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	p, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(p)
	// leading junk + PEM headers
	withHdr := pem.EncodeToMemory(&pem.Block{Type: blk.Type, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "X": "y"}, Bytes: blk.Bytes})
	_, _, err = keyfile.ParsePrivateKey(append([]byte("garbage before the block\n"), withHdr...))
	t.Logf("leading junk + PEM headers: err=%v", err)
	// both-form ML-DSA with garbage expanded key
	type both struct{ Seed, Expanded []byte }
	t.Logf("CheckConsistency(MLDSA65, seed, garbage)=%v", keyfile.CheckConsistency(keyfile.MLDSA65, seed, make([]byte, 4032)))
	t.Logf("CheckConsistency(MLDSA44)=%v (MLDSA87)=%v", keyfile.CheckConsistency(keyfile.MLDSA44, seed, make([]byte, 2560)), keyfile.CheckConsistency(keyfile.MLDSA87, seed, make([]byte, 4896)))
}
