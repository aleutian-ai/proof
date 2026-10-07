// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// bundleEntry and bundleChain mirror bundle-format.md §4, strictly.
type bundleEntry struct {
	EntryID         string `json:"entry_id"`
	EntryType       string `json:"entry_type"`
	GlobalSeq       string `json:"global_seq"`
	PreviousHash    string `json:"previous_hash"`
	Timestamp       string `json:"timestamp"`
	ContentHash     string `json:"content_hash"`
	ChainHash       string `json:"chain_hash"`
	RecordSignature *struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	} `json:"record_signature"`
	Disclosed *struct {
		Content string `json:"content"`
		Nonce   string `json:"nonce"`
	} `json:"disclosed"`
}

type bundleChain struct {
	ChainID     string        `json:"chain_id"`
	Entries     []bundleEntry `json:"entries"`
	Checkpoints []string      `json:"checkpoints"`
}

type bundleDoc struct {
	Format string        `json:"format"`
	Chains []bundleChain `json:"chains"`
}

func export(t *testing.T, s *Sink, sel ExportSelection) ([]byte, ExportSummary, error) {
	t.Helper()
	var buf bytes.Buffer
	sum, err := s.Export(context.Background(), sel, &buf)
	return buf.Bytes(), sum, err
}

// decodeStrict decodes with unknown members refused. It is NOT a full
// bundle-format §3 check (encoding/json folds case and keeps duplicate keys);
// the conformance vectors (_72c) and the verifiers hold that line.
func decodeStrict(t *testing.T, raw []byte) bundleDoc {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b bundleDoc
	if err := dec.Decode(&b); err != nil {
		t.Fatalf("not a strict bundle: %v", err)
	}
	return b
}

func chainOf(t *testing.T, b bundleDoc, id string) bundleChain {
	t.Helper()
	for _, c := range b.Chains {
		if c.ChainID == id {
			return c
		}
	}
	t.Fatalf("chain %s not in the bundle", id)
	return bundleChain{}
}

// The whole folder exports as a strict bundle: members in the required order,
// every entry exactly as stored, checkpoints byte-for-byte, no disclosure by
// default, and nothing secret.
func TestExport_All(t *testing.T) {
	s, _, _ := setup(t)
	raw, sum, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(`{"format":"aleutian.proof.bundle.v1","chains":[{"chain_id":`)) {
		t.Fatalf("member order: %.80s", raw)
	}
	b := decodeStrict(t, raw)
	if sum.Chains != 3 || sum.Entries != 6 || sum.Checkpoints != 3 || sum.Disclosed != 0 || len(b.Chains) != 3 {
		t.Fatalf("summary %+v, %d chains", sum, len(b.Chains))
	}
	for _, subject := range []string{"u-81", "u-82", "u-90"} {
		if bytes.Contains(raw, []byte(subject)) {
			t.Fatalf("the bundle names subject %s", subject)
		}
	}
	a81 := cid(t, s, "u-81")
	c := chainOf(t, b, a81)
	ids := entryIDs(t, s, a81)
	for i, e := range c.Entries {
		if e.EntryID != ids[i] || e.GlobalSeq != []string{"0", "1", "2"}[i] || e.Disclosed != nil ||
			len(e.Timestamp) != len("2026-01-01T00:00:00.000000Z") || e.EntryType != EntryTypeEvent {
			t.Fatalf("entry %d: %+v", i, e)
		}
		if (i == 0) != (e.PreviousHash == "") || (i > 0 && e.PreviousHash != c.Entries[i-1].ChainHash) {
			t.Fatalf("entry %d: previous_hash not as stored", i)
		}
	}
	file, err := os.ReadFile(filepath.Join(s.anchorDir(a81), "0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Checkpoints) != 1 || c.Checkpoints[0] != string(file) {
		t.Fatal("the checkpoint is not the file's exact text")
	}
}

// --subject resolves through the index: only that subject's chains, and the
// subject never appears. After an erasure the subject has none: refused.
func TestExport_Subject(t *testing.T) {
	s, _, _ := setup(t)
	raw, sum, err := export(t, s, ExportSelection{Subject: "u-82"})
	if err != nil {
		t.Fatal(err)
	}
	b := decodeStrict(t, raw)
	if sum.Chains != 1 || b.Chains[0].ChainID != cid(t, s, "u-82") || bytes.Contains(raw, []byte("u-82")) {
		t.Fatalf("subject export: %+v", sum)
	}
	if _, err := eraseOne(t, s, "u-82"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := export(t, s, ExportSelection{Subject: "u-82"}); !errors.Is(err, ErrExportEmpty) {
		t.Fatalf("err = %v, want ErrExportEmpty", err)
	}
	if _, _, err := export(t, s, ExportSelection{Subject: "u-82", Class: "other"}); !errors.Is(err, ErrExportEmpty) {
		t.Fatalf("other class: err = %v", err)
	}
}

// Disclosure: all opens every live event; erased events never; the erasure
// record never; the content and nonce open the stored commitment.
func TestExport_DiscloseAll(t *testing.T) {
	s, _, _ := setup(t)
	if _, err := eraseOne(t, s, "u-82"); err != nil {
		t.Fatal(err)
	}
	raw, sum, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll})
	if err != nil {
		t.Fatal(err)
	}
	b := decodeStrict(t, raw)
	if sum.Disclosed != 4 { // u-81 ×3, u-90 ×1; u-82's 2 are erased
		t.Fatalf("disclosed %d, want 4", sum.Disclosed)
	}
	for _, c := range b.Chains {
		for _, e := range c.Entries {
			switch {
			case e.EntryType == EntryTypeErasure && e.Disclosed != nil:
				t.Fatal("an erasure record was disclosed")
			case c.ChainID == cid(t, s, "u-82") && e.Disclosed != nil:
				t.Fatal("an erased event was disclosed")
			case e.Disclosed != nil:
				content, _ := base64.StdEncoding.DecodeString(e.Disclosed.Content)
				nonce, _ := hex.DecodeString(e.Disclosed.Nonce)
				if !commitment.Verify(e.ContentHash, nonce, content) {
					t.Fatal("a disclosed event does not open its commitment")
				}
			}
		}
	}
}

// Listed ids: each must be exactly one live event in the selected chains.
func TestExport_DiscloseListed(t *testing.T) {
	s, _, _ := setup(t)
	a81 := entryIDs(t, s, cid(t, s, "u-81"))
	a82chain := cid(t, s, "u-82")
	a82 := entryIDs(t, s, a82chain)

	raw, sum, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseListed,
		DiscloseIDs: []string{a81[1], a81[1]}}) // a repeat counts once
	if err != nil || sum.Disclosed != 1 || bytes.Count(raw, []byte(`"disclosed"`)) != 1 {
		t.Fatalf("err %v, disclosed %d", err, sum.Disclosed)
	}

	cases := map[string]ExportSelection{
		"not in the selected chains": {Chains: []string{a82chain}, Disclose: DiscloseListed, DiscloseIDs: []string{a81[0]}},
		"no such entry":              {All: true, Disclose: DiscloseListed, DiscloseIDs: []string{"sink-" + strings.Repeat("0", 32)}},
		"not an entry id":            {All: true, Disclose: DiscloseListed, DiscloseIDs: []string{"u-81"}},
	}
	for name, sel := range cases {
		if _, _, err := export(t, s, sel); !errors.Is(err, ErrDisclosure) {
			t.Fatalf("%s: err = %v, want ErrDisclosure", name, err)
		}
	}
	if _, err := eraseOne(t, s, "u-82"); err != nil {
		t.Fatal(err)
	}
	erasureID := entryIDs(t, s, a82chain)[2]
	for name, id := range map[string]string{"an erased event": a82[0], "an erasure record": erasureID} {
		_, _, err := export(t, s, ExportSelection{Chains: []string{a82chain}, Disclose: DiscloseListed,
			DiscloseIDs: []string{id}})
		if !errors.Is(err, ErrDisclosure) {
			t.Fatalf("%s: err = %v, want ErrDisclosure", name, err)
		}
	}
}

// A live event whose content is missing cannot be represented: not disclosing
// it would read as `committed`. The export fails, rather than hide it.
func TestExport_MissingContentFails(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-90")
	id := entryIDs(t, s, chain)[0]
	sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.deleteRows(map[string][]string{chain: {id}}); err != nil {
		t.Fatal(err)
	}
	sec.Close()
	if _, _, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll}); !errors.Is(err, ErrExportUnrepresentable) {
		t.Fatalf("err = %v, want ErrExportUnrepresentable", err)
	}
	if _, _, err := export(t, s, ExportSelection{All: true}); err != nil {
		t.Fatalf("without disclosure the chain is representable: %v", err)
	}
}

// Content left before an erasure (an interrupted erasure) is never disclosed,
// and is reported.
func TestExport_IncompleteErasureNotDisclosed(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-82")
	ids := entryIDs(t, s, chain)
	if _, err := eraseOne(t, s, "u-82"); err != nil {
		t.Fatal(err)
	}
	sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, 32)
	if err := sec.putAll(map[string]map[string]secret{chain: {ids[0]: {content: []byte("left"), nonce: nonce}}}); err != nil {
		t.Fatal(err)
	}
	sec.Close()
	raw, sum, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll})
	if err != nil {
		t.Fatal(err)
	}
	if sum.IncompleteErasures != 1 || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte("left")))) {
		t.Fatalf("incomplete %d; the leftover content must never be exported", sum.IncompleteErasures)
	}
}

// A signature row is exported exactly, split at its storage boundary,
// whatever its length: never repaired, padded or omitted.
func TestExport_SignatureRowsExact(t *testing.T) {
	dir := t.TempDir()
	s := openSigning(t, dir, testRecordSigner(t, 7))
	if _, err := s.Commit(context.Background(), events("u-81", 3)); err != nil {
		t.Fatal(err)
	}
	chain := cid(t, s, "u-81")
	ids := entryIDs(t, s, chain)
	sig, err := openSignatures(s.signaturesPath(), DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	short := []byte{0xaa, 0xbb, 0xcc} // shorter than a key id
	err = sig.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(signaturesBucket)
		if err := b.Put(rowKey(chain, ids[1]), short); err != nil {
			return err
		}
		return b.Put(rowKey(chain, ids[2]), []byte{})
	})
	sig.Close()
	if err != nil {
		t.Fatal(err)
	}
	raw, sum, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	c := decodeStrict(t, raw).Chains[0]
	if rs := c.Entries[0].RecordSignature; rs == nil || len(rs.KeyID) != 32 || len(rs.Signature) != 4412 {
		t.Fatalf("a valid row: %+v", rs)
	}
	if rs := c.Entries[1].RecordSignature; rs == nil || rs.KeyID != "aabbcc" || rs.Signature != "" {
		t.Fatalf("a short row must be exported exactly: %+v", rs)
	}
	if rs := c.Entries[2].RecordSignature; rs == nil || rs.KeyID != "" || rs.Signature != "" {
		t.Fatalf("an empty row must be exported, not omitted: %+v", rs)
	}
	if len(sum.RecordKeyIDs) != 1 {
		t.Fatalf("record key ids %v", sum.RecordKeyIDs)
	}
}

// What a bundle cannot represent fails the whole export.
func TestExport_Unrepresentable(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Sink, dir string){
		"a gap in the checkpoints": func(t *testing.T, s *Sink, dir string) {
			if err := os.Rename(filepath.Join(dir, "0001.json"), filepath.Join(dir, "0002.json")); err != nil {
				t.Fatal(err)
			}
		},
		"a stray file": func(t *testing.T, s *Sink, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"checkpoint text that is not UTF-8": func(t *testing.T, s *Sink, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "0001.json"), []byte{'{', 0xff, '}'}, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, _ := setup(t)
			damage(t, s, s.anchorDir(cid(t, s, "u-90")))
			if _, _, err := export(t, s, ExportSelection{All: true}); !errors.Is(err, ErrExportUnrepresentable) {
				t.Fatalf("err = %v, want ErrExportUnrepresentable", err)
			}
		})
	}
}

func TestExport_Selection(t *testing.T) {
	s, _, _ := setup(t)
	a81 := cid(t, s, "u-81")
	bad := map[string]ExportSelection{
		"nothing":                 {},
		"two selectors":           {All: true, Subject: "u-81"},
		"class without a subject": {All: true, Class: "events"},
		"invalid chain id":        {Chains: []string{"../x"}},
		"a chain twice":           {Chains: []string{a81, a81}},
		"ids without listed":      {All: true, Disclose: DiscloseAll, DiscloseIDs: []string{"sink-" + strings.Repeat("0", 32)}},
		"listed without ids":      {All: true, Disclose: DiscloseListed},
		"invalid subject":         {Subject: "Jo Smith"},
	}
	for name, sel := range bad {
		if _, _, err := export(t, s, sel); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, _, err := export(t, s, ExportSelection{Chains: []string{"events." + strings.Repeat("0", 32)}}); !errors.Is(err, ErrExportEmpty) {
		t.Fatalf("a chain not in the folder: err = %v", err)
	}
	raw, _, err := export(t, s, ExportSelection{Chains: []string{a81}})
	if err != nil || len(decodeStrict(t, raw).Chains) != 1 {
		t.Fatalf("one chain: %v", err)
	}
}

// The limits: an export that would exceed them fails instead of writing a
// bundle every verifier must refuse.
func TestExport_Limits(t *testing.T) {
	s, _, _ := setup(t)
	for name, shrink := range map[string]func() func(){
		"entries": func() func() { old := maxBundleEntries; maxBundleEntries = 5; return func() { maxBundleEntries = old } },
		"checkpoints": func() func() {
			old := maxBundleCheckpoints
			maxBundleCheckpoints = 2
			return func() { maxBundleCheckpoints = old }
		},
		"chains": func() func() { old := maxBundleChains; maxBundleChains = 2; return func() { maxBundleChains = old } },
		"bytes":  func() func() { old := maxBundleBytes; maxBundleBytes = 1000; return func() { maxBundleBytes = old } },
	} {
		restore := shrink()
		_, _, err := export(t, s, ExportSelection{All: true})
		restore()
		if !errors.Is(err, ErrExportTooLarge) {
			t.Fatalf("%s: err = %v, want ErrExportTooLarge", name, err)
		}
	}
}

// Chains are read one lock hold at a time with a gap between: a writer
// committing in the gap is not starved, and the export still completes.
func TestExport_WriterNotStarved(t *testing.T) {
	s, _, _ := setup(t)
	commits := 0
	betweenPages = func() {
		if _, err := s.Commit(context.Background(), events("u-99", 1)); err != nil {
			t.Errorf("a writer between chains: %v", err)
		}
		commits++
	}
	defer func() { betweenPages = nil }()
	raw, _, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	decodeStrict(t, raw)
	// At least one gap between each pair of chains (more when the chain
	// listing itself is paged, as under SINK_TINY_PAGES).
	if commits < 2 {
		t.Fatalf("%d commits in the gaps, want at least 2", commits)
	}
}

func TestExport_Cancelled(t *testing.T) {
	s, _, _ := setup(t)
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Export(c, ExportSelection{All: true}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// The byte limit includes the bundle's closing bytes: a limit one byte under
// the full size fails, even though every chain fitted.
func TestExport_ByteLimitIsExact(t *testing.T) {
	s, _, _ := setup(t)
	full, _, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	old := maxBundleBytes
	defer func() { maxBundleBytes = old }()
	maxBundleBytes = int64(len(full))
	if _, _, err := export(t, s, ExportSelection{All: true}); err != nil {
		t.Fatalf("exactly at the limit: %v", err)
	}
	maxBundleBytes = int64(len(full)) - 1
	if _, _, err := export(t, s, ExportSelection{All: true}); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("one byte over: err = %v", err)
	}
}

// The core cryptographic property: from the exported STRINGS alone, every
// chain hash recomputes and every record signature verifies.
func TestExport_ExportedStringsRecompute(t *testing.T) {
	rs := testRecordSigner(t, 9)
	s := openSigning(t, t.TempDir(), rs)
	if _, err := s.Commit(context.Background(), append(events("u-81", 3), events("u-82", 2)...)); err != nil {
		t.Fatal(err)
	}
	key, err := recordKeyOf(rs)
	if err != nil {
		t.Fatal(err)
	}
	raw, sum, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.RecordKeyIDs) != 1 || sum.RecordKeyIDs[0] != key.id {
		t.Fatalf("record key ids %v, want [%s]", sum.RecordKeyIDs, key.id)
	}
	checked := 0
	for _, c := range decodeStrict(t, raw).Chains {
		for _, e := range c.Entries {
			ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			var seq int64
			if _, err := fmt.Sscan(e.GlobalSeq, &seq); err != nil {
				t.Fatal(err)
			}
			h, err := chainformat.ComputeChainHashV3(e.PreviousHash, seq, ts, e.ContentHash)
			if err != nil || h != e.ChainHash {
				t.Fatalf("chain hash does not recompute from the exported strings: %v", err)
			}
			sig, _ := base64.StdEncoding.DecodeString(e.RecordSignature.Signature)
			f := recordFields{chainID: c.ChainID, entryID: e.EntryID, entryType: e.EntryType, globalSeq: seq,
				prevHash: e.PreviousHash, timestamp: ts, contentHash: e.ContentHash, keyID: e.RecordSignature.KeyID}
			if err := verifyRecordSignature(key.pub, f, sig); err != nil {
				t.Fatalf("record signature does not verify from the exported strings: %v", err)
			}
			checked++
		}
	}
	if checked != 5 {
		t.Fatalf("checked %d entries", checked)
	}
}

// The checkpoint key ids are reported, so the recipient knows which keys to ask for.
func TestExport_CheckpointKeyIDs(t *testing.T) {
	s, signer, _ := setup(t)
	_, sum, err := export(t, s, ExportSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.CheckpointKeyIDs) != 1 || sum.CheckpointKeyIDs[0] != signer.KeyID() {
		t.Fatalf("checkpoint key ids %v, want [%s]", sum.CheckpointKeyIDs, signer.KeyID())
	}
}

// A chain whose subject is forgotten but whose erasure is not finished
// (pending): exported for integrity, nothing disclosed, reported; an explicit
// id on it fails.
func TestExport_PendingErasureNeverDisclosed(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-82")
	ids := entryIDs(t, s, chain)
	markPending(t, s, chain)
	raw, sum, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll})
	if err != nil {
		t.Fatal(err)
	}
	if sum.PendingErasures != 1 || sum.Disclosed != 4 {
		t.Fatalf("pending %d, disclosed %d (u-81 ×3 + u-90 only)", sum.PendingErasures, sum.Disclosed)
	}
	for _, e := range chainOf(t, decodeStrict(t, raw), chain).Entries {
		if e.Disclosed != nil {
			t.Fatal("content on a pending-erasure chain was disclosed")
		}
	}
	_, _, err = export(t, s, ExportSelection{Chains: []string{chain}, Disclose: DiscloseListed, DiscloseIDs: []string{ids[0]}})
	if !errors.Is(err, ErrDisclosure) {
		t.Fatalf("listed on a pending chain: err = %v", err)
	}
	if _, sum, err := export(t, s, ExportSelection{Chains: []string{chain}}); err != nil || sum.PendingErasures != 0 {
		t.Fatalf("integrity-only export of a pending chain: %v, %+v", err, sum)
	}
}

// A damaged nonce is never rewritten: asked to disclose it, the export fails.
func TestExport_DamagedNonceFails(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-90")
	id := entryIDs(t, s, chain)[0]
	if err := withSecrets(s, func(tx *bolt.Tx) error {
		return tx.Bucket(noncesBucket).Put(rowKey(chain, id), bytes.Repeat([]byte{1}, 31))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll}); !errors.Is(err, ErrExportUnrepresentable) {
		t.Fatalf("err = %v, want ErrExportUnrepresentable", err)
	}
	if _, _, err := export(t, s, ExportSelection{All: true}); err != nil {
		t.Fatalf("without disclosure: %v", err)
	}
}

// A relabelled erasure still erases (found by hash), and its leftovers are
// withheld without a misleading "run erase --resume" warning.
func TestExport_RelabelledErasure(t *testing.T) {
	s, _, _ := setup(t)
	chain := cid(t, s, "u-82")
	ids := entryIDs(t, s, chain)
	if _, err := eraseOne(t, s, "u-82"); err != nil {
		t.Fatal(err)
	}
	relabel(t, s, chain, 2, EntryTypeEvent) // the erasure entry, now labelled an event
	if err := withSecrets(s, func(tx *bolt.Tx) error {
		if err := tx.Bucket(contentBucket).Put(rowKey(chain, ids[0]), []byte("left")); err != nil {
			return err
		}
		return tx.Bucket(noncesBucket).Put(rowKey(chain, ids[0]), bytes.Repeat([]byte{1}, 32))
	}); err != nil {
		t.Fatal(err)
	}
	raw, sum, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseAll})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte("left")))) {
		t.Fatal("content before a relabelled erasure was disclosed")
	}
	if sum.IncompleteErasures != 0 {
		t.Fatal("a relabelled erasure must not trigger the erase --resume warning")
	}
}

// A listed id matching an event on two chains is ambiguous: refused.
func TestExport_AmbiguousListedID(t *testing.T) {
	s, _, _ := setup(t)
	id := "sink-" + strings.Repeat("e", 32)
	for _, subj := range []string{"u-81", "u-90"} {
		chain := cid(t, s, subj)
		appendRaw(t, s, chain, id)
		if err := withSecrets(s, func(tx *bolt.Tx) error {
			if err := tx.Bucket(contentBucket).Put(rowKey(chain, id), []byte("x")); err != nil {
				return err
			}
			return tx.Bucket(noncesBucket).Put(rowKey(chain, id), bytes.Repeat([]byte{2}, 32))
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := export(t, s, ExportSelection{All: true, Disclose: DiscloseListed, DiscloseIDs: []string{id}})
	if !errors.Is(err, ErrDisclosure) || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("err = %v, want ambiguity", err)
	}
}

// Entries a bundle cannot carry: a non-v3 format, a timestamp outside years
// 0001-9999 (year 0: the store cannot even hold one above 9999).
func TestExport_UnrepresentableEntries(t *testing.T) {
	for name, damage := range map[string]func(e *store.Entry){
		"format v2": func(e *store.Entry) { e.FormatVersion = 2 },
		"year 0000": func(e *store.Entry) { e.Timestamp = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := setup(t)
			st, err := boltstore.Open(s.DBPath())
			if err != nil {
				t.Fatal(err)
			}
			rows, err := st.Range(context.Background(), cid(t, s, "u-90"), 0, 1<<62, 0)
			if err == nil {
				damage(&rows[0])
				err = st.WriteBatch(context.Background(), rows[:1])
			}
			st.Close()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := export(t, s, ExportSelection{All: true}); !errors.Is(err, ErrExportUnrepresentable) {
				t.Fatalf("err = %v, want ErrExportUnrepresentable", err)
			}
		})
	}
}

// Errors name chains by position, never by id.
func TestExport_ErrorsNameNoChain(t *testing.T) {
	s, _, _ := setup(t)
	dir := s.anchorDir(cid(t, s, "u-90"))
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := export(t, s, ExportSelection{All: true})
	if err == nil || chainIDInText.MatchString(err.Error()) || !strings.Contains(err.Error(), "chain #") {
		t.Fatalf("err = %v", err)
	}
}
