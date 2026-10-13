package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
)

// forged erasure, then the operator's routine checkpoint launders it
func TestZZ_ForgedErasureLaundered(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	// attacker: append keyless erasure entry
	st, err := s.openStore(false)
	if err != nil { t.Fatal(err) }
	_, tail, _ := st.ReadTail(ctx, chain)
	rec := erasureRecord(tail)
	l, _ := linker.New(st)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id, _ := newEntryID()
	if _, err := l.Append(ctx, chain, []linker.Input{{EntryID: id, EntryType: EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: erasureHash(rec)}}); err != nil { t.Fatal(err) }
	st.Close()
	sec, _ := openSecrets(s.secretsPath(), DefaultLockTimeout)
	if err := sec.putAll(map[string]map[string]secret{chain: {id: {content: rec}}}); err != nil { t.Fatal(err) }
	if _, err := sec.eraseChain(chain, map[string][]byte{id: rec}); err != nil { t.Fatal(err) }
	sec.Close()
	subj, _ := openSubjects(s.subjectsPath(), DefaultLockTimeout)
	ch, err := subj.forget("u-81", "")
	if err != nil { t.Fatal(err) }
	for _, c := range ch { subj.clear(c) }
	subj.Close()

	r, err := s.Verify(ctx, ring)
	t.Logf("after forged erasure: OK=%v err=%v report=%+v", r.OK(), err, chainReport(t, r, chain))
	done, err := s.Checkpoint(ctx, signer, nil)
	t.Logf("checkpoint: %+v err=%v", done, err)
	r, err = s.Verify(ctx, ring)
	t.Logf("after routine checkpoint: OK=%v err=%v report=%+v", r.OK(), err, chainReport(t, r, chain))
}

// sources file poisoning: future records silently dropped as duplicates
func TestZZ_SourcePoison(t *testing.T) {
	ctx := context.Background()
	s, _, ring := setup(t)
	chain := cid(t, s, "u-81")
	ids := entryIDs(t, s, chain)
	src, err := openSources(s.sourcesPath(), DefaultLockTimeout)
	if err != nil { t.Fatal(err) }
	pos := map[string]position{}
	for i := 100; i < 110; i++ {
		pos["EVIDENCE:"+string(rune('0'+i-100))] = position{entryID: ids[0], seq: 0}
	}
	if err := src.putBatch(chain, pos); err != nil { t.Fatal(err) }
	src.Close()
	recs := events("u-81", 3)
	for i := range recs { recs[i].Source = "EVIDENCE:" + string(rune('0'+i)); recs[i].Content = []byte(`{"new":"fraud event"}`) }
	out, err := s.Commit(ctx, recs)
	t.Logf("commit outcomes=%s err=%v entries now=%d", pattern(out), err, len(entryIDs(t, s, chain)))
	r, err := s.Verify(ctx, ring)
	t.Logf("verify OK=%v err=%v %+v", r.OK(), err, chainReport(t, r, chain))
}

// anchors removed -> checkpoint starts a new series at 0001 without complaint
func TestZZ_AnchorsDeletedResigned(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	os.RemoveAll(filepath.Join(s.dir, "anchors", chain))
	// need a new entry? no: no anchors -> previous nil -> signs
	done, err := s.Checkpoint(ctx, signer, nil)
	t.Logf("checkpoint: %+v err=%v", done, err)
	r, _ := s.Verify(ctx, ring)
	t.Logf("verify OK=%v %+v", r.OK(), chainReport(t, r, chain))
}

func TestZZ_EmptyCheckpointFile(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil { t.Fatal(err) }
	// simulate power loss: 0002.json exists, zero length
	os.WriteFile(filepath.Join(s.dir, "anchors", chain, "0002.json"), nil, 0o644)
	r, err := s.Verify(ctx, ring)
	t.Logf("verify OK=%v err=%v %+v", r.OK(), err, chainReport(t, r, chain).Problems)
	done, err := s.Checkpoint(ctx, signer, nil)
	t.Logf("checkpoint: %+v err=%v", done, err)
	var buf bytes.Buffer
	_, err = s.Export(ctx, ExportSelection{Chains: []string{chain}}, &buf)
	t.Logf("export err=%v len=%d tail=%s", err, buf.Len(), buf.Bytes()[max(0, buf.Len()-60):])
}

func TestZZ_ExportShape(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	chain := cid(t, s, "u-81")
	var buf bytes.Buffer
	if _, err := s.Export(ctx, ExportSelection{Chains: []string{chain}, Disclose: DiscloseAll}, &buf); err != nil { t.Fatal(err) }
	var b struct{ Chains []struct{ Entries []map[string]any; Checkpoints []string } }
	json.Unmarshal(buf.Bytes(), &b)
	t.Logf("entry0=%v", b.Chains[0].Entries[0])
	t.Logf("checkpoint=%s", b.Chains[0].Checkpoints[0])
	// tamper content then export with disclosure: is the modification exported silently?
	ids := entryIDs(t, s, chain)
	writeContent(s, chain, ids[0], []byte("tampered"))
	buf.Reset()
	sum, err := s.Export(ctx, ExportSelection{Chains: []string{chain}, Disclose: DiscloseAll}, &buf)
	t.Logf("export of modified content: err=%v sum=%+v", err, sum)
	writeContent(s, chain, ids[0], []byte{})
	buf.Reset()
	sum, err = s.Export(ctx, ExportSelection{Chains: []string{chain}, Disclose: DiscloseAll}, &buf)
	t.Logf("export of empty content: err=%v sum=%+v", err, sum)
}

func TestZZ_StageSkip(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{".secrets", ".subjects", ".signatures", ".sources"} {
		s, _, ring := setup(t)
		p := s.DBPath() + name
		os.Remove(p)
		db, err := bolt.Open(p, 0o600, nil)
		if err != nil { t.Fatal(err) }
		db.Close()
		r, err := s.Verify(ctx, ring)
		t.Logf("%s empty bbolt: OK=%v err=%v recsig=%q", name, r.OK(), err, r.RecordSignatures)
	}
}
