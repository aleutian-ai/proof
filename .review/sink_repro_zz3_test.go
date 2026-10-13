package sink

import (
	"context"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/linker"
)

func TestZZ_MidErasure(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	chain := cid(t, s, "u-81")
	st, _ := s.openStore(false)
	_, tail, _ := st.ReadTail(ctx, chain)
	rec := erasureRecord(tail)
	l, _ := linker.New(st)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id, _ := newEntryID()
	id2, _ := newEntryID()
	content := []byte(`{"benign":"filler"}`)
	c, nonce, _ := commitment.Salted(content)
	if _, err := l.Append(ctx, chain, []linker.Input{
		{EntryID: id, EntryType: EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: erasureHash(rec)},
		{EntryID: id2, EntryType: EntryTypeEvent, Timestamp: now.Add(time.Microsecond), IngestedAt: now.Add(time.Microsecond), ContentHash: c},
	}); err != nil { t.Fatal(err) }
	st.Close()
	sec, _ := openSecrets(s.secretsPath(), DefaultLockTimeout)
	sec.putAll(map[string]map[string]secret{chain: {id: {content: rec}}})
	if _, err := sec.eraseChain(chain, map[string][]byte{id: rec}); err != nil { t.Fatal(err) }
	sec.putAll(map[string]map[string]secret{chain: {id2: {content: content, nonce: nonce}}})
	sec.Close()
	r, err := s.Verify(ctx, ring)
	t.Logf("verify OK=%v err=%v %+v", r.OK(), err, chainReport(t, r, chain))
	out, err := s.Commit(ctx, events("u-81", 1))
	t.Logf("writer keeps committing: %s err=%v", pattern(out), err)
	done, err := s.Checkpoint(ctx, signer, nil)
	t.Logf("checkpoint %+v %v", done, err)
	r, err = s.Verify(ctx, ring)
	t.Logf("verify OK=%v err=%v %+v", r.OK(), err, chainReport(t, r, chain))
	res, err := s.EraseSubject(ctx, "u-81")
	t.Logf("later real erase: %+v err=%v", res, err)
}
