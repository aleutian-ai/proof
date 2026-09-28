// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package topicsink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/linker"
	bolt "go.etcd.io/bbolt"
)

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

func TestChainFor(t *testing.T) {
	cases := []struct {
		key string
		ok  bool
	}{
		{"u-81", true},
		{"a", true},
		{"orders.eu_west-1", true},
		{"0", true},
		{strings.Repeat("a", 64), true},
		{"", false},
		{strings.Repeat("a", 65), false},
		{"U-81", false},           // not lowercased for you
		{" u-81", false},          // not trimmed for you
		{"jo@example.com", false}, // the case the rule exists for
		{"-a", false},
		{".a", false},
		{"..", false},
		{"a/b", false}, // would escape the content folder
		{"a b", false},
		{"a\x00b", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.key), func(t *testing.T) {
			got, err := ChainFor(c.key)
			if c.ok {
				if err != nil || got != c.key {
					t.Fatalf("ChainFor(%q) = %q, %v; want the key unchanged", c.key, got, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ChainFor(%q) = %q, %v; want ErrInvalidKey", c.key, got, err)
			}
			if c.key != "" && strings.Contains(err.Error(), c.key) {
				t.Fatalf("the error echoes the refused key: %v", err)
			}
		})
	}
}

func TestRecordFromJSON(t *testing.T) {
	line := []byte(`{"user":"u-81","event":"login","n":1}`)
	r, err := RecordFromJSON(line, "user")
	if err != nil || r.Key != "u-81" || string(r.Content) != string(line) {
		t.Fatalf("got %+v, %v", r, err)
	}
	line[2] = 'X' // the record must not alias the caller's buffer
	if r.Content[2] == 'X' {
		t.Fatal("Record.Content aliases the input line")
	}

	for name, in := range map[string]string{
		"missing field":    `{"topic":"a"}`,
		"number field":     `{"user":81}`,
		"null field":       `{"user":null}`,
		"not an object":    `["u-81"]`,
		"not JSON":         `user=u-81`,
		"trailing garbage": `{"user":"u-81"} x`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RecordFromJSON([]byte(in), "user"); err == nil {
				t.Fatalf("RecordFromJSON(%s) succeeded", in)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSigner(t *testing.T) (*anchor.MLDSA65Signer, *anchor.KeyRing) {
	t.Helper()
	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	id, pub, err := anchor.KeyIDOf(s)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	if err != nil {
		t.Fatal(err)
	}
	return s, ring
}

func events(key string, n int) []Record {
	out := make([]Record, n)
	for i := range out {
		out[i] = Record{Key: key, Content: []byte(fmt.Sprintf(`{"user":%q,"i":%d}`, key, i))}
	}
	return out
}

func chainReport(t *testing.T, r Report, chain string) ChainReport {
	t.Helper()
	for _, c := range r.Chains {
		if c.Chain == chain {
			return c
		}
	}
	t.Fatalf("no report for chain %s in %+v", chain, r)
	return ChainReport{}
}

func mustVerify(t *testing.T, s *Sink, keys anchor.KeySource) Report {
	t.Helper()
	r, err := s.Verify(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() {
		t.Fatalf("verify found problems: %+v", r)
	}
	return r
}

// setup commits u-81 ×3, u-82 ×2 and u-90 ×1, interleaved, and checkpoints them.
func setup(t *testing.T) (*Sink, *anchor.MLDSA65Signer, *anchor.KeyRing) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)
	a, b, c := events("u-81", 3), events("u-82", 2), events("u-90", 1)
	batch := []Record{a[0], b[0], a[1], c[0], b[1], a[2]}
	got, err := s.Commit(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	want := []Committed{{"u-81", 3}, {"u-82", 2}, {"u-90", 1}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Commit = %v, want %v (grouped, in order of first appearance)", got, want)
	}
	if _, err := s.Checkpoint(context.Background(), signer); err != nil {
		t.Fatal(err)
	}
	return s, signer, ring
}

func entryIDs(t *testing.T, s *Sink, chain string) []string {
	t.Helper()
	st, err := s.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	es, err := readChain(context.Background(), st, chain)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(es))
	for i, e := range es {
		ids[i] = e.EntryID
	}
	return ids
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)

	// One chain per key, each checkpointed and verified on its own.
	r := mustVerify(t, s, ring)
	if len(r.Chains) != 3 {
		t.Fatalf("want 3 chains, got %+v", r.Chains)
	}
	for chain, n := range map[string]int{"u-81": 3, "u-82": 2, "u-90": 1} {
		c := chainReport(t, r, chain)
		if c.Entries != n || c.Opened != n || c.Checkpoints != 1 || c.Unanchored != 0 {
			t.Errorf("%s: %+v, want %d entries all opened, 1 checkpoint", chain, c, n)
		}
	}

	// Nothing new: no checkpoint written.
	if cp, err := s.Checkpoint(ctx, signer); err != nil || len(cp) != 0 {
		t.Fatalf("second checkpoint with nothing new: %v, %v", cp, err)
	}

	// New entries on one chain: only that chain gets a checkpoint, linked to its first.
	if _, err := s.Commit(ctx, events("u-82", 2)); err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, mustVerify(t, s, ring), "u-82"); c.Unanchored != 2 {
		t.Fatalf("u-82 before its checkpoint: %+v, want 2 unanchored", c)
	}
	cp, err := s.Checkpoint(ctx, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp) != 1 || cp[0].Chain != "u-82" || cp[0].Entries != 4 ||
		cp[0].File != filepath.Join("anchors", "u-82", "0002.json") {
		t.Fatalf("checkpoint = %+v, want only u-82's 0002 over 4 entries", cp)
	}
	mustVerify(t, s, ring)
}

// TestErase is the ticket's erasure criterion: the erased chain still verifies,
// its events cannot be opened, and the other chains are unaffected.
func TestErase(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	before := entryIDs(t, s, "u-81")

	res, err := s.Erase(ctx, "u-81")
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 3 || res.ErasureEntryID == "" {
		t.Fatalf("Erase = %+v", res)
	}

	// Erased items cannot be opened: no nonce and no content, for any of them.
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), lockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range before {
		if _, err := ns.Get("u-81", id); !errors.Is(err, noncestore.ErrNotFound) {
			t.Errorf("nonce for erased %s still stored: %v", id, err)
		}
		if _, err := os.Stat(s.contentPath("u-81", id)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("content for erased %s still on disk: %v", id, err)
		}
	}
	ns.Close()

	// Every chain still verifies, the erased one included, and its old
	// checkpoint still binds.
	r := mustVerify(t, s, ring)
	if c := chainReport(t, r, "u-81"); c.Erased != 3 || c.Opened != 0 || c.Checkpoints != 1 || c.Unanchored != 1 {
		t.Fatalf("u-81 after erase: %+v, want 3 erased, 1 checkpoint, the erasure entry unanchored", c)
	}
	for chain, n := range map[string]int{"u-82": 2, "u-90": 1} {
		if c := chainReport(t, r, chain); c.Opened != n || c.Erased != 0 {
			t.Errorf("%s was affected by erasing u-81: %+v", chain, c)
		}
	}

	// The erasure is checkpointed like any other entry, and the user can come back.
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint(ctx, signer); err != nil {
		t.Fatal(err)
	}
	c := chainReport(t, mustVerify(t, s, ring), "u-81")
	if c.Erased != 3 || c.Opened != 1 || c.Checkpoints != 2 || c.Unanchored != 0 {
		t.Fatalf("u-81 after a new event: %+v", c)
	}

	// Erasing again is safe, and erases only what is left.
	res, err = s.Erase(ctx, "u-81")
	if err != nil || res.Events != 4 {
		t.Fatalf("second erase = %+v, %v", res, err)
	}
	if c := chainReport(t, mustVerify(t, s, ring), "u-81"); c.Erased != 4 || c.Opened != 0 {
		t.Fatalf("u-81 after a second erase: %+v", c)
	}
}

func TestErase_Refusals(t *testing.T) {
	s, _, _ := setup(t)
	if _, err := s.Erase(context.Background(), "jo@example.com"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid chain id: %v", err)
	}
	if _, err := s.Erase(context.Background(), "u-99"); err == nil {
		t.Fatal("erasing a chain with no entries must fail, not record an erasure of nothing")
	}
}

// ---------------------------------------------------------------------------
// What Verify catches
// ---------------------------------------------------------------------------

// TestVerify_Detects: each tamper is reported on the chain it touched, and only
// that chain.
func TestVerify_Detects(t *testing.T) {
	cases := []struct {
		name   string
		chain  string
		tamper func(t *testing.T, s *Sink)
		want   string
	}{
		{"content edited", "u-81", func(t *testing.T, s *Sink) {
			id := entryIDs(t, s, "u-81")[1]
			if err := os.WriteFile(s.contentPath("u-81", id), []byte(`{"user":"u-81","i":99}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "MODIFIED"},
		{"content deleted by hand", "u-81", func(t *testing.T, s *Sink) {
			if err := os.Remove(s.contentPath("u-81", entryIDs(t, s, "u-81")[0])); err != nil {
				t.Fatal(err)
			}
		}, "MISSING"},
		{"nonce deleted by hand", "u-82", func(t *testing.T, s *Sink) {
			ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), lockTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer ns.Close()
			if err := ns.Delete("u-82", entryIDs(t, s, "u-82")[0]); err != nil {
				t.Fatal(err)
			}
		}, "nonce is gone"},
		{"checkpoint moved to another chain", "u-90", func(t *testing.T, s *Sink) {
			raw, err := os.ReadFile(filepath.Join(s.anchorDir("u-82"), "0001.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.anchorDir("u-90"), "0001.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "another chain"},
		{"checkpoint signed by another key", "u-81", func(t *testing.T, s *Sink) {
			other, _ := newSigner(t)
			if err := os.RemoveAll(s.anchorDir("u-81")); err != nil {
				t.Fatal(err)
			}
			// Checkpoint re-signs only chains without one: u-81 alone.
			if _, err := s.Checkpoint(context.Background(), other); err != nil {
				t.Fatal(err)
			}
		}, "checkpoint 0001"},
		{"erasure left content behind", "u-81", func(t *testing.T, s *Sink) {
			id := entryIDs(t, s, "u-81")[0]
			raw, err := os.ReadFile(s.contentPath("u-81", id))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Erase(context.Background(), "u-81"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.contentPath("u-81", id), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "run erase again"},
		{"erasure record edited", "u-81", func(t *testing.T, s *Sink) {
			res, err := s.Erase(context.Background(), "u-81")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.contentPath("u-81", res.ErasureEntryID), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "erasure record"},
		{"entry written by another tool", "u-90", func(t *testing.T, s *Sink) {
			st, err := s.openStore()
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			l, err := linker.New(st)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if _, err := l.Append(context.Background(), "u-90", []linker.Input{{EntryID: "ts-" + strings.Repeat("0", 32),
				EntryType: "mcp.digest", Timestamp: now, IngestedAt: now,
				ContentHash: strings.Repeat("ab", 64)}}); err != nil {
				t.Fatal(err)
			}
		}, "never writes"},
		{"entry id crafted as a path", "u-90", func(t *testing.T, s *Sink) {
			appendRaw(t, s, "u-90", "../../../outside")
		}, "never assigns"},
		{"chain removed from the evidence file", `"u-90"`, func(t *testing.T, s *Sink) {
			raw, err := bolt.Open(s.DBPath(), 0o600, &bolt.Options{Timeout: lockTimeout})
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if err := raw.Update(func(tx *bolt.Tx) error {
				c := tx.Bucket([]byte("entries")).Cursor()
				prefix := []byte("u-90\x00")
				for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Seek(prefix) {
					if err := c.Delete(); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}, "REMOVED"},
		{"content left by an unfinished commit", "u-82", func(t *testing.T, s *Sink) {
			stray := s.contentPath("u-82", "ts-"+strings.Repeat("f", 32))
			if err := os.WriteFile(stray, []byte(`{"user":"u-82"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "matches no entry"},
		{"oversized content", "u-82", func(t *testing.T, s *Sink) {
			id := entryIDs(t, s, "u-82")[0]
			if err := os.WriteFile(s.contentPath("u-82", id), make([]byte, MaxContentBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "over the"},
		{"content replaced by a symlink", "u-82", func(t *testing.T, s *Sink) {
			p := s.contentPath("u-82", entryIDs(t, s, "u-82")[0])
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/hosts", p); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, ring := setup(t)
			c.tamper(t, s)
			r, err := s.Verify(context.Background(), ring)
			if err != nil {
				t.Fatal(err)
			}
			if r.OK() {
				t.Fatalf("verify passed after %s", c.name)
			}
			for _, cr := range r.Chains {
				joined := strings.Join(cr.Problems, "; ")
				if cr.Chain == c.chain && !strings.Contains(joined, c.want) {
					t.Errorf("%s: problems %q do not mention %q", cr.Chain, joined, c.want)
				}
				if cr.Chain != c.chain && len(cr.Problems) > 0 {
					t.Errorf("untouched chain %s reports problems: %q", cr.Chain, joined)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Commit edge cases
// ---------------------------------------------------------------------------

// TestCommit_ValidatesBeforeWriting: one bad record refuses the whole call, and
// no file is created.
func TestCommit_ValidatesBeforeWriting(t *testing.T) {
	good := Record{Key: "u-1", Content: []byte("{}")}
	cases := map[string][]Record{
		"no records":      nil,
		"over the cap":    make([]Record, MaxBatch+1),
		"invalid key":     {good, {Key: "jo@example.com", Content: []byte("{}")}},
		"empty content":   {good, {Key: "u-2"}},
		"content too big": {good, {Key: "u-2", Content: make([]byte, MaxContentBytes+1)}},
	}
	for name, recs := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Commit(context.Background(), recs); err == nil {
				t.Fatal("Commit accepted it")
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatalf("a refused call left files behind: %v", left)
			}
		})
	}
}

func TestCommit_AtTheCap(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), events("u-1", MaxBatch)); err != nil {
		t.Fatalf("exactly MaxBatch records must be accepted: %v", err)
	}
}

// TestCommit_FailedAppendLeavesNothing: content and nonces are written before
// the append. When the append fails they must be removed again.
func TestCommit_FailedAppendLeavesNothing(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Commit(ctx, events("u-1", 3)); err == nil {
		t.Fatal("a cancelled context must fail the append")
	}
	left, err := os.ReadDir(filepath.Join(s.dir, "content", "u-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("content left behind by a failed append: %v", left)
	}
	if ids := entryIDs(t, s, "u-1"); len(ids) != 0 {
		t.Fatalf("entries written by a failed append: %v", ids)
	}
	// Nonce file: the only keys were for this batch, so nothing for u-1 can remain.
	raw, err := bolt.Open(noncestore.PathFor(s.DBPath()), 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	n := 0
	_ = raw.View(func(tx *bolt.Tx) error { n = tx.Bucket([]byte("nonces")).Stats().KeyN; return nil })
	if n != 0 {
		t.Fatalf("%d nonces left behind by a failed append", n)
	}
}

// TestConcurrentCommits: the Sink serialises its own callers, so parallel
// commits all land instead of failing on the file lock.
//
// The file lock is shortened to a microsecond, so a caller that reached the
// file without queueing on the Sink would fail rather than wait it out.
func TestConcurrentCommits(t *testing.T) {
	defer func(d time.Duration) { lockTimeout = d }(lockTimeout)
	lockTimeout = time.Microsecond
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, ring := newSigner(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Commit(context.Background(), events(fmt.Sprintf("u-%d", i%3), 5))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for _, c := range mustVerify(t, s, ring).Chains {
		total += c.Opened
	}
	if total != 40 {
		t.Fatalf("opened %d events, want 40", total)
	}
}

// appendRaw appends an entry with an arbitrary id, as another writer of the
// evidence file could.
func appendRaw(t *testing.T, s *Sink, chain, entryID string) {
	t.Helper()
	st, err := s.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := l.Append(context.Background(), chain, []linker.Input{{EntryID: entryID,
		EntryType: EntryTypeEvent, Timestamp: now, IngestedAt: now,
		ContentHash: strings.Repeat("ab", 64)}}); err != nil {
		t.Fatal(err)
	}
}

// TestCraftedChainID: a chain id read back from a shared evidence file is never
// turned into a path.
func TestCraftedChainID(t *testing.T) {
	s, signer, ring := setup(t)
	appendRaw(t, s, "../escape", "ts-"+strings.Repeat("1", 32))

	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, `"../escape"`); len(c.Problems) == 0 {
		t.Fatalf("crafted chain not reported: %+v", c)
	}
	if _, err := s.Checkpoint(context.Background(), signer); err == nil {
		t.Fatal("Checkpoint must refuse a crafted chain id")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.dir), "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("something was created outside the sink: %v", err)
	}
}

// TestErase_RemovesLeftovers: content and a nonce left by a commit that stopped
// before its append are erased too.
func TestErase_RemovesLeftovers(t *testing.T) {
	s, _, ring := setup(t)
	strayID := "ts-" + strings.Repeat("e", 32)
	if err := os.WriteFile(s.contentPath("u-81", strayID), []byte(`{"user":"u-81"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), lockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.PutBatch("u-81", map[string][]byte{strayID: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	ns.Close()

	if _, err := s.Erase(context.Background(), "u-81"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.contentPath("u-81", strayID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover content survived erasure: %v", err)
	}
	ns, err = noncestore.Open(noncestore.PathFor(s.DBPath()), lockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if _, err := ns.Get("u-81", strayID); !errors.Is(err, noncestore.ErrNotFound) {
		t.Fatalf("leftover nonce survived erasure: %v", err)
	}
	ns.Close()
	mustVerify(t, s, ring)
}

// TestCheckpoint_RefusesUnverifiedSeries: a series that does not verify under
// the signing key is reported, not extended.
func TestCheckpoint_RefusesUnverifiedSeries(t *testing.T) {
	s, _, _ := setup(t)
	if _, err := s.Commit(context.Background(), events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	other, _ := newSigner(t)
	_, err := s.Checkpoint(context.Background(), other)
	if err == nil || !strings.Contains(err.Error(), "do not verify under this key") {
		t.Fatalf("Checkpoint with another key = %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.anchorDir("u-81"), "0002.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a checkpoint was written on top of an unverified series")
	}
}
