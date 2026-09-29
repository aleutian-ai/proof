// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/internal/noncestore"
	"github.com/aleutian-ai/proof/linker"
	bolt "go.etcd.io/bbolt"
)

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
			ns, err := noncestore.Open(noncestore.PathFor(s.DBPath()), DefaultLockTimeout)
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
			if _, err := s.Checkpoint(context.Background(), other, nil); err != nil {
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
			st, err := s.openStore(false)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			l, err := linker.New(st)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if _, err := l.Append(context.Background(), "u-90", []linker.Input{{EntryID: "sink-" + strings.Repeat("0", 32),
				EntryType: "mcp.digest", Timestamp: now, IngestedAt: now,
				ContentHash: strings.Repeat("ab", 64)}}); err != nil {
				t.Fatal(err)
			}
		}, "never writes"},
		{"entry id crafted as a path", "u-90", func(t *testing.T, s *Sink) {
			appendRaw(t, s, "u-90", "../../../outside")
		}, "never assigns"},
		{"chain removed from the evidence file", "u-90", func(t *testing.T, s *Sink) {
			raw, err := bolt.Open(s.DBPath(), 0o600, &bolt.Options{Timeout: DefaultLockTimeout})
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
			stray := s.contentPath("u-82", "sink-"+strings.Repeat("f", 32))
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

// TestCraftedChainID: a chain id read back from a shared evidence file is never
// turned into a path.
func TestCraftedChainID(t *testing.T) {
	s, signer, ring := setup(t)
	appendRaw(t, s, "../escape", "sink-"+strings.Repeat("1", 32))

	r, err := s.Verify(context.Background(), ring)
	if err != nil {
		t.Fatal(err)
	}
	if c := chainReport(t, r, "../escape"); len(c.Problems) == 0 {
		t.Fatalf("crafted chain not reported: %+v", c)
	}
	done, err := s.Checkpoint(context.Background(), signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if problemFor(done, "../escape") == "" {
		t.Fatalf("Checkpoint did not refuse a crafted chain id: %+v", done)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.dir), "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("something was created outside the sink: %v", err)
	}
}

// TestCheckpoint_RefusesUnverifiedSeries: a series that does not verify under
// the signing key is reported, not extended.
func TestCheckpoint_RefusesUnverifiedSeries(t *testing.T) {
	s, _, _ := setup(t)
	if _, err := s.Commit(context.Background(), events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	other, _ := newSigner(t)
	done, err := s.Checkpoint(context.Background(), other, nil)
	if err != nil || !strings.Contains(problemFor(done, "u-81"), "do not verify under the trusted keys") {
		t.Fatalf("Checkpoint with another key = %+v, %v", done, err)
	}
	if _, err := os.Stat(filepath.Join(s.anchorDir("u-81"), "0002.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a checkpoint was written on top of an unverified series")
	}
}

// ---------------------------------------------------------------------------
// Idempotency by Source
// ---------------------------------------------------------------------------
