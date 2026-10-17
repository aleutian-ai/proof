// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
)

// Checkpoint series: what makes one well formed, and what Checkpoint does when
// a chain's series is not, or was signed by an earlier key.

// A series holds only its numbered checkpoints, without a gap, each within the
// size bound. Verify reports anything else, and Checkpoint adds nothing to it.
func TestAnchors_StrayFileAndGap(t *testing.T) {
	for name, tamper := range map[string]func(dir string) error{
		"stray file": func(dir string) error { return os.WriteFile(filepath.Join(dir, "notes.json"), []byte("{}"), 0o644) },
		"gap": func(dir string) error {
			return os.Rename(filepath.Join(dir, "0001.json"), filepath.Join(dir, "0002.json"))
		},
		"oversized": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "0001.json"), make([]byte, maxAnchorBytes+1), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, signer, ring := setup(t)
			if err := tamper(s.anchorDir(cid(t, s, "u-81"))); err != nil {
				t.Fatal(err)
			}
			if p := problems(t, s, ring, cid(t, s, "u-81")); p == "" {
				t.Fatal("Verify accepted the malformed series")
			}
			if _, err := s.Commit(context.Background(), events("u-81", 1)); err != nil {
				t.Fatal(err)
			}
			done, err := s.Checkpoint(context.Background(), signer, nil, UntrackedHeads())
			if err != nil {
				t.Fatal(err)
			}
			if problemFor(done, cid(t, s, "u-81")) == "" {
				t.Fatalf("Checkpoint added to a malformed series: %+v", done)
			}
		})
	}
}

// A series must grow, and each checkpoint names its predecessor.
func TestCheckpointSeriesMustGrowAndLink(t *testing.T) {
	// Each case breaks exactly one rule; the other checks all pass.
	cases := map[string]struct {
		grow   bool // commit a new entry first, so the successor covers more
		mutate func(next *anchor.Anchor)
	}{
		"does not grow": {grow: false, mutate: func(*anchor.Anchor) {}},
		"wrong predecessor id": {grow: true, mutate: func(next *anchor.Anchor) {
			next.PreviousAnchorID = "anchor_11111111-1111-1111-1111-111111111111"
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, signer, ring := setup(t)
			if c.grow {
				if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
					t.Fatal(err)
				}
			}
			f, err := s.openFolder(false)
			if err != nil {
				t.Fatal(err)
			}
			series, _, err := f.readAnchors(cid(t, s, "u-81"))
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			st, err := s.openStore(true)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := readChain(ctx, st, cid(t, s, "u-81"))
			st.Close()
			if err != nil {
				t.Fatal(err)
			}
			prev := series[0]
			// A valid, signed successor over the SAME entries: the chain and
			// signature checks pass; only the series rules can object.
			next, err := build.Anchor(ctx, build.Input{Subject: cid(t, s, "u-81"), Entries: entries, Previous: &prev})
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(&next)
			signed, err := anchor.SignAnchor(ctx, signer, next)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.MarshalIndent(signed, "", "  ")
			if err := os.WriteFile(filepath.Join(s.anchorDir(cid(t, s, "u-81")), "0002.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if p := problems(t, s, ring, cid(t, s, "u-81")); !strings.Contains(p, "checkpoint 0002") {
				t.Fatalf("Verify accepted it: %q", p)
			}
		})
	}
}

// One chain that cannot be checkpointed does not stop the others.
func TestCheckpoint_ContinuesPastABadChain(t *testing.T) {
	ctx := context.Background()
	s, signer, _ := setup(t)
	// u-81 (first in order) gets a malformed series; u-82 and u-90 get new entries.
	if err := os.WriteFile(filepath.Join(s.anchorDir(cid(t, s, "u-81")), "stray.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"u-81", "u-82", "u-90"} {
		if _, err := s.Commit(ctx, events(c, 1)); err != nil {
			t.Fatal(err)
		}
	}
	done, err := s.Checkpoint(ctx, signer, nil, UntrackedHeads())
	if err != nil {
		t.Fatal(err)
	}
	if problemFor(done, cid(t, s, "u-81")) == "" {
		t.Fatalf("the bad chain was not reported: %+v", done)
	}
	for _, c := range []string{"u-82", "u-90"} {
		if _, err := os.Stat(filepath.Join(s.anchorDir(cid(t, s, c)), "0002.json")); err != nil {
			t.Fatalf("%s was not checkpointed after a bad chain before it: %v", c, err)
		}
	}
}

// After a key rotation, the new key checkpoints on top of a series signed by
// the old one, when the old key is trusted; and verify accepts both.
func TestCheckpoint_KeyRotation(t *testing.T) {
	ctx := context.Background()
	s, oldSigner, _ := setup(t)
	newSigner, _ := newSigner(t)
	ring := func(signers ...*anchor.MLDSA65Signer) anchor.KeySource {
		keys := map[string][]byte{}
		for _, sg := range signers {
			id, pub, err := anchor.KeyIDOf(sg)
			if err != nil {
				t.Fatal(err)
			}
			keys[id] = pub
		}
		r, err := anchor.NewKeyRing(anchor.TrustProvided, keys)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil {
		t.Fatal(err)
	}
	// Without trusting the old key: refused, as a problem, not an error.
	done, err := s.Checkpoint(ctx, newSigner, nil, UntrackedHeads())
	if err != nil || problemFor(done, cid(t, s, "u-81")) == "" {
		t.Fatalf("new key alone: %+v, %v", done, err)
	}
	// Trusting both: the new key signs 0002 on top of the old key's 0001.
	both := ring(oldSigner, newSigner)
	done, err = s.Checkpoint(ctx, newSigner, both, UntrackedHeads())
	if err != nil || problemFor(done, cid(t, s, "u-81")) != "" {
		t.Fatalf("rotation: %+v, %v", done, err)
	}
	if c := chainReport(t, mustVerify(t, s, both), cid(t, s, "u-81")); c.Checkpoints != 2 {
		t.Fatalf("after rotation: %+v", c)
	}
}

// TestCheckpoint_HeadsAreRequired: a checkpoint without a record of its
// series heads is refused, unless the caller has said, by name, that it
// gives that up (docs/decisions.md D23).
func TestCheckpoint_HeadsAreRequired(t *testing.T) {
	ctx := context.Background()
	s, signer, _ := setup(t)
	if _, err := s.Checkpoint(ctx, signer, nil); !errors.Is(err, ErrHeadsRequired) {
		t.Fatalf("no heads: %v, want ErrHeadsRequired", err)
	}
	heads := NewFileHeads(filepath.Join(t.TempDir(), "heads.json"))
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(heads), UntrackedHeads()); err == nil {
		t.Fatal("accepted heads and no heads at once")
	}
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(heads)); err != nil {
		t.Fatal(err)
	}
}
