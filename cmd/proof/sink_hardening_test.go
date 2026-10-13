// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/sink"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

var (
	chainIDShape = regexp.MustCompile(`[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}`)
	entryIDShape = regexp.MustCompile(`sink-[0-9a-f]{32}`)
)

// mapsNoChain fails if output of a command that had a subject on its command
// line holds a chain id, an entry id or a checkpoint path: any of them maps the
// subject to its chain.
func mapsNoChain(t *testing.T, out string) {
	t.Helper()
	if chainIDShape.MatchString(out) || entryIDShape.MatchString(out) || strings.Contains(out, "anchors/") {
		t.Fatalf("output maps the subject to a chain:\n%s", out)
	}
}

// newSink commits u-81 (two events) and u-82 (one) and checkpoints them.
func newSink(t *testing.T) (dir, priv, pub string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "sink")
	priv, pub = sinkKeys(t)
	ev := "{\"user\":\"u-81\",\"n\":1}\n{\"user\":\"u-82\",\"n\":2}\n{\"user\":\"u-81\",\"n\":3}\n"
	if code, o, e := sinkRun(t, ev, "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: exit %d\n%s%s", code, o, e)
	}
	if code, o, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, o, e)
	}
	return dir, priv, pub
}

// TestSinkErase_KeyCheckpointsInTheSameRun: `erase --key` erases and then
// checkpoints the erased chains, printing counts only. Erase followed by a
// plain checkpoint no longer covers the erasure: checkpoint cannot tell it from
// one written into the folder.
func TestSinkErase_KeyCheckpointsInTheSameRun(t *testing.T) {
	t.Run("two commands leave it unanchored", func(t *testing.T) {
		dir, priv, pub := newSink(t)
		code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81")
		if code != exitOK || !strings.Contains(errs, "not checkpointed") || !strings.Contains(errs, "--key") {
			t.Fatalf("erase: exit %d\n%s%s", code, out, errs)
		}
		mapsNoChain(t, out+errs)
		code, out, _ = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv)
		if code != exitBroken || !strings.Contains(out, "NOT checkpointed") || !strings.Contains(out, "erase … --key") {
			t.Fatalf("checkpoint over an unconfirmed erasure: exit %d\n%s", code, out)
		}
		code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
		if code != exitOK || !strings.Contains(out, "subject erased (not yet checkpointed)") {
			t.Fatalf("verify: exit %d\n%s", code, out)
		}
	})
	t.Run("one command covers it", func(t *testing.T) {
		dir, priv, pub := newSink(t)
		code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81", "--key", priv)
		if code != exitOK || !strings.Contains(out, "Checkpointed 1 erased chain") {
			t.Fatalf("erase --key: exit %d\n%s%s", code, out, errs)
		}
		mapsNoChain(t, out+errs)
		noSubjects(t, out+errs)
		code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
		if code != exitOK || !strings.Contains(out, "2 checkpoints, 0 unanchored · subject erased\n") {
			t.Fatalf("verify after erase --key: exit %d\n%s", code, out)
		}
	})
	t.Run("a bad key is found before anything is erased", func(t *testing.T) {
		dir, _, pub := newSink(t)
		code, _, _ := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81", "--key", filepath.Join(dir, "no-such-key"))
		if code != exitIOError {
			t.Fatalf("erase with a missing key: exit %d", code)
		}
		if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK || strings.Contains(out, "erased (") {
			t.Fatalf("the subject was erased although the key could not be read:\n%s", out)
		}
	})
	t.Run("resume with a key", func(t *testing.T) {
		dir, priv, pub := newSink(t)
		// An interrupted erasure: the subject forgotten, the chain not yet erased.
		db, err := bbolt.Open(filepath.Join(dir, "evidence.db.subjects"), 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Update(func(tx *bbolt.Tx) error {
			fw, rv := tx.Bucket([]byte("forward")), tx.Bucket([]byte("reverse"))
			k, chain := fw.Cursor().Seek([]byte("u-81\x00"))
			chain = append([]byte(nil), chain...)
			if err := fw.Delete(append([]byte(nil), k...)); err != nil {
				return err
			}
			return rv.Put(chain, []byte("\x00pending-erasure"))
		}); err != nil {
			t.Fatal(err)
		}
		db.Close()
		code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--resume", "--key", priv)
		if code != exitOK || !strings.Contains(out, "completed 1 interrupted erasure") ||
			!strings.Contains(out, "Checkpointed 1 erased chain") {
			t.Fatalf("erase --resume --key: exit %d\n%s%s", code, out, errs)
		}
		mapsNoChain(t, out+errs)
		if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK ||
			!strings.Contains(out, "· subject erased\n") {
			t.Fatalf("verify: exit %d\n%s", code, out)
		}
	})
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{
			{"erase", "--subject", "u-81", "--resume"},
			{"erase", "--subject", "u-81", "--subject-file", "x"},
			{"erase"},
			{"erase", "--subject", "u-81", "--heads", "h.json"},
			{"erase", "--subject", "u-81", "--trust", "k.pem"},
		} {
			if code, _, _ := sinkRun(t, "", args...); code != exitUsage {
				t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
			}
		}
	})
}

// TestSink_SubjectFile: the subject can come from a file, or standard input,
// instead of the command line.
func TestSink_SubjectFile(t *testing.T) {
	dir, priv, pub := newSink(t)
	file := filepath.Join(t.TempDir(), "subject")
	if err := os.WriteFile(file, []byte("u-82\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if code, _, errs := runWithStdin(t, "", func(a []string, o, e *os.File) int { return cmdSinkExport(a, o, e) },
		"--dir", dir, "--subject-file", file, "--out", bundle); code != exitOK || !strings.Contains(errs, "1 chain(s)") {
		t.Fatalf("export --subject-file: exit %d\n%s", code, errs)
	}
	if code, _, _ := runWithStdin(t, "", func(a []string, o, e *os.File) int { return cmdSinkExport(a, o, e) },
		"--dir", dir, "--subject-file", file, "--subject", "u-82", "--out", bundle+"2"); code != exitUsage {
		t.Fatalf("export with both --subject and --subject-file: exit %d", code)
	}
	code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject-file", file, "--key", priv)
	if code != exitOK || !strings.Contains(out, "erased 1 subject: 1 chain, 1 event") {
		t.Fatalf("erase --subject-file: exit %d\n%s%s", code, out, errs)
	}
	noSubjects(t, out+errs)
	// Standard input.
	code, out, errs = sinkRun(t, "u-81\n", "erase", "--dir", dir, "--subject-file", "-", "--key", priv)
	if code != exitOK || !strings.Contains(out, "erased 1 subject: 1 chain, 2 events") {
		t.Fatalf("erase --subject-file -: exit %d\n%s%s", code, out, errs)
	}
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK ||
		strings.Count(out, "· subject erased\n") != 2 {
		t.Fatalf("verify: exit %d\n%s", code, out)
	}
	// A file that is not one subject is refused, and never echoed.
	if err := os.WriteFile(file, []byte("u-1\nu-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject-file", file); code != exitIOError ||
		strings.Contains(errs, "u-1") {
		t.Fatalf("two subjects in the file: exit %d\n%s", code, errs)
	}
}

// TestSinkCommit_SourceMakesARetrySafe: with --source-field or --source-prefix,
// piping the same input twice commits nothing new. Without either it doubled
// the entries.
func TestSinkCommit_SourceMakesARetrySafe(t *testing.T) {
	events := "{\"user\":\"u-81\",\"id\":\"m-1\"}\n{\"user\":\"u-82\",\"id\":7}\n\n{\"user\":\"u-81\",\"id\":\"m-3\"}\n"
	for name, flags := range map[string][]string{
		"source field":  {"--source-field", "id"},
		"source prefix": {"--source-prefix", "events-2026-10-13.jsonl"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "sink")
			args := append([]string{"commit", "--dir", dir, "--class", "events", "--subject-field", "user"}, flags...)
			code, out, errs := sinkRun(t, events, args...)
			if code != exitOK || !strings.Contains(out, "committed 3 entries on 2 chains (0 duplicates)") {
				t.Fatalf("first: exit %d\n%s%s", code, out, errs)
			}
			code, out, errs = sinkRun(t, events, args...)
			if code != exitOK || !strings.Contains(out, "committed 0 entries on 2 chains (3 duplicates)") {
				t.Fatalf("again: exit %d\n%s%s", code, out, errs)
			}
			// The same position with other content is refused by line, and the
			// message repeats neither the source nor the content.
			changed := strings.Replace(events, `"id":"m-3"}`, `"id":"m-3","edited":true}`, 1)
			code, _, errs = sinkRun(t, changed, args...)
			if code != exitIOError || !strings.Contains(errs, "line 4") || !strings.Contains(errs, "already committed") ||
				strings.Contains(errs, "m-3") || strings.Contains(errs, "edited") || strings.Contains(errs, "events-2026") {
				t.Fatalf("changed line: exit %d\n%s", code, errs)
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "sink")
	base := []string{"commit", "--dir", dir, "--class", "events", "--subject-field", "user"}
	for name, flags := range map[string][]string{
		"both":                       {"--source-field", "id", "--source-prefix", "p"},
		"the subject field":          {"--source-field", "user"},
		"a prefix with other things": {"--source-prefix", "a b"},
	} {
		if code, _, _ := sinkRun(t, events, append(append([]string(nil), base...), flags...)...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
	}
	// A line without the source field is refused, not committed without one.
	if code, _, errs := sinkRun(t, "{\"user\":\"u-81\"}\n", append(append([]string(nil), base...), "--source-field", "id")...); code != exitIOError ||
		!strings.Contains(errs, "line 1") {
		t.Fatalf("a line with no source: exit %d\n%s", code, errs)
	}
}

// TestSinkVerify_RequireCheckpoint: with anchors/ removed, verify passed. With
// --require-checkpoint a chain no verified checkpoint covers fails.
func TestSinkVerify_RequireCheckpoint(t *testing.T) {
	dir, _, pub := newSink(t)
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--require-checkpoint"); code != exitOK {
		t.Fatalf("a checkpointed sink: exit %d\n%s", code, out)
	}
	if err := os.RemoveAll(filepath.Join(dir, "anchors")); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK {
		t.Fatalf("without the flag: exit %d\n%s", code, out)
	}
	code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--require-checkpoint")
	if code != exitBroken || !strings.Contains(out, "no verified checkpoint covers this chain") ||
		!strings.Contains(out, "2 of 2 chains FAILED") {
		t.Fatalf("with the flag: exit %d\n%s", code, out)
	}
}

// TestSink_Heads: with --heads, removed checkpoints are noticed by verify, and
// checkpoint does not start the series again.
func TestSink_Heads(t *testing.T) {
	dir, priv, pub := newSink(t)
	heads := filepath.Join(t.TempDir(), "heads.json")
	if code, out, errs := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv, "--heads", heads); code != exitOK {
		t.Fatalf("checkpoint --heads: exit %d\n%s%s", code, out, errs)
	}
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--heads", heads); code != exitOK {
		t.Fatalf("verify --heads: exit %d\n%s", code, out)
	}
	if err := os.RemoveAll(filepath.Join(dir, "anchors")); err != nil {
		t.Fatal(err)
	}
	code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--heads", heads)
	if code != exitBroken || !strings.Contains(out, "cut or restarted") {
		t.Fatalf("verify after removing anchors/: exit %d\n%s", code, out)
	}
	code, out, _ = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv, "--heads", heads)
	if code != exitBroken || strings.Count(out, "NOT checkpointed") != 2 || !strings.Contains(out, "cut or restarted") {
		t.Fatalf("checkpoint after removing anchors/: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "anchors")); err == nil {
		t.Fatal("a new series was started")
	}
	// Inside the sink folder it protects nothing: refused.
	if code, _, errs := sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--heads", filepath.Join(dir, "heads.json")); code != exitIOError ||
		!strings.Contains(errs, "inside the sink folder") {
		t.Fatalf("a heads file inside the folder: exit %d\n%s", code, errs)
	}
}

// TestSinkRepair: a commit that stopped after writing its content and nonce
// leaves rows verify reports for good. repair removes them, and says how many,
// naming no chain.
func TestSinkRepair(t *testing.T) {
	dir, _, pub := newSink(t)
	chain := contentChains(t, dir)[0]
	db, err := bbolt.Open(filepath.Join(dir, "evidence.db.secrets"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := append(append([]byte(chain), 0), []byte("sink-"+strings.Repeat("e", 32))...)
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket([]byte("content")).Put(key, []byte(`{"user":"u-81","left":"over"}`)); err != nil {
			return err
		}
		return tx.Bucket([]byte("nonces")).Put(key, make([]byte, 32))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitBroken ||
		!strings.Contains(out, "matches no entry") {
		t.Fatalf("verify with a leftover row: exit %d\n%s", code, out)
	}
	code, out, errs := sinkRun(t, "", "repair", "--dir", dir)
	if code != exitOK || !strings.Contains(out, "removed 1 content row, 1 nonce, 0 source positions and 0 record signatures") {
		t.Fatalf("repair: exit %d\n%s%s", code, out, errs)
	}
	mapsNoChain(t, out+errs)
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK {
		t.Fatalf("verify after repair: exit %d\n%s", code, out)
	}
	if code, out, _ := sinkRun(t, "", "repair", "--dir", dir); code != exitOK || !strings.Contains(out, "nothing to repair") {
		t.Fatalf("repair again: exit %d\n%s", code, out)
	}
	// The removed content is out of the live file, not in a free page.
	if raw, _ := os.ReadFile(filepath.Join(dir, "evidence.db.secrets")); strings.Contains(string(raw), `"left":"over"`) {
		t.Fatal("the removed content is still in the secrets file")
	}
	if code, _, _ := sinkRun(t, "", "repair", "--dir", filepath.Join(t.TempDir(), "nothing")); code != exitIOError {
		t.Fatalf("repair of a folder that is not a sink: exit %d", code)
	}
}

// TestCorruptStore_EverySinkVerb: on a folder with a damaged file, verify
// exits 1 and every other verb exits 3. None exits 2 (the Go runtime's status
// for a panic, and this command's for a usage error), and none hangs. With
// --skip-check the damage is met inside the operation instead of before it.
func TestCorruptStore_EverySinkVerb(t *testing.T) {
	template, priv, pub := newSink(t)
	bundle := func(t *testing.T) string { return filepath.Join(t.TempDir(), "bundle.json") }
	verbs := map[string]func(t *testing.T, dir string) (string, []string, int){
		"commit": func(t *testing.T, dir string) (string, []string, int) {
			return "{\"user\":\"u-81\"}\n{\"user\":\"u-99\"}\n", []string{"sink", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"}, exitIOError
		},
		"commit --skip-check": func(t *testing.T, dir string) (string, []string, int) {
			return "{\"user\":\"u-81\"}\n{\"user\":\"u-99\"}\n", []string{"sink", "commit", "--dir", dir, "--class", "events", "--subject-field", "user", "--skip-check"}, exitIOError
		},
		"erase": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "erase", "--dir", dir, "--subject", "u-81", "--key", priv}, exitIOError
		},
		"erase --skip-check": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "erase", "--dir", dir, "--subject", "u-81", "--skip-check"}, exitIOError
		},
		"erase --resume": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "erase", "--dir", dir, "--resume", "--skip-check"}, exitIOError
		},
		"repair": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "repair", "--dir", dir}, exitIOError
		},
		"repair --skip-check": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "repair", "--dir", dir, "--skip-check"}, exitIOError
		},
		"checkpoint": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "checkpoint", "--dir", dir, "--key", priv}, exitIOError
		},
		"export": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "export", "--dir", dir, "--all", "--out", bundle(t)}, exitIOError
		},
		"verify": func(t *testing.T, dir string) (string, []string, int) {
			return "", []string{"sink", "verify", "--dir", dir, "--key", pub}, exitBroken
		},
	}
	for _, file := range []string{"evidence.db", "evidence.db.secrets", "evidence.db.subjects"} {
		for name, verb := range verbs {
			t.Run(file+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				for _, f := range []string{"evidence.db", "evidence.db.secrets", "evidence.db.subjects"} {
					raw, err := os.ReadFile(filepath.Join(template, f))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, f), raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				overwritePages(t, filepath.Join(dir, file))
				stdin, args, want := verb(t, dir)
				var code int
				var errOut string
				withStdin(t, stdin, func() { code, _, errOut = runMain(t, args...) })
				if code == exitUsage {
					t.Fatalf("exit 2: a damaged file read as a usage error\n%.600s", errOut)
				}
				if code != want {
					t.Fatalf("exit %d, want %d\n%.600s", code, want, errOut)
				}
			})
		}
	}
}

// TestSinkInit_AnUnsignedSinkIsRefused: init on a sink that already holds
// unsigned records cannot make it sign. It says so and generates nothing,
// instead of printing commands that would then be refused.
func TestSinkInit_AnUnsignedSinkIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	if code, _, e := sinkRun(t, "{\"user\":\"u-81\"}\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: exit %d\n%s", code, e)
	}
	code, _, errs := sinkRun(t, "", "init", "--dir", dir)
	if code != exitUsage || !strings.Contains(errs, "already holds unsigned records") {
		t.Fatalf("init on an unsigned sink: exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(dir + ".keys"); err == nil {
		t.Fatal("keys were generated for a sink that cannot use them")
	}
	if code, _, e := sinkRun(t, "{\"user\":\"u-82\"}\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("the sink no longer commits: exit %d\n%s", code, e)
	}
}

// TestSinkCheckpoint_ConfirmErasedChain: an erasure made without --key on a
// sink that does not sign could never be checkpointed afterwards: every later
// `checkpoint` refused its chain and exited 1, and nothing the refusal named
// did anything. The operator can vouch for the chain by its id, taken from
// verify's output, and is warned what that means.
func TestSinkCheckpoint_ConfirmErasedChain(t *testing.T) {
	dir, priv, pub := newSink(t)
	if code, o, e := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81"); code != exitOK ||
		!strings.Contains(e, "--confirm-erased-chain") {
		t.Fatalf("erase: exit %d\n%s%s", code, o, e)
	}
	// Neither of the commands the refusal used to name does anything now.
	if code, out, _ := sinkRun(t, "", "erase", "--dir", dir, "--resume", "--key", priv); code != exitOK ||
		!strings.Contains(out, "no interrupted erasures") {
		t.Fatalf("erase --resume --key: exit %d\n%s", code, out)
	}
	code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv)
	if code != exitBroken || !strings.Contains(out, "--confirm-erased-chain") {
		t.Fatalf("checkpoint: exit %d\n%s", code, out)
	}
	// The chain id comes from verify, which names no subject.
	_, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	m := regexp.MustCompile(`chain (\S+) .*subject erased \(not yet checkpointed\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("verify shows no erased, uncheckpointed chain:\n%s", out)
	}
	noSubjects(t, out)
	code, out, errs := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv, "--confirm-erased-chain", m[1])
	if code != exitOK || !strings.Contains(out, "signed over 3 entries") || !strings.Contains(errs, "you are vouching") {
		t.Fatalf("checkpoint --confirm-erased-chain: exit %d\n%s%s", code, out, errs)
	}
	if code, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK || !strings.Contains(out, "· subject erased\n") {
		t.Fatalf("verify: exit %d\n%s", code, out)
	}
	// Routine runs are quiet again.
	if code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("a routine checkpoint afterwards: exit %d\n%s", code, out)
	}
	// Vouching for a chain that is not an uncheckpointed erasure: refused.
	live := contentChains(t, dir)
	for _, c := range live {
		if c == m[1] {
			continue
		}
		if code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv, "--confirm-erased-chain", c); code != exitBroken ||
			!strings.Contains(out, "does not end with an erasure") {
			t.Fatalf("vouching for a live chain: exit %d\n%s", code, out)
		}
	}
	if code, _, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv, "--confirm-erased-chain", "../x"); code != exitUsage {
		t.Fatalf("a value that is not a chain id: exit %d", code)
	}
}

// TestSinkErase_SaysWhatToRunWhenItsCheckpointFails: `erase --key` whose
// checkpoint step does not complete says the erasure is done, the checkpoint
// is not, and what to run, without naming a chain.
func TestSinkErase_SaysWhatToRunWhenItsCheckpointFails(t *testing.T) {
	dir, priv, _ := newSink(t)
	other, _ := sinkKeys(t) // the existing checkpoints are not this key's
	code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81", "--key", other)
	if code != exitBroken || !strings.Contains(out, "erased 1 subject") ||
		!strings.Contains(out, "NOT checkpointed: the erasure is done, its checkpoint is not") ||
		!strings.Contains(out, "--confirm-erased-chain") {
		t.Fatalf("erase --key with a key the series is not signed with: exit %d\n%s%s", code, out, errs)
	}
	mapsNoChain(t, out+errs)
	_ = priv
}

// TestSinkErase_DoesNotSignAnErasureItFoundAlreadyThere: a forged erasure on a
// chain whose index row is left alone; the operator's ordinary
// `erase --subject S --key K` then met it. It kept the erasure entry it found,
// and signed it. It now says the chain already ended with an erasure and does
// not checkpoint it.
func TestSinkErase_DoesNotSignAnErasureItFoundAlreadyThere(t *testing.T) {
	dir, priv, pub := newSink(t)
	if code, _, e := sinkRun(t, "{\"user\":\"u-81\"}\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatal(e)
	}
	// Forge: turn u-81's last entry (uncheckpointed) into a genuine-shaped
	// erasure of what precedes it. The entry type is in no hash.
	forgeTailErasure(t, dir)
	code, out, errs := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81", "--key", priv)
	if code != exitOK || !strings.Contains(out, "already ended with an erasure") || strings.Contains(out, "Checkpointed") {
		t.Fatalf("erase --key over a forged erasure: exit %d\n%s%s", code, out, errs)
	}
	mapsNoChain(t, out+errs)
	if _, out, _ := sinkRun(t, "", "verify", "--dir", dir, "--key", pub); !strings.Contains(out, "subject erased (not yet checkpointed)") {
		t.Fatalf("the forged erasure was signed:\n%s", out)
	}
}

// forgeTailErasure appends a well-formed erasure entry to the longest chain of
// a sink (u-81's, in these tests), as anyone who can write the evidence file
// can: the record is fixed and public, and takes no key.
func forgeTailErasure(t *testing.T, dir string) {
	t.Helper()
	c := context.Background()
	st, err := boltstore.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	chains, err := st.Chains(c)
	if err != nil {
		t.Fatal(err)
	}
	victim, tail := "", int64(-1)
	for _, chain := range chains {
		if _, seq, err := st.ReadTail(c, chain); err == nil && seq > tail {
			victim, tail = chain, seq
		}
	}
	record := fmt.Sprintf(`{"erased":"every earlier event on this chain","through_global_seq":"%d"}`, tail)
	sum := sha512.Sum512([]byte("aleutian.sink.erasure.v1:" + record))
	l, err := linker.New(st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := l.Append(c, victim, []linker.Input{{EntryID: "sink-" + strings.Repeat("f", 32),
		EntryType: sink.EntryTypeErasure, Timestamp: now, IngestedAt: now, ContentHash: hex.EncodeToString(sum[:])}}); err != nil {
		t.Fatal(err)
	}
}
