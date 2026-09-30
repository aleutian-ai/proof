// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	bbolt "go.etcd.io/bbolt"

	boltstore "github.com/aleutian-ai/proof/store/bolt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// sinkRun runs `proof sink <args>` with stdin.
func sinkRun(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runWithStdin(t, stdin, cmdSink, args...)
}

// sinkKeys writes an ML-DSA-65 key pair the way `proof keygen` does.
func sinkKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, pubRaw, err := anchor.KeyIDOf(s)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	priv, pub = filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(priv, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSink_Usage(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"no verb":                       nil,
		"unknown verb":                  {"append", "--dir", dir},
		"commit, no class":              {"commit", "--dir", dir, "--subject-field", "user"},
		"commit, class and class field": {"commit", "--dir", dir, "--class", "events", "--class-field", "kind", "--subject-field", "user"},
		"commit, class field, no list":  {"commit", "--dir", dir, "--class-field", "kind", "--subject-field", "user"},
		"commit, list, no class field":  {"commit", "--dir", dir, "--class", "events", "--classes", "a", "--subject-field", "user"},
		"commit, class field = subject": {"commit", "--dir", dir, "--class-field", "user", "--classes", "a", "--subject-field", "user"},
		"commit, invalid listed class":  {"commit", "--dir", dir, "--class-field", "kind", "--classes", "a,B c", "--subject-field", "user"},
		"commit, no subject":            {"commit", "--dir", dir, "--class", "events"},
		"checkpoint, no key":            {"checkpoint", "--dir", dir},
		"verify, no key":                {"verify", "--dir", dir},
		"erase, no subject":             {"erase", "--dir", dir},
		"erase, subject + resume":       {"erase", "--dir", dir, "--subject", "u-1", "--resume"},
		"erase, resume + class":         {"erase", "--dir", dir, "--resume", "--class", "payments"},
		"stray argument":                {"erase", "--dir", dir, "--subject", "u-1", "extra"},
		"wrong verb's flag":             {"commit", "--dir", dir, "--chain", "events.00000000000000000000000000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := sinkRun(t, "", args...); code != exitUsage {
				t.Fatalf("exit %d, want %d", code, exitUsage)
			}
		})
	}
	if code, out, _ := sinkRun(t, "", "help"); code != exitOK || !strings.Contains(out, "proof sink commit") {
		t.Fatalf("help: exit %d, %q", code, out)
	}
}

// TestSink_EndToEnd drives every verb the way docs/sink-format.md's walkthrough does.
func TestSink_EndToEnd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, pub := sinkKeys(t)
	events := `{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}

{"user":"u-81","event":"export","rows":120}
`
	code, out, errs := sinkRun(t, events, "commit", "--dir", dir, "--class", "events", "--subject-field", "user")
	if code != exitOK || !strings.Contains(out, "committed 3 entries on 2 chains (0 duplicates)") {
		t.Fatalf("commit: exit %d\n%s%s", code, out, errs)
	}
	noSubjects(t, out+errs)
	if len(contentChains(t, dir)) != 2 {
		t.Fatal("want two opaque chains")
	}
	if code, out, errs = sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK ||
		strings.Count(out, "checkpoint anchors/") != 2 {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", pub); code != exitOK ||
		!strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs = sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-81"); code != exitOK ||
		!strings.Contains(out, "erased 1 subject: 1 chain, 2 events. The subject is forgotten") {
		t.Fatalf("erase: exit %d\n%s%s", code, out, errs)
	}
	noSubjects(t, out+errs)
	code, out, errs = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitOK || !strings.Contains(out, "0 opened, 2 erased") || !strings.Contains(out, "all 2 chains verify") {
		t.Fatalf("verify after erase: exit %d\n%s%s", code, out, errs)
	}
	// u-82's is the chain with an opened event.
	m := regexp.MustCompile(`chain (\S+) +verifies +1 entry: 1 opened`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no chain with one opened event in:\n%s", out)
	}
	c82 := m[1]

	// Tampering: verify exits 1 (a finding, like a broken chain), naming the chain.
	editContent(t, dir, c82, []byte(`{"user":"u-82"}`))
	code, out, _ = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitBroken || !strings.Contains(out, "chain "+c82) || !strings.Contains(out, "MODIFIED") {
		t.Fatalf("verify after tampering: exit %d\n%s", code, out)
	}
}

// TestSink_CommitBadLine names the line, commits nothing from its batch, and
// never echoes a refused key.
func TestSink_CommitBadLine(t *testing.T) {
	for name, line := range map[string]string{
		"email as key": `{"user":"jo@example.com"}`,
		"no key field": `{"topic":"a"}`,
		"not JSON":     `user=u-1`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			code, _, errs := sinkRun(t, `{"user":"u-1"}`+"\n"+line+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user")
			if code != exitIOError || !strings.Contains(errs, "line 2") {
				t.Fatalf("exit %d, stderr %q; want exit %d naming line 2", code, errs, exitIOError)
			}
			if strings.Contains(errs, "jo@example.com") {
				t.Fatalf("stderr echoes the refused key: %q", errs)
			}
			if _, err := os.Stat(filepath.Join(dir, "evidence.db")); !os.IsNotExist(err) {
				t.Fatal("line 1 was committed although its batch had a bad line")
			}
		})
	}
}

// TestSink_CommitBatches: input longer than one batch is committed in full, and
// a later bad line does not hide the batches already committed.
func TestSink_CommitBatches(t *testing.T) {
	var in strings.Builder
	n := sink.MaxBatch*2 + 7
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, `{"user":"u-%d","i":%d}`+"\n", i%2, i)
	}
	code, out, errs := sinkRun(t, in.String(), "commit", "--dir", t.TempDir(), "--class", "events", "--subject-field", "user")
	if code != exitOK || !strings.Contains(out, fmt.Sprintf("committed %d entries on 2 chains", n)) {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}

	in.Reset()
	for i := 0; i < sink.MaxBatch; i++ {
		fmt.Fprintf(&in, `{"user":"u-1","i":%d}`+"\n", i)
	}
	in.WriteString(`{"user":"Not-Valid"}` + "\n")
	code, out, errs = sinkRun(t, in.String(), "commit", "--dir", t.TempDir(), "--class", "events", "--subject-field", "user")
	if code != exitIOError || !strings.Contains(errs, fmt.Sprintf("line %d", sink.MaxBatch+1)) ||
		!strings.Contains(out, fmt.Sprintf("committed %d entries on 1 chain", sink.MaxBatch)) {
		t.Fatalf("later bad line: exit %d\n%s%s", code, out, errs)
	}
}

func TestSink_CheckpointWrongKeyType(t *testing.T) {
	pemBytes, err := keyfile.MarshalPrivateKey(keyfile.XWing, make([]byte, keyfile.XWing.SeedSize()))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "xwing.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := sinkRun(t, "", "checkpoint", "--dir", t.TempDir(), "--key", p)
	if code != exitIOError || !strings.Contains(errs, "ML-DSA-65") {
		t.Fatalf("exit %d, %q", code, errs)
	}
}

// TestSink_BusyAndRefusedExits: a held folder exits 4 (retryable); a chain that
// cannot be checkpointed exits 1 (a finding), and the others are still signed.
func TestSink_BusyAndRefusedExits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, _ := sinkKeys(t)
	code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n"+`{"user":"u-2"}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user")
	if code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	both := contentChains(t, dir)
	c1, c2 := both[0], both[1]
	if code, _, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("checkpoint: %d %s", code, e)
	}
	// u-1 gets a stray file in its checkpoint folder; both get a new event.
	if err := os.WriteFile(filepath.Join(dir, "anchors", c1, "stray.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, e := sinkRun(t, `{"user":"u-1","n":2}`+"\n"+`{"user":"u-2","n":2}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv)
	if code != exitBroken || !strings.Contains(out, "chain "+c1+" NOT checkpointed") ||
		!strings.Contains(out, "anchors/"+c2+"/0002.json") {
		t.Fatalf("exit %d\n%s", code, out)
	}

	holder, err := boltstore.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if code, _, _ := sinkRun(t, `{"user":"u-3"}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitBusy {
		t.Fatalf("commit on a held folder: exit %d, want %d", code, exitBusy)
	}
}

// TestSink_TrustAfterRotation: a new key extends a series signed by the old one
// only when the old public key is passed with --trust.
func TestSink_TrustAfterRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	oldPriv, oldPub := sinkKeys(t)
	newPriv, newPub := sinkKeys(t)
	if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	if code, _, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", oldPriv); code != exitOK {
		t.Fatalf("checkpoint: %d %s", code, e)
	}
	if code, _, e := sinkRun(t, `{"user":"u-1","n":2}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	if code, out, _ := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", newPriv); code != exitBroken ||
		!strings.Contains(out, "NOT checkpointed") {
		t.Fatalf("without --trust: exit %d\n%s", code, out)
	}
	if code, out, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", newPriv, "--trust", oldPub); code != exitOK ||
		!strings.Contains(out, "0002.json") {
		t.Fatalf("with --trust: exit %d\n%s%s", code, out, e)
	}
	_ = newPub
}

// contentChains lists the sink's chains, from the evidence file.
func contentChains(t *testing.T, dir string) []string {
	t.Helper()
	st, err := boltstore.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	chains, err := st.Chains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return chains
}

// editContent replaces the first content row of a chain in the secrets file,
// as someone editing the sink by hand would.
func editContent(t *testing.T, dir, chain string, data []byte) {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(dir, "evidence.db.secrets"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bbolt.Tx) error {
		prefix := append([]byte(chain), 0)
		k, _ := tx.Bucket([]byte("content")).Cursor().Seek(prefix)
		if k == nil || !bytes.HasPrefix(k, prefix) {
			return fmt.Errorf("no content for chain %s", chain)
		}
		return tx.Bucket([]byte("content")).Put(append([]byte(nil), k...), data)
	}); err != nil {
		t.Fatal(err)
	}
}

// stickChain makes a chain unreadable past its tail (an undecodable entry), so
// it cannot be erased.
func stickChain(t *testing.T, dir, chain string) {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(dir, "evidence.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := append(append([]byte(chain), 0), 0, 0, 0, 0, 0, 0, 0, 99)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("entries")).Put(key, []byte("not an entry"))
	}); err != nil {
		t.Fatal(err)
	}
}

// noSubjects fails if CLI output names a subject: which chain holds whom is the
// secret index's content, and who was erased is what erasure removes.
func noSubjects(t *testing.T, out string) {
	t.Helper()
	if regexp.MustCompile(`u-\d`).MatchString(out) {
		t.Fatalf("CLI output names a subject:\n%s", out)
	}
}

// TestSink_EraseScopes: a class-scoped erasure says only that class went;
// a subject erasure says it is forgotten; --resume completes nothing when
// nothing is pending; an unknown subject erases nothing.
func TestSink_EraseScopes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	for _, class := range []string{"payments", "auth"} {
		if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n", "commit", "--dir", dir, "--class", class, "--subject-field", "user"); code != exitOK {
			t.Fatalf("commit %s: %d %s", class, code, e)
		}
	}
	code, out, e := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-1", "--class", "payments")
	if code != exitOK || !strings.Contains(out, "erased the payments evidence of 1 subject: 1 chain, 1 event") ||
		!strings.Contains(out, "any other class is kept") {
		t.Fatalf("class-scoped: exit %d\n%s%s", code, out, e)
	}
	noSubjects(t, out+e)
	code, out, e = sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-1")
	if code != exitOK || !strings.Contains(out, "erased 1 subject: 1 chain, 1 event. The subject is forgotten") {
		t.Fatalf("subject: exit %d\n%s%s", code, out, e)
	}
	noSubjects(t, out+e)
	if code, out, _ = sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-1"); code != exitOK ||
		!strings.Contains(out, "no evidence held") {
		t.Fatalf("again: exit %d\n%s", code, out)
	}
	if code, out, _ = sinkRun(t, "", "erase", "--dir", dir, "--resume"); code != exitOK ||
		!strings.Contains(out, "no interrupted erasures") {
		t.Fatalf("resume: exit %d\n%s", code, out)
	}
}

// TestSink_EraseRefusalNamesNoSubject: a chain that cannot be erased is found
// before the subject is forgotten; the refusal exits 3 and never names the
// subject.
func TestSink_EraseRefusalNamesNoSubject(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	stickChain(t, dir, contentChains(t, dir)[0])
	code, out, e := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-1")
	if code != exitIOError || !strings.Contains(e, "not forgotten") {
		t.Fatalf("exit %d\n%s%s", code, out, e)
	}
	noSubjects(t, out+e)
}

// TestSink_ClassFieldAndShowSubjects: --class-field takes each line's class;
// verify names no subject unless asked, and then warns first; an erased
// subject's chain says so.
func TestSink_ClassFieldAndShowSubjects(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	priv, pub := sinkKeys(t)
	in := `{"kind":"auth","user":"u-1"}
{"kind":"payments","user":"u-1","amount":4}
{"kind":"auth","user":"u-2"}
`
	code, out, e := sinkRun(t, in, "commit", "--dir", dir, "--class-field", "kind", "--classes", "auth,payments",
		"--subject-field", "user")
	if code != exitOK || !strings.Contains(out, "committed 3 entries on 3 chains") {
		t.Fatalf("commit: exit %d\n%s%s", code, out, e)
	}
	classes := map[string]int{}
	for _, c := range contentChains(t, dir) {
		classes[strings.SplitN(c, ".", 2)[0]]++
	}
	if classes["auth"] != 2 || classes["payments"] != 1 {
		t.Fatalf("chains by class = %v; want 2 auth, 1 payments", classes)
	}
	if code, _, e := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("checkpoint: %d %s", code, e)
	}

	code, out, e = sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitOK || !strings.Contains(out, "all 3 chains verify") {
		t.Fatalf("verify: exit %d\n%s%s", code, out, e)
	}
	noSubjects(t, out+e)

	code, out, e = sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--show-subjects")
	if code != exitOK || strings.Count(out, "· subject u-1") != 2 || strings.Count(out, "· subject u-2") != 1 ||
		!strings.Contains(e, "secret-index material") || !strings.HasPrefix(out, "# SECRET") {
		t.Fatalf("verify --show-subjects: exit %d\n%s%s", code, out, e)
	}

	if code, _, e := sinkRun(t, "", "erase", "--dir", dir, "--subject", "u-2"); code != exitOK {
		t.Fatalf("erase: %d %s", code, e)
	}
	code, out, e = sinkRun(t, "", "verify", "--dir", dir, "--key", pub, "--show-subjects")
	if code != exitOK || strings.Count(out, "· subject erased") != 1 || strings.Contains(out, "u-2") {
		t.Fatalf("verify after erase: exit %d\n%s%s", code, out, e)
	}

	// A bad class names the line, never the value.
	for _, bad := range []string{"Jo Smith", "u-3", "refunds"} { // invalid, a pseudonym, not listed
		code, _, e = sinkRun(t, `{"kind":"`+bad+`","user":"u-3"}`+"\n", "commit", "--dir", dir,
			"--class-field", "kind", "--classes", "auth,payments", "--subject-field", "user")
		if code != exitIOError || !strings.Contains(e, "line 1") || strings.Contains(e, bad) {
			t.Fatalf("class %q: exit %d, %q", bad, code, e)
		}
	}
}

// TestSink_VerifyNeverPrintsRawIndexKeys: a malformed index key is shown by
// number only; it could hold a subject.
func TestSink_VerifyNeverPrintsRawIndexKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sink")
	_, pub := sinkKeys(t)
	if code, _, e := sinkRun(t, `{"user":"u-1"}`+"\n", "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: %d %s", code, e)
	}
	db, err := bbolt.Open(filepath.Join(dir, "evidence.db.subjects"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("reverse")).Put([]byte("u-9\x00payments"), []byte("payments\x00u-9"))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	code, out, e := sinkRun(t, "", "verify", "--dir", dir, "--key", pub)
	if code != exitBroken || !strings.Contains(out, "invalid index row #1") {
		t.Fatalf("exit %d\n%s%s", code, out, e)
	}
	noSubjects(t, out+e)
}
