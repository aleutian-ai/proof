// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// bundleResult is the §9 result, as far as these tests read it.
type bundleResult struct {
	Result          string `json:"result"`
	Readable        bool   `json:"readable"`
	Reason          string `json:"reason"`
	CheckpointTrust string `json:"checkpoint_trust"`
	RecordTrust     string `json:"record_trust"`
	Verdict         string `json:"verdict"`
	Chains          map[string]struct {
		Verdict string `json:"verdict"`
		Counts  struct {
			Entries       int `json:"entries"`
			Opened        int `json:"opened"`
			Authenticated int `json:"authenticated"`
		} `json:"counts"`
		Problems []struct {
			Code  string `json:"code"`
			Count int    `json:"count"`
			First *int   `json:"first"`
		} `json:"problems"`
	} `json:"chains"`
}

// runVerifyBundle runs `proof sink verify-bundle` in this process.
func runVerifyBundle(args ...string) (code int, stdout, stderr string) {
	var out, errs bytes.Buffer
	code = cmdSinkVerifyBundle(args, &out, &errs)
	return code, out.String(), errs.String()
}

// decodeBundleResult reads --json output, which must be one JSON value.
func decodeBundleResult(t *testing.T, out string) bundleResult {
	t.Helper()
	var res bundleResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("--json output is not one JSON value: %v\n%.300s", err, out)
	}
	if res.Result != "aleutian.proof.bundle-result.v1" {
		t.Fatalf("result id %q", res.Result)
	}
	return res
}

// exportedBundle makes a real sink through the CLI (commit, checkpoint),
// exports all of it with every event disclosed, and returns the bundle's path
// and the checkpoint public key's.
func exportedBundle(t *testing.T) (bundle, pub string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sink")
	priv, pub := sinkKeys(t)
	events := `{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}
{"user":"u-81","event":"export","rows":120}
`
	if code, out, errs := sinkRun(t, events, "commit", "--dir", dir, "--class", "events", "--subject-field", "user"); code != exitOK {
		t.Fatalf("commit: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs := sinkRun(t, "", "checkpoint", "--dir", dir, "--key", priv); code != exitOK {
		t.Fatalf("checkpoint: exit %d\n%s%s", code, out, errs)
	}
	bundle = filepath.Join(t.TempDir(), "bundle.json")
	if code, msg := runExport("--dir", dir, "--all", "--disclose", "all", "--out", bundle); code != exitOK {
		t.Fatalf("export: exit %d\n%s", code, msg)
	}
	return bundle, pub
}

// A bundle exported from a real sink verifies: OK under the checkpoint key,
// UNAUTHENTICATED without one, and FAILED with `modified` once a disclosed
// event's content is changed.
func TestSinkVerifyBundle_EndToEnd(t *testing.T) {
	bundle, pub := exportedBundle(t)

	code, out, errs := runVerifyBundle(bundle, "--key", pub)
	if code != 0 || errs != "" {
		t.Fatalf("with the key: exit %d\n%s%s", code, out, errs)
	}
	for _, want := range []string{"verdict: OK\n", "checkpoint trust: checked", "record trust: not checked",
		"the bundle writer's own implementation", "not an independent one", "Limits (docs/bundle-format.md §1)",
		"does not show", "historical artifact"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output lacks %q:\n%s", want, out)
		}
	}
	noSubjects(t, out)

	// The same through the real dispatch, flags before the file, as JSON.
	code, out, errs = capture(t, "sink", "verify-bundle", "--json", "--key", pub, bundle)
	if code != 0 || errs != "" {
		t.Fatalf("--json through run: exit %d\n%s%s", code, out, errs)
	}
	res := decodeBundleResult(t, out)
	if !res.Readable || res.Verdict != "ok" || res.CheckpointTrust != "checked" || res.RecordTrust != "not_checked" ||
		len(res.Chains) != 2 {
		t.Fatalf("result %+v", res)
	}
	entries, opened := 0, 0
	for id, c := range res.Chains {
		if c.Verdict != "ok" || len(c.Problems) != 0 || c.Counts.Authenticated != c.Counts.Entries {
			t.Fatalf("chain %s: %+v", id, c)
		}
		entries += c.Counts.Entries
		opened += c.Counts.Opened
	}
	if entries != 3 || opened != 3 {
		t.Fatalf("%d entries, %d opened, want 3 and 3", entries, opened)
	}

	// No key: consistent, and its provenance not established.
	code, out, _ = runVerifyBundle(bundle)
	if code != 4 || !strings.Contains(out, "verdict: UNAUTHENTICATED\n") || !strings.Contains(out, "checkpoint trust: not checked") {
		t.Fatalf("without a key: exit %d\n%s", code, out)
	}

	// A key that signed nothing here: the checkpoints are by an unknown key.
	_, stranger := sinkKeys(t)
	code, out, _ = runVerifyBundle(bundle, "--key", stranger)
	if code != 1 || !strings.Contains(out, "checkpoint-unknown-key") {
		t.Fatalf("with another key: exit %d\n%s", code, out)
	}

	// The same key for both roles is allowed, with a warning; the sink does
	// not sign records, so record trust then fails every entry as unsigned.
	code, out, errs = runVerifyBundle(bundle, "--key", pub, "--record-trust", pub)
	if code != 1 || !strings.Contains(errs, "one compromise forges both") || !strings.Contains(out, "unsigned (count") {
		t.Fatalf("one key for both roles: exit %d\n%s%s", code, out, errs)
	}

	// Change one disclosed event's content.
	text, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	content := regexp.MustCompile(`"content":"[A-Za-z0-9+/=]+"`)
	if len(content.FindAll(text, -1)) != 3 {
		t.Fatalf("want 3 disclosed events in the bundle, found %d", len(content.FindAll(text, -1)))
	}
	replaced := false
	tampered := content.ReplaceAllFunc(text, func(m []byte) []byte {
		if replaced {
			return m
		}
		replaced = true
		return []byte(`"content":"` + base64.StdEncoding.EncodeToString([]byte(`{"user":"u-81","event":"logout"}`)) + `"`)
	})
	tamperedPath := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runVerifyBundle(tamperedPath, "--key", pub)
	if code != 1 || !strings.Contains(out, "verdict: FAILED\n") || !strings.Contains(out, "problems: modified (count 1, first at index") {
		t.Fatalf("tampered content: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "logout") {
		t.Fatalf("the output prints disclosed content:\n%s", out)
	}
	code, out, _ = runVerifyBundle("--json", tamperedPath, "--key", pub)
	res = decodeBundleResult(t, out)
	modified := 0
	for _, c := range res.Chains {
		for _, p := range c.Problems {
			if p.Code != "modified" || p.Count != 1 || p.First == nil || c.Verdict != "failed" {
				t.Fatalf("problem %+v on a %s chain", p, c.Verdict)
			}
			modified++
		}
	}
	if code != 1 || res.Verdict != "failed" || modified != 1 {
		t.Fatalf("tampered content as JSON: exit %d, verdict %q, %d modified", code, res.Verdict, modified)
	}
}

// Exit 2 is the caller's mistake: arguments, or a bundle or key file that is
// missing, not a file, or not a key. Exit 3 is a bundle that cannot be read.
func TestSinkVerifyBundle_UsageAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	_, pub := sinkKeys(t)
	priv, _ := sinkKeys(t)
	empty := write("empty.json", `{"format":"aleutian.proof.bundle.v1","chains":[]}`)
	pubText, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no bundle":             {[]string{"--key", pub}, 2, "exactly one bundle file"},
		"two bundles":           {[]string{empty, "--key", pub, empty}, 2, "exactly one bundle file"},
		"unknown flag":          {[]string{empty, "--checkpoint-key", pub}, 2, "flag provided but not defined"},
		"missing bundle":        {[]string{filepath.Join(dir, "absent.json")}, 2, "no such file"},
		"bundle is a directory": {[]string{dir}, 2, "not a regular file"},
		"missing key":           {[]string{empty, "--key", filepath.Join(dir, "absent.pem")}, 2, "no such file"},
		"key is a directory":    {[]string{empty, "--record-trust", dir}, 2, "not a regular file"},
		"key is a private key":  {[]string{empty, "--key", priv}, 2, "not an ML-DSA-65 public key file"},
		"key is not PEM":        {[]string{empty, "--record-trust", empty}, 2, "not an ML-DSA-65 public key file"},
		"key with text after":   {[]string{empty, "--key", write("extra.pem", string(pubText)+"x\n")}, 2, "only whitespace around it"},
		"key over 16 KiB":       {[]string{empty, "--key", write("big.pem", string(pubText)+strings.Repeat("\n", 16<<10))}, 2, "over 16384 bytes"},
		"empty bundle, a key":   {[]string{empty, "--key", pub}, 4, ""},
		"empty file":            {[]string{write("zero.json", "")}, 3, ""},
		"cut bundle":            {[]string{write("cut.json", `{"format":"aleutian.proof.bundle.v1","chains":[`)}, 3, ""},
		"an entries array":      {[]string{write("entries.json", `[{"entry_id":"e"}]`)}, 3, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runVerifyBundle(c.args...)
			if code != c.code || !strings.Contains(errs, c.want) {
				t.Fatalf("exit %d, want %d; stderr lacks %q:\n%s%s", code, c.code, c.want, out, errs)
			}
			if c.code == 2 && out != "" {
				t.Fatalf("a usage error wrote to stdout: %s", out)
			}
		})
	}

	// An unreadable bundle: the reason, which key sets were given, and as
	// JSON exactly the three members of §9.1.
	dup := write("dup.json", `{"format":"aleutian.proof.bundle.v1","chains":[],"chains":[],"secret-member":"secret-value"}`)
	code, out, errs := runVerifyBundle(dup, "--key", pub)
	if code != 3 || errs != "" || !strings.Contains(out, "UNREADABLE: duplicate-key\n") ||
		!strings.Contains(out, "checkpoint keys: given; record keys: none given") ||
		!strings.Contains(out, "Limits (docs/bundle-format.md §1)") || strings.Contains(out, "secret") {
		t.Fatalf("unreadable: exit %d\n%s%s", code, out, errs)
	}
	code, out, _ = runVerifyBundle(dup, "--json")
	if code != 3 || strings.Join(strings.Fields(out), "") != `{"result":"aleutian.proof.bundle-result.v1","readable":false,"reason":"duplicate-key"}` {
		t.Fatalf("unreadable as JSON: exit %d\n%s", code, out)
	}

	// The verb is listed, and has its own help.
	if code, _, errs := sinkRun(t, "", "nonsense"); code != exitUsage || !strings.Contains(errs, "proof sink verify-bundle <bundle.json>") {
		t.Fatalf("the sink usage does not list verify-bundle: exit %d\n%s", code, errs)
	}
	if code, _, errs := runVerifyBundle("-h"); code != 2 || !strings.Contains(errs, "5 an internal error") {
		t.Fatalf("-h: exit %d\n%s", code, errs)
	}
}

// --json output larger than a pipe's buffer arrives whole. The reader starts
// late, so the writer must block and resume: output cut at the buffer's size
// (64 KiB) would not parse.
func TestSinkVerifyBundle_LargeJSONThroughAPipe(t *testing.T) {
	const chains = 600
	var b strings.Builder
	b.WriteString(`{"format":"aleutian.proof.bundle.v1","chains":[`)
	for i := 0; i < chains; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"chain_id":"events.%032x","entries":[{"entry_id":"","entry_type":"","global_seq":"",`+
			`"previous_hash":"","timestamp":"","content_hash":"","chain_hash":""}],"checkpoints":[]}`, i)
	}
	b.WriteString(`]}`)
	bundle := filepath.Join(t.TempDir(), "many.json")
	if err := os.WriteFile(bundle, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan []byte, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		out, _ := io.ReadAll(r)
		read <- out
	}()
	var errs bytes.Buffer
	code := cmdSinkVerifyBundle([]string{bundle, "--json"}, w, &errs)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-read
	r.Close()
	if code != 1 || errs.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if len(out) <= 64<<10 {
		t.Fatalf("the output is %d bytes: too small to test a pipe's buffer", len(out))
	}
	res := decodeBundleResult(t, string(out))
	if !bytes.HasSuffix(out, []byte("}\n")) || len(res.Chains) != chains || res.Verdict != "failed" {
		t.Fatalf("the output is cut: %d bytes, %d chains of %d", len(out), len(res.Chains), chains)
	}
	for id, c := range res.Chains {
		if len(c.Problems) != 1 || c.Problems[0].Code != "field-shape" {
			t.Fatalf("chain %s: %+v", id, c.Problems)
		}
	}

	// A reader that has gone away is an error, not a silent partial result.
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	errs.Reset()
	if code := cmdSinkVerifyBundle([]string{bundle, "--json"}, w, &errs); code != 5 || !strings.Contains(errs.String(), "writing the result") {
		t.Fatalf("a closed pipe: exit %d: %s", code, errs.String())
	}
	w.Close()
}
