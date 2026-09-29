// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	ctx "context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// sinkMaxLine caps one input line. Longer than a record may be, so an oversized
// record is refused by the sink with its real reason rather than by the scanner.
const sinkMaxLine = 1 << 20

const sinkUsage = `usage:
  proof sink commit     [--dir D] --class NAME --subject-field FIELD   < events.jsonl
  proof sink checkpoint [--dir D] --key <ml-dsa-65 private.pem> [--trust <public.pem>]…
  proof sink verify     [--dir D] --key <ml-dsa-65 public.pem>
  proof sink erase      [--dir D] --chain ID

A sink is a folder (default ./sink-data) holding one chain per key. See
docs/sink-format.md. --trust names earlier signing keys whose checkpoints may
be built on (after a key rotation). Exit: 0 ok · 1 a chain failed verification
or was not checkpointed · 2 usage · 3 error · 4 the folder is busy.`

// cmdSink runs the sink verbs.
//
// Like anchor and keygen, checkpoint takes a private key, so these verbs stay in
// the human CLI and are never exposed over MCP.
//
// Exit codes follow the rest of the CLI: 1 when verification finds a problem or
// a chain could not be checkpointed, 3 when an operation fails, 4 when another
// process holds the folder (retryable), 2 for usage.
func cmdSink(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, sinkUsage)
		return exitUsage
	}
	verb := args[0]
	fs := flag.NewFlagSet("sink "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "the sink folder")
	var class, subjectField, key, chain *string
	var trust multiFlag
	switch verb {
	case "commit":
		class = fs.String("class", "", "the evidence class of every event: payments, auth, events… (never a person)")
		subjectField = fs.String("subject-field", "", "the JSON field whose value is the subject (a pseudonym)")
	case "checkpoint":
		key = fs.String("key", "", "ML-DSA-65 private key (PEM), from `proof keygen --alg ml-dsa-65`")
		fs.Var(&trust, "trust", "an earlier ML-DSA-65 public key (PEM) existing checkpoints may be signed with; repeatable")
	case "verify":
		key = fs.String("key", "", "ML-DSA-65 public key (PEM) the checkpoints are signed with")
	case "erase":
		chain = fs.String("chain", "", "the chain to erase")
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, sinkUsage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "proof sink: unknown verb %q\n\n%s\n", verb, sinkUsage)
		return exitUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "proof sink %s: unexpected argument %q\n", verb, fs.Arg(0))
		return exitUsage
	}
	for name, v := range map[string]*string{"--class": class, "--subject-field": subjectField, "--key": key, "--chain": chain} {
		if v != nil && *v == "" {
			fmt.Fprintf(stderr, "proof sink %s: %s is required\n", verb, name)
			return exitUsage
		}
	}

	s, err := sink.Open(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink: %v\n", err)
		return exitIOError
	}
	c := ctx.Background()
	var failed bool
	switch verb {
	case "commit":
		err = sinkCommit(c, s, *class, *subjectField, os.Stdin, stdout)
	case "checkpoint":
		failed, err = sinkCheckpoint(c, s, *key, trust, stdout)
	case "verify":
		failed, err = sinkVerify(c, s, *key, stdout)
	case "erase":
		err = sinkErase(c, s, *chain, stdout)
	}
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "proof sink %s: %v\n", verb, err)
		if errors.Is(err, sink.ErrBusy) {
			return exitBusy
		}
		return exitIOError
	case failed:
		return exitBroken
	}
	return exitOK
}

// sinkCommit reads JSONL and commits it in batches of sink.MaxBatch.
//
// Every line of a batch is parsed before the batch is committed, so a bad line
// stops the run with the batches before it committed and nothing after. Totals
// are printed however the run ends.
func sinkCommit(c ctx.Context, s *sink.Sink, class, field string, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), sinkMaxLine)
	totals := map[string]int{}
	subjectOf := map[string]string{}
	var order []string
	var batch []sink.Record
	lines := 0

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		done, err := s.Commit(c, batch)
		for _, d := range done {
			if _, seen := totals[d.Chain]; !seen {
				order = append(order, d.Chain)
			}
			totals[d.Chain] += d.Entries
			subjectOf[d.Chain] = d.Subject
		}
		batch = batch[:0]
		return err
	}
	defer func() {
		// The subject is the operator's own input; the chain is where it went.
		// The chain id is opaque: the subject is only in the secret index.
		for _, ch := range order {
			fmt.Fprintf(out, "committed %4d for %s → chain %s\n", totals[ch], subjectOf[ch], ch)
		}
	}()

	for sc.Scan() {
		lines++
		line := sc.Bytes() // committed exactly as it arrived; only blank lines are skipped
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		r, err := sink.RecordFromJSON(line, field)
		if err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
		r.Class = class
		if err := r.Validate(); err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
		batch = append(batch, r)
		if len(batch) == sink.MaxBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("after line %d: %w", lines, err)
	}
	if err := flush(); err != nil {
		return err
	}
	if len(order) == 0 {
		return errors.New("no events on stdin")
	}
	return nil
}

// sinkCheckpoint signs what is new. The bool reports whether any chain was
// refused (a finding: exit 1); the error, an operational failure.
func sinkCheckpoint(c ctx.Context, s *sink.Sink, keyPath string, trust []string, out io.Writer) (bool, error) {
	signer, err := loadSigner(keyPath)
	if err != nil {
		return false, err
	}
	defer signer.Close()
	var trusted anchor.KeySource
	if len(trust) > 0 {
		// The signer's own key is always trusted: its checkpoints must verify
		// the next time this runs.
		keys := map[string][]byte{}
		id, pub, err := anchor.KeyIDOf(signer)
		if err != nil {
			return false, err
		}
		keys[id] = pub
		for _, p := range trust {
			id, pub, err := readPublicKey(p)
			if err != nil {
				return false, err
			}
			keys[id] = pub
		}
		if trusted, err = anchor.NewKeyRing(anchor.TrustProvided, keys); err != nil {
			return false, err
		}
	}
	done, err := s.Checkpoint(c, signer, trusted)
	refused := 0
	for _, d := range done {
		if d.Problem != "" {
			refused++
			fmt.Fprintf(out, "chain %s NOT checkpointed: %s\n", printable(d.Chain), d.Problem)
			continue
		}
		fmt.Fprintf(out, "checkpoint %s signed over %s\n", d.File, plural(int(d.Entries), "entry", "entries"))
	}
	if err != nil {
		return refused > 0, err
	}
	if len(done) == 0 {
		fmt.Fprintln(out, "nothing new since the last checkpoints")
	}
	return refused > 0, nil
}

// readPublicKey reads an ML-DSA-65 public key and its key id.
func readPublicKey(path string) (string, []byte, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	alg, pub, err := keyfile.ParsePublicKey(pem)
	if err != nil {
		return "", nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if alg != keyfile.MLDSA65 {
		return "", nil, fmt.Errorf("%s holds a %s key; checkpoints are signed with ML-DSA-65", path, alg)
	}
	id, err := keyfile.KeyIDHex(alg, pub)
	if err != nil {
		return "", nil, err
	}
	return id, pub, nil
}

// printable quotes a chain id that is not a valid one: it may come from a
// crafted evidence file or a stray folder name, and must not reach a terminal
// raw.
func printable(chain string) string {
	if sink.ValidChainID(chain) {
		return chain
	}
	return fmt.Sprintf("%q", chain)
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// sinkVerify prints one line per chain. The bool reports whether any chain
// failed; the error, whether verification could not run at all.
func sinkVerify(c ctx.Context, s *sink.Sink, keyPath string, out io.Writer) (bool, error) {
	id, pub, err := readPublicKey(keyPath)
	if err != nil {
		return false, err
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	if err != nil {
		return false, err
	}
	rep, err := s.Verify(c, ring)
	if err != nil {
		return false, err
	}
	if len(rep.Chains) == 0 {
		return false, errors.New("the evidence file has no chains")
	}
	bad := 0
	for _, ch := range rep.Chains {
		verdict := "verifies"
		if len(ch.Problems) > 0 {
			verdict = "FAILS"
			bad++
		}
		fmt.Fprintf(out, "chain %-12s %-8s %s: %d opened, %d erased · %s, %d unanchored\n",
			printable(ch.Chain), verdict, plural(ch.Entries, "entry", "entries"), ch.Opened, ch.Erased,
			plural(ch.Checkpoints, "checkpoint", "checkpoints"), ch.Unanchored)
		for _, p := range ch.Problems {
			fmt.Fprintf(out, "    %s\n", p)
		}
	}
	if bad > 0 {
		fmt.Fprintf(out, "%d of %d chains FAILED\n", bad, len(rep.Chains))
		return true, nil
	}
	fmt.Fprintf(out, "all %d chains verify\n", len(rep.Chains))
	return false, nil
}

func sinkErase(c ctx.Context, s *sink.Sink, chain string, out io.Writer) error {
	res, err := s.Erase(c, chain)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "erased %s on chain %s; the erasure is entry %s.\n"+
		"Their content, nonces and source positions are deleted, and the files rewritten: none can be\n"+
		"opened from this folder again, and the chain still verifies.\n"+
		"Not reached by this: backups or snapshots of %s, SSD blocks, anyone an event or nonce was\n"+
		"disclosed to, and the chain id, which stays in the chain, its checkpoints and folder names.\n",
		plural(res.Events, "event", "events"), res.Chain, res.ErasureEntryID,
		strings.TrimSuffix(s.DBPath(), "evidence.db"))
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
