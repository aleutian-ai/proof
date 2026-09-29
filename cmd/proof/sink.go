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
  proof sink erase      [--dir D] --subject S [--class C]   (or --resume)

A sink is a folder (default ./sink-data) holding one opaque chain per
(class, subject); only a secret index links subjects to chains. See
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
	var class, subjectField, key, subject, eraseClass *string
	var resume *bool
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
		subject = fs.String("subject", "", "the subject to erase (every class, unless --class)")
		eraseClass = fs.String("class", "", "erase only this class of the subject's evidence; the others are kept")
		resume = fs.Bool("resume", false, "only complete erasures an earlier, interrupted call started")
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
	if verb == "erase" && (*subject == "") == !*resume {
		fmt.Fprintln(stderr, "proof sink erase: give --subject, or --resume (not both)")
		return exitUsage
	}
	if verb == "erase" && *resume && *eraseClass != "" {
		fmt.Fprintln(stderr, "proof sink erase: --class applies to --subject, not to --resume")
		return exitUsage
	}
	for name, v := range map[string]*string{"--class": class, "--subject-field": subjectField, "--key": key} {
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
		err = sinkErase(c, s, *subject, *eraseClass, *resume, stdout)
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
//
// Only counts are printed. Which chain holds which subject is the content of
// the secret subject index: printed, it would land in terminals, logs and CI
// output, and re-identify the chain after any erasure.
func sinkCommit(c ctx.Context, s *sink.Sink, class, field string, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), sinkMaxLine)
	chains := map[string]bool{}
	entries, duplicates := 0, 0
	var batch []sink.Record
	lines := 0

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		done, err := s.Commit(c, batch)
		for _, d := range done {
			chains[d.Chain] = true
			entries += d.Entries
			duplicates += d.Duplicates
		}
		batch = batch[:0]
		return err
	}
	defer func() {
		if len(chains) == 0 {
			return
		}
		fmt.Fprintf(out, "committed %s on %s (%s)\n", plural(entries, "entry", "entries"),
			plural(len(chains), "chain", "chains"), plural(duplicates, "duplicate", "duplicates"))
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
	if len(chains) == 0 {
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

// sinkErase erases a subject (every class), one class of a subject's
// evidence, or only completes interrupted erasures. The output says which, so a
// class-scoped erasure is never mistaken for forgetting the subject.
//
// It never prints the subject: a line saying who was erased, and when, is a
// lasting record of exactly what the erasure removes.
func sinkErase(c ctx.Context, s *sink.Sink, subject, class string, resume bool, out io.Writer) error {
	var res sink.SubjectErasure
	var err error
	switch {
	case resume:
		res.Resumed, err = s.ResumeErasures(c)
	case class != "":
		res, err = s.EraseSubjectClass(c, subject, class)
	default:
		res, err = s.EraseSubject(c, subject)
	}
	if len(res.Resumed) > 0 {
		fmt.Fprintf(out, "completed %s an earlier call left unfinished\n",
			plural(len(res.Resumed), "interrupted erasure", "interrupted erasures"))
	}
	var incomplete *sink.ErasureIncompleteError
	if errors.As(err, &incomplete) {
		if len(res.Erased) > 0 {
			fmt.Fprintf(out, "erased %s of the subject's evidence\n", plural(len(res.Erased), "chain", "chains"))
		}
		if incomplete.Forgotten {
			fmt.Fprintln(out, "The subject is removed from the index, but its evidence on the pending chains is "+
				"not yet deleted.")
		}
		return err
	}
	if err != nil {
		return err
	}
	if resume {
		if len(res.Resumed) == 0 {
			fmt.Fprintln(out, "no interrupted erasures")
		}
		return nil
	}
	if len(res.Erased) == 0 {
		fmt.Fprintln(out, "no evidence held for that subject in that scope (never committed, or already erased)")
		return nil
	}
	events, leftovers := 0, 0
	for _, e := range res.Erased {
		events += e.Events
		leftovers += e.Leftovers
	}
	if class != "" {
		fmt.Fprintf(out, "erased the %s evidence of 1 subject: %s, %s.\n"+
			"Only that class: the subject's evidence in any other class is kept.\n",
			class, plural(len(res.Erased), "chain", "chains"), plural(events, "event", "events"))
	} else {
		fmt.Fprintf(out, "erased 1 subject: %s, %s. The subject is forgotten: nothing in this folder\n"+
			"links it to the erased chains any more, and a later event for it starts a new chain.\n",
			plural(len(res.Erased), "chain", "chains"), plural(events, "event", "events"))
	}
	if leftovers > 0 {
		fmt.Fprintf(out, "Also removed %s of commits that never reached a chain.\n",
			plural(leftovers, "leftover", "leftovers"))
	}
	fmt.Fprintf(out, "Content, nonces and source positions are deleted and the files rewritten; every chain still verifies.\n"+
		"Not reached by this: backups or snapshots of %s, SSD blocks, and anyone an event or nonce\n"+
		"was disclosed to.\n", strings.TrimSuffix(s.DBPath(), "evidence.db"))
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
