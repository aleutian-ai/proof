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
  proof sink init       [--dir D] [--keys-dir K] [--op-vault VAULT] [--one-key] [--force]
  proof sink commit     [--dir D] (--class NAME | --class-field FIELD --classes A,B…) --subject-field FIELD
                        [--record-key <record private.pem>]  < events.jsonl
  proof sink checkpoint [--dir D] --key <ml-dsa-65 private.pem> [--trust <public.pem>]…
  proof sink verify     [--dir D] --key <ml-dsa-65 public.pem> [--record-trust <record public.pem>]… [--show-subjects]
  proof sink erase      [--dir D] --subject S [--class C]   (or --resume)   [--record-key <record private.pem>]
  proof sink export     [--dir D] (--chain C… | --subject S [--class K] | --all)
                        [--disclose none|all|<entry id>,…] --out bundle.json

A sink is a folder (default ./sink-data) holding one opaque chain per
(class, subject); only a secret index links subjects to chains. See
docs/sink-format.md. --trust names earlier signing keys whose checkpoints may
be built on (after a key rotation). --record-key signs every record written
(a sink signs from its first commit, or never); --record-trust checks every
record's signature (repeatable, for rotated keys). Keep the record key and the
checkpoint key separate: init makes both, beside the sink folder. Exit: 0 ok · 1 a chain failed verification or was not
checkpointed · 2 usage, or a record key given or missing against the sink's
signing · 3 error · 4 the folder is busy.`

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
	if verb == "init" {
		return cmdSinkInit(args[1:], stdout, stderr)
	}
	if verb == "export" {
		return cmdSinkExport(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("sink "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "the sink folder")
	var class, classField, classes, subjectField, key, subject, eraseClass, recordKey *string
	var resume, showSubjects *bool
	var trust, recordTrust multiFlag
	switch verb {
	case "commit":
		class = fs.String("class", "", "the evidence class of every event: payments, auth, events… (never a person)")
		classField = fs.String("class-field", "", "instead of --class: the JSON field whose value is each event's class")
		classes = fs.String("classes", "", "with --class-field: the only classes it may hold, comma-separated "+
			"(a class is public and never erased, so data may not choose one freely)")
		subjectField = fs.String("subject-field", "", "the JSON field whose value is the subject (a pseudonym)")
		recordKey = fs.String("record-key", "", "ML-DSA-65 private key (PEM) to sign every record with; "+
			"required for a sink that signs, refused for one that does not")
	case "checkpoint":
		key = fs.String("key", "", "ML-DSA-65 private key (PEM), from `proof keygen --alg ml-dsa-65`")
		fs.Var(&trust, "trust", "an earlier ML-DSA-65 public key (PEM) existing checkpoints may be signed with; repeatable")
	case "verify":
		key = fs.String("key", "", "ML-DSA-65 public key (PEM) the checkpoints are signed with")
		showSubjects = fs.Bool("show-subjects", false, "also print each live chain's subject, read from the "+
			"secret index (the output is then secret too)")
		fs.Var(&recordTrust, "record-trust", "an ML-DSA-65 public key (PEM) record signatures may be made "+
			"with; repeatable. Given, EVERY record must carry a valid signature")
	case "erase":
		subject = fs.String("subject", "", "the subject to erase (every class, unless --class)")
		eraseClass = fs.String("class", "", "erase only this class of the subject's evidence; the others are kept")
		resume = fs.Bool("resume", false, "only complete erasures an earlier, interrupted call started")
		recordKey = fs.String("record-key", "", "ML-DSA-65 private key (PEM) to sign erasure entries with; "+
			"required for a sink that signs")
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
	var allowed []string
	if verb == "commit" {
		if (*class == "") == (*classField == "") {
			fmt.Fprintln(stderr, "proof sink commit: give --class or --class-field (one of them)")
			return exitUsage
		}
		if (*classField == "") != (*classes == "") {
			fmt.Fprintln(stderr, "proof sink commit: --classes goes with --class-field, and is required by it")
			return exitUsage
		}
		if *classField != "" && *classField == *subjectField {
			fmt.Fprintln(stderr, "proof sink commit: --class-field and --subject-field must differ")
			return exitUsage
		}
		for _, c := range strings.Split(*classes, ",") {
			if *classes == "" {
				break
			}
			if !sink.ValidClass(c) {
				fmt.Fprintf(stderr, "proof sink commit: --classes: %q is not a valid class\n", c)
				return exitUsage
			}
			allowed = append(allowed, c)
		}
	}
	for name, v := range map[string]*string{"--subject-field": subjectField, "--key": key} {
		if v != nil && *v == "" {
			fmt.Fprintf(stderr, "proof sink %s: %s is required\n", verb, name)
			return exitUsage
		}
	}

	var opts []sink.Option
	if recordKey != nil && *recordKey != "" {
		rs, err := loadRecordSigner(*recordKey, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "proof sink %s: %v\n", verb, err)
			return exitIOError
		}
		defer rs.Close()
		opts = append(opts, sink.WithRecordSigner(rs))
	}
	s, err := sink.Open(*dir, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink: %v\n", err)
		return exitIOError
	}
	c := ctx.Background()
	var failed bool
	switch verb {
	case "commit":
		err = sinkCommit(c, s, sink.JSONFields{Class: *class, ClassField: *classField, Classes: allowed,
			SubjectField: *subjectField}, os.Stdin, stdout)
	case "checkpoint":
		failed, err = sinkCheckpoint(c, s, *key, trust, stdout, stderr)
	case "verify":
		failed, err = sinkVerify(c, s, *key, recordTrust, *showSubjects, stdout, stderr)
	case "erase":
		err = sinkErase(c, s, *subject, *eraseClass, *resume, stdout)
	}
	switch {
	case errors.Is(err, sink.ErrRecordSignerRequired):
		// Configuration, not a failure: retrying will not help.
		fmt.Fprintf(stderr, "proof sink %s: this sink signs its records: pass --record-key <record private key>\n", verb)
		return exitUsage
	case errors.Is(err, sink.ErrSinkNotSigning):
		fmt.Fprintf(stderr, "proof sink %s: this sink already holds unsigned records, so it cannot start "+
			"signing: drop --record-key (or start a new sink)\n", verb)
		return exitUsage
	case err != nil:
		fmt.Fprintf(stderr, "proof sink %s: %v\n", verb, err)
		if errors.Is(err, sink.ErrBusy) {
			return exitBusy
		}
		if verb == "verify" && errors.Is(err, sink.ErrCorrupt) {
			// A damaged evidence file is a failed verification, not a file
			// the command could not find.
			return exitBroken
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
func sinkCommit(c ctx.Context, s *sink.Sink, fields sink.JSONFields, in io.Reader, out io.Writer) error {
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
		out, err := s.Commit(c, batch)
		for i, o := range out {
			if !o.Committed {
				continue
			}
			// One chain per (class, subject): count pairs, held only for this run.
			chains[batch[i].Class+"\x00"+batch[i].Subject] = true
			if o.Duplicate {
				duplicates++
			} else {
				entries++
			}
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
		r, err := sink.RecordFromJSON(line, fields)
		if err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
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
func sinkCheckpoint(c ctx.Context, s *sink.Sink, keyPath string, trust []string, out, errOut io.Writer) (bool, error) {
	signer, err := loadSigner(keyPath)
	if err != nil {
		return false, err
	}
	defer signer.Close()
	// R7: separate keys are recommended, never forbidden. Say so, and go on.
	if used, err := s.UsesRecordKey(c, signer.KeyID()); err != nil {
		return false, err
	} else if used {
		fmt.Fprintln(errOut, "warning: this checkpoint key also signs this sink's records. Keep them "+
			"separate: the record key is online in the writer, and if it leaks, checkpoints signed by "+
			"another key still pin what they covered")
	}
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
		return "", nil, fmt.Errorf("%s holds a %s key; checkpoints and records are signed with ML-DSA-65", path, alg)
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
//
// With showSubjects it also reads the secret index (sink.ChainSubjects) and
// prints each live chain's subject, after a warning on stderr: the output is
// then as secret as the index.
func sinkVerify(c ctx.Context, s *sink.Sink, keyPath string, recordTrust []string, showSubjects bool,
	out, errOut io.Writer) (bool, error) {
	id, pub, err := readPublicKey(keyPath)
	if err != nil {
		return false, err
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	if err != nil {
		return false, err
	}
	var opts []sink.VerifyOption
	if len(recordTrust) > 0 {
		// A separate ring: trusting a key for records never trusts it for
		// checkpoints.
		keys := map[string][]byte{}
		for _, p := range recordTrust {
			rid, rpub, err := readPublicKey(p)
			if err != nil {
				return false, err
			}
			if rid == id {
				fmt.Fprintln(errOut, "warning: the same key is given for checkpoints (--key) and records "+
					"(--record-trust). Keep them separate: the record key is online in the writer")
			}
			keys[rid] = rpub
		}
		records, err := anchor.NewKeyRing(anchor.TrustProvided, keys)
		if err != nil {
			return false, err
		}
		opts = append(opts, sink.WithRecordTrust(records))
	}
	subjectOf := map[string]string{}
	if showSubjects {
		// A separate read, before Verify: a commit or erasure meanwhile can make
		// the two disagree. Best effort, for an operator's eyes only.
		rows, err := s.ChainSubjects(c)
		if err != nil {
			return false, err
		}
		for _, r := range rows {
			subjectOf[r.Chain] = r.Subject
		}
		fmt.Fprintln(errOut, "subjects shown: this output is secret-index material; "+
			"do not paste it into tickets, chats or logs")
		// Marked in the output itself too: stdout is what gets saved or captured.
		fmt.Fprintln(out, "# SECRET: subject-index material (proof sink verify --show-subjects)")
	}
	checked := sink.RecordSignatureCheck("")
	if len(recordTrust) > 0 {
		checked = sink.RecordSignaturesChecked
	}
	// Streamed: each chain's line as soon as it is verified (the folder is read
	// a page at a time, and writers are not held up meanwhile). Findings of the
	// cross-chain sweep come after the chains.
	sum, err := s.VerifyEach(c, ring, func(ch sink.ChainReport) error {
		verdict := "verifies"
		if len(ch.Problems) > 0 {
			verdict = "FAILS"
		}
		fmt.Fprintf(out, "chain %-12s %-8s %s: %d opened, %d erased · %s, %d unanchored%s%s%s%s\n",
			printable(ch.Chain), verdict, plural(ch.Entries, "entry", "entries"), ch.Opened, ch.Erased,
			plural(ch.Checkpoints, "checkpoint", "checkpoints"), ch.Unanchored,
			signedNote(checked, ch), orphanNote(ch.OrphanSignatures), indexNote(ch.Index),
			subjectNote(subjectOf[ch.Chain]))
		for _, p := range ch.Problems {
			fmt.Fprintf(out, "    %s\n", p)
		}
		return nil
	}, opts...)
	if err != nil {
		return false, err
	}
	if sum.Reports == 0 {
		return false, errors.New("the evidence file has no chains")
	}
	// Record signatures are a separate dimension: never let a pass read as
	// "signatures verified" when they were not checked.
	switch sum.RecordSignatures {
	case sink.RecordSignaturesNotChecked:
		fmt.Fprintln(out, "Record signatures: NOT CHECKED (this sink signs its records). "+
			"Pass --record-trust <record public key> to verify them.")
	case sink.RecordSignaturesChecked:
		fmt.Fprintln(out, "Record signatures: checked against --record-trust")
	}
	if sum.Failed > 0 {
		fmt.Fprintf(out, "%d of %d chains FAILED\n", sum.Failed, sum.Reports)
		return true, nil
	}
	fmt.Fprintf(out, "all %d chains verify\n", sum.Reports)
	return false, nil
}

// signedNote is a chain's signed count, when signatures were checked.
func signedNote(check sink.RecordSignatureCheck, ch sink.ChainReport) string {
	if check != sink.RecordSignaturesChecked || ch.Entries == 0 {
		return ""
	}
	return fmt.Sprintf(" · %d signed", ch.Signed)
}

// orphanNote mentions signature rows that match no entry: a note, not a
// failure (a crash or a failed cleanup leaves them).
func orphanNote(n int) string {
	if n == 0 {
		return ""
	}
	return " · " + plural(n, "orphan signature", "orphan signatures") + " (note)"
}

// loadRecordSigner loads an ML-DSA-65 record signer from a private key file,
// zeroizing the seed once the signer has copied it.
func loadRecordSigner(path string, errOut io.Writer) (*sink.MLDSA65RecordSigner, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(errOut, "warning: %s is readable by others (mode %04o); a private key file should be 0600\n",
			path, fi.Mode().Perm())
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer clear(pem) // the PEM encodes the seed too
	alg, seed, err := keyfile.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	defer zeroizeSeed(seed)
	if alg != keyfile.MLDSA65 {
		return nil, fmt.Errorf("%s holds a %s key, but records are signed with ML-DSA-65. "+
			"Generate one with: proof keygen --alg ml-dsa-65", path, alg)
	}
	return sink.NewMLDSA65RecordSigner(seed)
}

// indexNote describes a chain's subject-index state, when it is not the usual
// "live".
func indexNote(index sink.IndexState) string {
	switch index {
	case "", sink.IndexLive:
		return ""
	case sink.IndexErased:
		return " · subject erased"
	case sink.IndexErasedUnanchored:
		return " · subject erased (not yet checkpointed)"
	case sink.IndexOnly:
		return " · bound, no entries yet"
	default:
		return " · index: " + string(index)
	}
}

func subjectNote(subject string) string {
	if subject == "" {
		return ""
	}
	return " · subject " + subject
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
