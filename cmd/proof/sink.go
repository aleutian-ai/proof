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
	"regexp"
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
                        [--source-field FIELD | --source-prefix P] [--record-key <record private.pem>]
                        [--skip-check]  < events.jsonl
  proof sink checkpoint [--dir D] --key <ml-dsa-65 private.pem> [--trust <public.pem>]…
                        [--record-trust <record public.pem>]… [--heads FILE]
                        [--confirm-erased-chain <chain id>]…
  proof sink verify     [--dir D] --key <ml-dsa-65 public.pem> [--record-trust <record public.pem>]…
                        [--heads FILE] [--require-checkpoint] [--show-subjects]
  proof sink erase      [--dir D] (--subject S | --subject-file FILE) [--class C]   (or --resume)
                        [--key <ml-dsa-65 private.pem> [--trust <public.pem>]… [--heads FILE]]
                        [--record-key <record private.pem>] [--skip-check]
  proof sink repair     [--dir D] [--heads FILE] [--skip-check]
  proof sink export     [--dir D] (--chain C… | --subject S | --subject-file FILE [--class K] | --all)
                        [--disclose none|all|<entry id>,…] --out bundle.json
  proof sink verify-bundle <bundle.json> [--key <public.pem>]… [--record-trust <record public.pem>]… [--json]
                        (no sink folder needed; its own exit codes: proof sink verify-bundle -h)

A sink is a folder (default ./sink-data) holding one opaque chain per
(class, subject); only a secret index links subjects to chains. See
docs/sink-format.md. --trust names earlier signing keys whose checkpoints may
be built on (after a key rotation). --record-key signs every record written
(a sink signs from its first commit, or never); --record-trust checks every
record's signature (repeatable, for rotated keys). Keep the record key and the
checkpoint key separate: init makes both, beside the sink folder.

erase --key erases and then checkpoints the erased chains in the same run:
checkpoint alone does not sign over an erasure it cannot tell the sink made
(on a sink that signs its records, checkpoint --record-trust can). For an
erasure of yours that missed that (erased without --key, or the run died before
its checkpoint), checkpoint --confirm-erased-chain <chain id> vouches for it:
take the id from verify's output, never from anything that names the subject.
--subject-file reads the subject from a file (- for standard input), so it is
not on the command line. --source-field (or --source-prefix, for input with no
id of its own: the source is P:<line number>) makes committing the same input
again a no-op. --heads keeps each chain's checkpoint count in a file OUTSIDE
the sink folder, so removed checkpoints are noticed. repair removes rows a
commit that crashed before its append left behind. The verbs that write read
each file through once first (--skip-check skips that).

Exit: 0 ok · 1 a chain failed verification or was not checkpointed, or a file
verify read is damaged · 2 usage, or a record key given or missing against the
sink's signing · 3 error, a damaged file included · 4 the folder is busy.`

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
	if verb == "verify-bundle" {
		return cmdSinkVerifyBundle(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("sink "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "the sink folder")
	var class, classField, classes, subjectField, key, subject, eraseClass, recordKey *string
	var sourceField, sourcePrefix, subjectFile, heads *string
	var resume, showSubjects, skipCheck, requireCheckpoint *bool
	var trust, recordTrust, confirmChains multiFlag
	headsFlag := func() *string {
		return fs.String("heads", "", "a file OUTSIDE the sink folder recording each chain's checkpoint count "+
			"and last checkpoint, so a series that was cut or restarted is noticed")
	}
	skipCheckFlag := func() *bool {
		return fs.Bool("skip-check", false, "do not read each file through before writing to it (the check "+
			"refuses a damaged file before anything is written; about 0.1 s per GiB)")
	}
	switch verb {
	case "commit":
		class = fs.String("class", "", "the evidence class of every event: payments, auth, events… (never a person)")
		classField = fs.String("class-field", "", "instead of --class: the JSON field whose value is each event's class")
		classes = fs.String("classes", "", "with --class-field: the only classes it may hold, comma-separated "+
			"(a class is public and never erased, so data may not choose one freely)")
		subjectField = fs.String("subject-field", "", "the JSON field whose value is the subject (a pseudonym)")
		sourceField = fs.String("source-field", "", "the JSON field whose value is each event's upstream id "+
			"(a string or a whole number): an event whose id is already committed is skipped, so the same "+
			"input can be committed again")
		sourcePrefix = fs.String("source-prefix", "", "for input with no id of its own: each event's source "+
			"is PREFIX:<line number>. Name the input for good (a file name and date): the same prefix on "+
			"different input is refused")
		recordKey = fs.String("record-key", "", "ML-DSA-65 private key (PEM) to sign every record with; "+
			"required for a sink that signs, refused for one that does not")
		skipCheck = skipCheckFlag()
	case "checkpoint":
		key = fs.String("key", "", "ML-DSA-65 private key (PEM), from `proof keygen --alg ml-dsa-65`")
		fs.Var(&trust, "trust", "an earlier ML-DSA-65 public key (PEM) existing checkpoints may be signed with; repeatable")
		fs.Var(&recordTrust, "record-trust", "an ML-DSA-65 public key (PEM) records are signed with; repeatable. "+
			"Given, every record of a chain must carry a valid signature for it to be checkpointed, and an "+
			"erasure whose signature verifies is signed over")
		heads = headsFlag()
		fs.Var(&confirmChains, "confirm-erased-chain", "a chain id (from `proof sink verify`) whose erasure "+
			"you vouch for as your own: sign over it although the sink cannot tell who wrote it; repeatable")
	case "verify":
		key = fs.String("key", "", "ML-DSA-65 public key (PEM) the checkpoints are signed with")
		showSubjects = fs.Bool("show-subjects", false, "also print each live chain's subject, read from the "+
			"secret index (the output is then secret too)")
		fs.Var(&recordTrust, "record-trust", "an ML-DSA-65 public key (PEM) record signatures may be made "+
			"with; repeatable. Given, EVERY record must carry a valid signature")
		heads = headsFlag()
		requireCheckpoint = fs.Bool("require-checkpoint", false, "fail a chain that no verified checkpoint "+
			"covers (without it, a folder whose anchors/ was removed still verifies)")
	case "erase":
		subject = fs.String("subject", "", "the subject to erase (every class, unless --class)")
		subjectFile = fs.String("subject-file", "", "instead of --subject: a file holding the subject "+
			"(- for standard input), so it is not on the command line")
		eraseClass = fs.String("class", "", "erase only this class of the subject's evidence; the others are kept")
		resume = fs.Bool("resume", false, "only complete erasures an earlier, interrupted call started")
		recordKey = fs.String("record-key", "", "ML-DSA-65 private key (PEM) to sign erasure entries with; "+
			"required for a sink that signs")
		key = fs.String("key", "", "ML-DSA-65 checkpoint private key (PEM): after erasing, checkpoint the "+
			"erased chains in the same run")
		fs.Var(&trust, "trust", "with --key: an earlier ML-DSA-65 public key (PEM) existing checkpoints may "+
			"be signed with; repeatable")
		heads = headsFlag()
		skipCheck = skipCheckFlag()
	case "repair":
		heads = fs.String("heads", "", "the checkpoint heads file (as given to checkpoint --heads): a chain it "+
			"records is never taken for one that held no entries")
		skipCheck = skipCheckFlag()
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
	eraseSubject := ""
	if verb == "erase" {
		given := 0
		for _, set := range []bool{*subject != "", *subjectFile != "", *resume} {
			if set {
				given++
			}
		}
		if given != 1 {
			fmt.Fprintln(stderr, "proof sink erase: give exactly one of --subject, --subject-file and --resume")
			return exitUsage
		}
		if *resume && *eraseClass != "" {
			fmt.Fprintln(stderr, "proof sink erase: --class applies to a subject, not to --resume")
			return exitUsage
		}
		if *key == "" && (len(trust) > 0 || *heads != "") {
			fmt.Fprintln(stderr, "proof sink erase: --trust and --heads go with --key (they are for the checkpoint)")
			return exitUsage
		}
		eraseSubject = *subject
		if *subjectFile != "" {
			var err error
			if eraseSubject, err = readSubjectFile(*subjectFile, os.Stdin); err != nil {
				fmt.Fprintf(stderr, "proof sink erase: %v\n", err)
				return exitIOError
			}
		}
	}
	for _, c := range confirmChains {
		if !sink.ValidChainID(c) {
			fmt.Fprintln(stderr, "proof sink checkpoint: --confirm-erased-chain takes a chain id, as "+
				"`proof sink verify` prints it")
			return exitUsage
		}
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
		if *sourceField != "" && *sourcePrefix != "" {
			fmt.Fprintln(stderr, "proof sink commit: give --source-field or --source-prefix, not both")
			return exitUsage
		}
		if *sourceField != "" && (*sourceField == *subjectField || *sourceField == *classField) {
			fmt.Fprintln(stderr, "proof sink commit: --source-field must differ from the subject and class "+
				"fields (a source is a position upstream, never who the event is about)")
			return exitUsage
		}
		if *sourcePrefix != "" && !sourcePrefixPattern.MatchString(*sourcePrefix) {
			fmt.Fprintln(stderr, "proof sink commit: --source-prefix: letters, digits and . _ @ - (max 200), "+
				"starting with a letter or digit")
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
	required := map[string]*string{"--subject-field": subjectField}
	if verb != "erase" {
		required["--key"] = key // optional for erase
	}
	for name, v := range required {
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
	if skipCheck != nil && *skipCheck {
		opts = append(opts, sink.WithoutIntegrityCheck())
	}
	s, err := sink.Open(*dir, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink: %v\n", err)
		return exitIOError
	}
	headsPath := ""
	if heads != nil {
		headsPath = *heads
	}
	c := ctx.Background()
	var failed bool
	switch verb {
	case "commit":
		err = sinkCommit(c, s, sink.JSONFields{Class: *class, ClassField: *classField, Classes: allowed,
			SubjectField: *subjectField, SourceField: *sourceField}, *sourcePrefix, os.Stdin, stdout)
	case "checkpoint":
		failed, err = sinkCheckpoint(c, s, *key, trust, recordTrust, confirmChains, headsPath, stdout, stderr)
	case "verify":
		failed, err = sinkVerify(c, s, *key, recordTrust, headsPath, *requireCheckpoint, *showSubjects, stdout, stderr)
	case "erase":
		failed, err = sinkErase(c, s, eraseSubject, *eraseClass, *resume,
			eraseCheckpoint{keyPath: *key, trust: trust, heads: headsPath, signing: *recordKey != ""}, stdout, stderr)
	case "repair":
		err = sinkRepair(c, s, headsPath, stdout)
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

// sourcePrefixPattern is what --source-prefix may hold: it becomes part of a
// stored source, so it is kept to plain characters.
var sourcePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,199}$`)

// maxSubjectFileBytes caps a --subject-file: a subject is at most 128 bytes.
const maxSubjectFileBytes = 4096

// readSubjectFile reads a subject from a file, or from stdin when path is "-",
// so that it need not be on the command line (where it is visible to other
// users and kept in shell history). Surrounding whitespace is dropped; the
// subject itself is validated by the sink, and never echoed.
func readSubjectFile(path string, stdin io.Reader) (string, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(io.LimitReader(stdin, maxSubjectFileBytes+1))
	} else {
		var f *os.File
		if f, err = os.Open(path); err == nil {
			raw, err = io.ReadAll(io.LimitReader(f, maxSubjectFileBytes+1))
			f.Close()
		}
	}
	if err != nil {
		return "", fmt.Errorf("--subject-file: %w", err)
	}
	if len(raw) > maxSubjectFileBytes {
		return "", errors.New("--subject-file: more than one subject's worth of bytes")
	}
	subject := strings.TrimSpace(string(raw))
	if subject == "" {
		return "", errors.New("--subject-file: no subject in it")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return "", errors.New("--subject-file: more than one line (one subject per run)")
	}
	return subject, nil
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
//
// With a source field, or a source prefix (each event's source is then
// prefix:<line number>, counting every line of the input), an event already
// committed is skipped, so the same input can be committed again after a
// failure. An event whose source is already committed with OTHER content is
// refused, by line number.
func sinkCommit(c ctx.Context, s *sink.Sink, fields sink.JSONFields, sourcePrefix string, in io.Reader,
	out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), sinkMaxLine)
	chains := map[string]bool{}
	entries, duplicates := 0, 0
	var batch []sink.Record
	var lineOf []int // the input line of each record in batch
	lines := 0

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		out, err := s.Commit(c, batch)
		var re *sink.RecordError
		if errors.As(err, &re) && errors.Is(err, sink.ErrSourceConflict) && re.Index < len(lineOf) {
			// By line, not by source: a source is not for terminals and logs.
			err = fmt.Errorf("line %d: %w; nothing of its batch was committed", lineOf[re.Index], re.Err)
		}
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
		batch, lineOf = batch[:0], lineOf[:0]
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
		if sourcePrefix != "" {
			r.Source = fmt.Sprintf("%s:%d", sourcePrefix, lines)
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
		batch = append(batch, r)
		lineOf = append(lineOf, lines)
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
func sinkCheckpoint(c ctx.Context, s *sink.Sink, keyPath string, trust, recordTrust, confirmChains []string,
	headsPath string, out, errOut io.Writer) (bool, error) {
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
	trusted, err := checkpointTrust(signer, trust)
	if err != nil {
		return false, err
	}
	var opts []sink.CheckpointOption
	if len(recordTrust) > 0 {
		records, err := recordRing(recordTrust, signer.KeyID(), errOut)
		if err != nil {
			return false, err
		}
		opts = append(opts, sink.CheckpointRecordTrust(records))
	}
	if headsPath != "" {
		opts = append(opts, sink.TrackHeads(sink.FileHeads(headsPath)))
	}
	if len(confirmChains) > 0 {
		// The sink cannot attribute these erasures; the operator does.
		fmt.Fprintf(errOut, "warning: you are vouching for the erasure at the end of %s. The sink cannot tell "+
			"who wrote an erasure record: this signs it as yours. Do it only for an erasure you made "+
			"(`proof sink erase` without --key, or a run that stopped before its checkpoint). An erasure "+
			"you cannot account for was written into the folder by something else.\n",
			plural(len(confirmChains), "chain", "chains"))
		opts = append(opts, sink.ConfirmErasedChains(confirmChains...))
	}
	done, err := s.Checkpoint(c, signer, trusted, opts...)
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

// checkpointTrust is the keys existing checkpoints may be signed with: nil
// (the signer's own only) unless earlier keys are named.
func checkpointTrust(signer *anchor.MLDSA65Signer, trust []string) (anchor.KeySource, error) {
	if len(trust) == 0 {
		return nil, nil
	}
	// The signer's own key is always trusted: its checkpoints must verify
	// the next time this runs.
	keys := map[string][]byte{}
	id, pub, err := anchor.KeyIDOf(signer)
	if err != nil {
		return nil, err
	}
	keys[id] = pub
	for _, p := range trust {
		id, pub, err := readPublicKey(p)
		if err != nil {
			return nil, err
		}
		keys[id] = pub
	}
	return anchor.NewKeyRing(anchor.TrustProvided, keys)
}

// recordRing is the keys record signatures may be made with. A separate ring:
// trusting a key for records never trusts it for checkpoints. checkpointKeyID
// is the checkpoint key in use, to warn when it is given for both.
func recordRing(paths []string, checkpointKeyID string, errOut io.Writer) (anchor.KeySource, error) {
	keys := map[string][]byte{}
	for _, p := range paths {
		rid, rpub, err := readPublicKey(p)
		if err != nil {
			return nil, err
		}
		if rid == checkpointKeyID {
			fmt.Fprintln(errOut, "warning: the same key is given for checkpoints (--key) and records "+
				"(--record-trust). Keep them separate: the record key is online in the writer")
		}
		keys[rid] = rpub
	}
	return anchor.NewKeyRing(anchor.TrustProvided, keys)
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
func sinkVerify(c ctx.Context, s *sink.Sink, keyPath string, recordTrust []string, headsPath string,
	requireCheckpoint, showSubjects bool, out, errOut io.Writer) (bool, error) {
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
		records, err := recordRing(recordTrust, id, errOut)
		if err != nil {
			return false, err
		}
		opts = append(opts, sink.WithRecordTrust(records))
	}
	if headsPath != "" {
		opts = append(opts, sink.WithCheckpointHeads(sink.FileHeads(headsPath)))
	}
	if requireCheckpoint {
		opts = append(opts, sink.RequireCheckpoints())
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

// eraseCheckpoint is how `erase` checkpoints the chains it erased: keyPath
// empty means it does not.
type eraseCheckpoint struct {
	keyPath string
	trust   []string
	heads   string
	// signing is true when a record key was given: the erasure entries are
	// signed, so a later `checkpoint --record-trust` can confirm them.
	signing bool
}

// sinkErase erases a subject (every class), one class of a subject's
// evidence, or only completes interrupted erasures. The output says which, so a
// class-scoped erasure is never mistaken for forgetting the subject. With a
// checkpoint key it then checkpoints the erased chains, in this same process:
// the erasure entry ids the erase call returned are what tell Checkpoint the
// sink made those erasures (sink.ConfirmErasures).
//
// It never prints the subject: a line saying who was erased, and when, is a
// lasting record of exactly what the erasure removes. Nor a chain id, an
// erasure entry id or a checkpoint's path: next to the subject on the command
// line, any of them maps the subject to its chain. Counts only.
//
// The bool reports that erased chains could not be checkpointed (exit 1).
func sinkErase(c ctx.Context, s *sink.Sink, subject, class string, resume bool, cp eraseCheckpoint,
	out, errOut io.Writer) (bool, error) {
	// The checkpoint key first: a bad key must be found before anything is
	// erased, not after.
	var signer *anchor.MLDSA65Signer
	var trusted anchor.KeySource
	if cp.keyPath != "" {
		var err error
		if signer, err = loadSigner(cp.keyPath); err != nil {
			return false, err
		}
		defer signer.Close()
		if trusted, err = checkpointTrust(signer, cp.trust); err != nil {
			return false, err
		}
	}
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
	if err != nil && !errors.As(err, &incomplete) {
		return false, err // nothing was erased
	}
	// The erasures this run can vouch for: those the erase calls returned,
	// except a chain the index had re-linked (its erasure entry was there
	// before this run, with nothing to say the sink made it).
	var confirmable []sink.EraseResult
	var chains []string
	relinked := 0
	for _, e := range append(append([]sink.EraseResult(nil), res.Resumed...), res.Erased...) {
		switch {
		case e.ErasureEntryID == "":
			// No entries, so no erasure entry: nothing to checkpoint.
		case e.Relinked:
			relinked++
		default:
			confirmable, chains = append(confirmable, e), append(chains, e.Chain)
		}
	}
	if relinked > 0 {
		fmt.Fprintf(out, "%s already ended with an erasure while the index still named a subject for it "+
			"(an index restored from before an erasure, or an erasure written into the folder). The subject "+
			"is forgotten and the content deleted, but this run did not make that erasure, so it is not "+
			"checkpointed here. If you know it is yours: `proof sink checkpoint --key … "+
			"--confirm-erased-chain <chain id>`, the id from `proof sink verify`.\n",
			plural(relinked, "chain", "chains"))
	}
	// What the checkpoint has to say comes after what the erasure did.
	var after strings.Builder
	defer func() { _, _ = io.WriteString(out, after.String()) }()
	refused := false
	switch {
	case len(chains) == 0:
	case signer == nil:
		how := "`proof sink checkpoint` does not sign over an erasure it cannot tell the sink made, so the " +
			"erased chains stay \"not yet checkpointed\" until you vouch for them: `proof sink checkpoint " +
			"--key … --confirm-erased-chain <chain id>`, the id from `proof sink verify`. Next time, erase " +
			"with --key <checkpoint private key> to checkpoint in the same run"
		if cp.signing {
			how = "`proof sink checkpoint --record-trust <record public key>` signs over it (the erasure " +
				"entries are signed), or erase with --key <checkpoint private key> to checkpoint in the same run"
		}
		fmt.Fprintln(errOut, "note: the erasure is not checkpointed. "+how+".")
	default:
		opts := []sink.CheckpointOption{sink.ConfirmErasures(confirmable...), sink.OnlyChains(chains...)}
		if cp.heads != "" {
			opts = append(opts, sink.TrackHeads(sink.FileHeads(cp.heads)))
		}
		done, cerr := s.Checkpoint(c, signer, trusted, opts...)
		signed := 0
		for _, d := range done {
			if d.Problem == "" {
				signed++
			}
		}
		if signed > 0 {
			fmt.Fprintf(&after, "Checkpointed %s: the erasure is signed.\n", plural(signed, "erased chain", "erased chains"))
		}
		if n := len(chains) - signed; n > 0 {
			refused = true
			// Why is in `verify`: a problem line names an entry or a folder, and
			// either maps the subject to its chain here.
			fmt.Fprintf(&after, "%s NOT checkpointed: the erasure is done, its checkpoint is not. Next: "+
				"`proof sink verify` shows the chains that read \"subject erased (not yet checkpointed)\" and "+
				"anything wrong with them. A chain whose erasure is still pending is finished and checkpointed "+
				"by `proof sink erase --resume --key …`. For the others, once what verify reports is fixed: "+
				"`proof sink checkpoint --key … --confirm-erased-chain <chain id>` (they are this run's "+
				"erasures; a later run can no longer tell).\n",
				plural(n, "erased chain was", "erased chains were"))
		}
		if cerr != nil && err == nil {
			return refused, redactChains(fmt.Errorf("the erasure is complete, but checkpointing it failed: %w. "+
				"Run `proof sink verify`, then `proof sink checkpoint --key … --confirm-erased-chain <chain id>` "+
				"for each chain it shows as erased and not yet checkpointed", cerr))
		}
	}
	if incomplete != nil {
		if len(res.Erased) > 0 {
			fmt.Fprintf(out, "erased %s of the subject's evidence\n", plural(len(res.Erased), "chain", "chains"))
		}
		if incomplete.Forgotten {
			fmt.Fprintln(out, "The subject is removed from the index, but its evidence on the pending chains is "+
				"not yet deleted.")
		}
		return refused, err
	}
	if resume {
		if len(res.Resumed) == 0 {
			fmt.Fprintln(out, "no interrupted erasures")
		}
		return refused, nil
	}
	if len(res.Erased) == 0 {
		fmt.Fprintln(out, "no evidence held for that subject in that scope (never committed, or already erased)")
		return refused, nil
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
	return refused, nil
}

// chainIDInMessage matches a chain id anywhere in a message.
var chainIDInMessage = regexp.MustCompile(`[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}`)

// redactedError is an error whose message names no chain, and which still
// unwraps to the original.
type redactedError struct{ err error }

func (e redactedError) Error() string {
	return chainIDInMessage.ReplaceAllString(e.err.Error(), "<chain>")
}
func (e redactedError) Unwrap() error { return e.err }

// redactChains keeps chain ids out of an error printed by a command that has
// the subject on its command line.
func redactChains(err error) error { return redactedError{err} }

// sinkRepair removes the rows a commit that crashed before its append left
// behind, and says how many. Counts only: a leftover row is keyed by its chain.
func sinkRepair(c ctx.Context, s *sink.Sink, headsPath string, out io.Writer) error {
	var opts []sink.RepairOption
	if headsPath != "" {
		opts = append(opts, sink.RepairHeads(sink.FileHeads(headsPath)))
	}
	sum, err := s.Repair(c, opts...)
	if sum.Removed() > 0 {
		fmt.Fprintf(out, "removed %s, %s, %s and %s that matched no entry, on %s; the files were rewritten\n",
			plural(sum.Content, "content row", "content rows"), plural(sum.Nonces, "nonce", "nonces"),
			plural(sum.Sources, "source position", "source positions"),
			plural(sum.Signatures, "record signature", "record signatures"),
			plural(sum.Chains, "chain", "chains"))
	}
	if sum.Skipped > 0 {
		fmt.Fprintf(out, "%s such rows and %s left alone: something says they may be what is left of entries "+
			"that were removed, not of a commit that stopped (a checkpoint, a recorded head, record "+
			"signatures on a chain with no entries, a chain that cannot be read), or an erasure is pending "+
			"(`proof sink erase --resume`). `proof sink verify` shows which. A pair whose first commit "+
			"stopped on a sink that signs is repaired once it has committed.\n",
			plural(sum.Skipped, "chain has", "chains have"), map[bool]string{true: "was", false: "were"}[sum.Skipped == 1])
	}
	if err != nil {
		return err
	}
	if sum.Removed() == 0 && sum.Skipped == 0 {
		fmt.Fprintln(out, "nothing to repair: no row without an entry")
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
