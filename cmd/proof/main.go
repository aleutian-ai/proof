// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command proof commits evidence to AleutianChain audit chains, anchors them and
// verifies them.
//
// # Description
//
// A single static binary. It reads and writes only the local files the caller
// names; the one exception is --op-vault (keygen, sink init), which runs the
// 1Password op CLI. Verifying needs only the files you name: no network, no
// credentials, no account, and no trust in the party that produced them.
//
// # Subcommands
//
// `proof help` lists every verb and its flags, and `proof sink help` the sink's:
// verify, export, init, commit, import, disclose, forget, keygen, anchor,
// version, and sink init, commit, checkpoint, verify, erase, repair, export and
// verify-bundle.
//
// # Exit codes
//
//	0  verification passed / command succeeded
//	1  verification FAILED — the chain is broken
//	2  usage error
//	3  I/O or parse error, including a store file too damaged to read
//	4  the chain or its database is busy: another writer holds it; retry
//
// The distinction between 1 and 3 matters in a script: "the chain is broken" and
// "I could not read the file" call for different responses, and collapsing them
// into "non-zero" loses that.
package main

import (
	"bufio"
	ctx "context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

const (
	exitOK      = 0
	exitBroken  = 1
	exitUsage   = 2
	exitIOError = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is main's testable body.
//
// A damaged store file is reported by the storage wrappers as an error: their
// every call is guarded, and a handle that failed is abandoned rather than
// closed, so nothing waits on a lock a failed transaction left held. This is
// the last line behind them. A panic that still gets here is not known to be
// file damage (it may be a bug), and is reported as what it is: the command
// ends with an error, never with the Go runtime's status 2, which in this
// command line means a usage error.
func run(args []string, stdout, stderr *os.File) int {
	code, failure := dispatchRecovered(args, stdout, stderr)
	if failure != nil {
		fmt.Fprintf(stderr, "proof: unexpected failure: %v\nThis is a bug in proof, or a store file damaged in "+
			"a way its storage layer did not report. Nothing can be said about the result.\n", failure)
		if len(args) > 1 && args[0] == "sink" && args[1] == "verify" {
			// Verification did not pass.
			return exitBroken
		}
		return exitIOError
	}
	return code
}

// dispatchRecovered runs the command and returns a panic or memory fault that
// escaped it, if any.
func dispatchRecovered(args []string, stdout, stderr *os.File) (code int, failure any) {
	old := debug.SetPanicOnFault(true)
	defer func() {
		debug.SetPanicOnFault(old)
		failure = recover()
	}()
	return dispatch(args, stdout, stderr), nil
}

// dispatch runs the named subcommand.
func dispatch(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "export":
		return cmdExport(args[1:], stdout, stderr)
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "anchor":
		return cmdAnchor(args[1:], stdout, stderr)
	case "commit":
		return cmdCommit(args[1:], stdout, stderr)
	case "import":
		return cmdImport(args[1:], stdout, stderr)
	case "disclose":
		return cmdDisclose(args[1:], stdout, stderr)
	case "forget":
		return cmdForget(args[1:], stdout, stderr)
	case "sink":
		return cmdSink(args[1:], stdout, stderr)
	case "version", "--version":
		return cmdVersion(stdout)
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "proof: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `proof — commit evidence to a chain, anchor it, verify it

usage:
  proof verify <entries.json> [--json] [--max-breaks N]
               [--anchor <anchor.json>] [--previous <prev.json> | --previous-hash <hash>]
               [--key <public.pem>] [--key-trust platform|provided|self]
  proof export --db <path> --chain <id> [--out <path>] [--jsonl] [--force]
  proof init   --db <path>
  proof commit --db <path> --chain <id> [--format-v2]   < entries.jsonl
  proof import --db <path> --chain <id> [--previous-hash <hash>]  < exported.jsonl
  proof disclose --db <path> --chain <id> --entry <id> --content <file>
  proof forget   --db <path> --chain <id> --entry <id>
  proof keygen [--alg x-wing] [--out-dir .] [--slot primary|backup|dual]
               [--name LABEL] [--op-vault VAULT] [--force]
  proof anchor --db <path> --chain <id> --subject <s> --key <private.pem>
               [--previous <anchor.json>] [--out <path>] [--force]
  proof sink init|commit|checkpoint|verify|erase|repair|export|verify-bundle …   (proof sink help)
  proof version

exit: 0 ok · 1 chain broken · 2 usage · 3 io error · 4 chain busy

verify reads only the files you name. No network, no credentials.

export and anchor only read the database: they never create it or change it,
so a mistyped --db is an error. --out refuses to replace an existing file
unless --force is given.

Three claims, and they are not the same:

  (no flags)        nothing was edited under you
  --anchor          ...and this is the chain that anchor committed to
  --anchor --key    ...and a key you named signed that anchor

Pass --previous for any anchor that is not the first in its chain: an anchor
commits to its predecessor's hash but names it only by id, so the hash cannot
be recovered from the anchor you are checking.

keygen writes a private key (0600) and a public key, in the standard PKCS#8 and
SubjectPublicKeyInfo formats other tools can read. It self-tests every key
before writing it, prints the SHA-512 fingerprint for reading aloud, and can
store the pair in 1Password with --op-vault. The private key is never printed.

anchor signs a statement that a chain had a particular head. It VERIFIES the
chain first and refuses to anchor a broken one, so the claim it makes is one it
established. Pass --previous for any anchor after the first; without it the
anchor is the first in its chain. Like keygen, this verb takes a key and is
therefore never exposed over MCP.

sink keeps one opaque chain per (class, subject) in a folder: commit a JSONL
stream, sign one checkpoint per chain, verify every chain on its own, and erase
a subject's events while every chain still verifies. See docs/sink-format.md.
`)
}

// cmdVerify checks a chain's linkage.
func cmdVerify(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	maxBreaks := fs.Int("max-breaks", 0, "stop collecting after N breaks (0 = all)")
	var opts anchorOptions
	fs.StringVar(&opts.anchorPath, "anchor", "", "also check the chain against this anchor JSON")
	fs.StringVar(&opts.previousPath, "previous", "", "the previous anchor's JSON; omit only for the first anchor in a chain")
	fs.StringVar(&opts.previousHash, "previous-hash", "", "the previous anchor's chain hash, if you kept the hash but not the anchor")
	fs.StringVar(&opts.keyPath, "key", "", "also verify the anchor's signature with this ML-DSA-65 public key (PEM)")
	fs.StringVar(&opts.keyTrust, "key-trust", "", "where the key came from: platform, provided (default), or self")
	// Go's flag package stops at the first non-flag argument, so a plain
	// fs.Parse would reject the natural `proof verify entries.json --anchor a.json`
	// — the flags after the filename would be read as extra positionals. This
	// loop lets flags and the filename appear in any order. It is not a
	// hand-rolled parser: fs.Parse still does the work, and still knows which
	// flags take a value, so `--anchor a.json` cannot be mistaken for a
	// positional.
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "proof verify: expected exactly one entries file, got %d\n",
			len(positional))
		return exitUsage
	}

	// The entries are walked as they are read and never held: a chain of any
	// length is verified in the memory one entry takes. The anchor is bound by
	// a walker of its own, as verify.BindAnchor would make, so what binding
	// reports does not depend on --max-breaks.
	w := verify.NewWalker(verify.Options{MaxBreaks: *maxBreaks})
	walkers := []*verify.Walker{w}
	var bindWalker *verify.Walker
	if opts.anchorPath != "" {
		bindWalker = verify.NewWalker(verify.Options{MaxBreaks: 1})
		walkers = append(walkers, bindWalker)
	}
	if err := walkEntriesFile(positional[0], walkers...); err != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitIOError
	}
	res := w.Result()

	anchorRes, aerr := verifyAnchorFlags(opts, bindWalker)
	if aerr != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", aerr)
		// A file that is missing or is not what its flag says is an input
		// failure. Flags that do not fit together are a usage error.
		var bad *inputFileError
		if errors.As(aerr, &bad) {
			return exitIOError
		}
		return exitUsage
	}

	// The result type carries both of these and nothing had ever set them —
	// Chain cannot, because it is handed entries and nothing else. This is the
	// caller that has the anchor, so this is where they become true.
	if anchorRes != nil {
		res.AnchorChecked = true
		if res.Verdict == verify.VerdictIntact && anchorRes.bind.Bound {
			res.Verdict = verify.VerdictAnchored
		}
	}

	if *asJSON {
		if err := encodeCombinedJSON(stdout, res, anchorRes); err != nil {
			fmt.Fprintf(stderr, "proof verify: encode result: %v\n", err)
			return exitIOError
		}
	} else {
		printResult(stdout, res, anchorRes != nil)
		if anchorRes != nil {
			printAnchorResult(stdout, anchorRes)
		}
	}

	if res.Verdict == verify.VerdictBroken {
		return exitBroken
	}
	// An anchor that does not describe this chain is a BROKEN verdict too. The
	// chain linking cleanly while the anchor disagrees is exactly the truncation
	// case — internally flawless, and not the chain that was committed to.
	if anchorRes != nil && !anchorRes.bind.Bound {
		return exitBroken
	}
	return exitOK
}

// printResult renders a human-readable verdict.
//
// The wording is deliberate. It reports what was actually established — that
// nothing was edited — and states plainly what was NOT, because a reader who
// sees "verified" will otherwise assume the stronger claim.
func printResult(w *os.File, res verify.Result, anchorFollows bool) {
	switch res.Verdict {
	case verify.VerdictBroken:
		fmt.Fprintf(w, "BROKEN — first break at entry %d\n\n", res.FirstBreak)
		for _, b := range res.Breaks {
			fmt.Fprintf(w, "  [%d] %-20s %s\n", b.Position, b.Type, b.EntryID)
			if b.Detail != "" {
				fmt.Fprintf(w, "       %s\n", b.Detail)
			}
			// Truncated SAFELY. This slice was b.Expected[:32] and b.Actual[:32]
			// behind a check on Expected alone, so a break carrying one side and
			// not the other — or a short value — panicked `proof verify` on the
			// very path it exists for. Found by a test for something else.
			if b.Expected != "" || b.Actual != "" {
				fmt.Fprintf(w, "       expected %s\n       actual   %s\n",
					shortHash(b.Expected), shortHash(b.Actual))
			}
		}
		if len(res.Breaks) > 1 {
			fmt.Fprintf(w, "\n  Note: one altered entry breaks every entry after it, so the\n"+
				"  count above is the blast radius. Entry %d is the place to look.\n", res.FirstBreak)
		}
	case verify.VerdictAnchored:
		fmt.Fprintf(w, "INTACT, ANCHORED — %d entries\n", res.EntriesVerified)
	default:
		fmt.Fprintf(w, "INTACT — %d entries verified", res.EntriesVerified)
		if res.TombstonesFound > 0 {
			fmt.Fprintf(w, ", %d erased", res.TombstonesFound)
		}
		fmt.Fprintln(w)
		if res.TombstonesFound == 0 {
			fmt.Fprintln(w, "\n  Proven:     nothing was edited under you.")
		} else {
			// An erased entry's chain hash is taken as stored, so the walk
			// links nothing before it to anything after it.
			fmt.Fprintf(w, "\n  Proven:     nothing after entry %d, the last erased one, was edited under you.\n",
				res.LastTombstone)
			fmt.Fprintf(w, "  NOT proven: that entries 0 to %d are unedited. An erased entry's chain hash\n"+
				"              is taken as stored, so whoever can write the store can replace\n"+
				"              everything before it.\n", res.LastTombstone)
		}
		if anchorFollows {
			// Saying "no anchor was checked" two lines above an anchor result
			// would be simply untrue. The truncation caveat still belongs here,
			// because linkage alone genuinely cannot see it — the anchor below
			// is what addresses it.
			fmt.Fprintln(w, "  NOT proven: that this is the whole chain — not from linkage alone.")
			fmt.Fprintln(w, "              See the anchor result below, which is what closes it.")
		} else {
			fmt.Fprintln(w, "  NOT proven: that this is the whole chain. Entries could have been")
			fmt.Fprintln(w, "              removed from the front and the rest re-linked; detecting")
			fmt.Fprintln(w, "              that needs an anchor, which was not checked here.")
		}
	}
}

// shortHash renders a hash for a human, truncated to a readable prefix.
//
// # Description
//
// Never slices past the end. A break may carry an empty or short value — an
// entry whose chain hash is missing entirely, for instance — and a report that
// panics while describing a broken chain is worse than no report.
//
// # Inputs
//
//   - h: a hash, possibly empty or shorter than the prefix
//
// # Outputs
//
//   - string: the first 32 characters with an ellipsis, the whole value if
//     shorter, or "(none)" if empty
//
// # Example
//
//	fmt.Println(shortHash(b.Expected))
//
// # Limitations
//
//   - For display only. Never compare truncated hashes.
//
// # Assumptions
//
//   - None.
func shortHash(h string) string {
	switch {
	case h == "":
		return "(none)"
	case len(h) <= 32:
		return h
	default:
		return h[:32] + "…"
	}
}

// walkEntriesFile reads exported entries from a file, a JSON array or JSONL,
// and adds each to every walker as it is read.
//
// The format is sniffed rather than flagged: a caller verifying a file someone
// handed them should not have to know which shape it is. Input that is not
// entries (an anchor, an export bundle, `{}`) is an error here, so it is never
// verified and reported as a broken chain. The error may come after entries
// have been walked; the caller reports it and no verdict.
func walkEntriesFile(path string, walkers ...*verify.Walker) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	rd := verify.NewEntryReader(f)
	for {
		e, err := rd.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, w := range walkers {
			w.Add(e)
		}
	}
}

// loadEntriesFrom reads exported entries from a stream, sniffing the same two
// shapes loadEntries accepts. Used by `proof import`, whose input arrives on
// stdin rather than as a path.
func loadEntriesFrom(r io.Reader) ([]verify.Entry, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return parseEntries(raw, "stdin")
}

// parseEntries decodes a JSON array or JSONL, whichever it was handed. Input
// that is not entries (an anchor, an export bundle, `{}`) is an error here, so
// it is never verified and reported as a broken chain.
func parseEntries(raw []byte, path string) ([]verify.Entry, error) {
	entries, err := verify.DecodeEntries(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return entries, nil
}

// exportPage is how many rows export reads from the store at a time. It is
// the most export holds, whatever the chain's length.
const exportPage = 1000

// cmdExport dumps a chain to portable JSON.
//
// It only reads. The database is opened read-only, so a mistyped --db is an
// error and not a new, empty database, and a chain that is not there is an
// error and not an empty file. Rows go from the store to the output a page at
// a time.
func cmdExport(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to export")
	outPath := fs.String("out", "", "write here instead of stdout")
	asJSONL := fs.Bool("jsonl", false, "one entry per line instead of a JSON array")
	force := fs.Bool("force", false, "replace the --out file if it exists")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" {
		fmt.Fprintln(stderr, "proof export: --db and --chain are required")
		return exitUsage
	}
	if err := refuseExistingOutput(*outPath, *force); err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitUsage
	}

	s, err := boltstore.Open(*dbPath, boltstore.WithReadOnly())
	if err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		if errors.Is(err, boltstore.ErrLocked) {
			return exitBusy
		}
		return exitIOError
	}
	defer s.Close()

	// The first page is read before the output is opened: a chain that is not
	// there leaves no file behind.
	rows, err := s.Range(ctx.Background(), *chainID, 0, 1<<62, exportPage)
	if err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	if len(rows) == 0 {
		fmt.Fprintf(stderr, "proof export: chain %q has no entries in %s\n", *chainID, *dbPath)
		return exitIOError
	}

	out, err := openOutput(*outPath, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	defer out.abort()

	ew := newEntryWriter(out.w, *asJSONL)
	for len(rows) > 0 {
		for _, r := range rows {
			if err := ew.write(toExported(r)); err != nil {
				fmt.Fprintf(stderr, "proof export: %v\n", err)
				return exitIOError
			}
		}
		if len(rows) < exportPage {
			break
		}
		next := rows[len(rows)-1].GlobalSeq + 1
		if rows, err = s.Range(ctx.Background(), *chainID, next, 1<<62, exportPage); err != nil {
			fmt.Fprintf(stderr, "proof export: %v\n", err)
			return exitIOError
		}
	}
	if err := ew.close(); err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	if err := out.commit(); err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	return exitOK
}

// refuseExistingOutput is the --out rule export and anchor share: a file that
// is already there is not replaced unless --force was given.
//
// A device or a pipe (/dev/stdout, a FIFO) is not a file that can be replaced,
// and is written to as it always was. Lstat, so a symlink counts as something
// at the path whether or not it points anywhere.
func refuseExistingOutput(path string, force bool) error {
	if path == "" || force || isStream(path) {
		return nil
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists — use --force to replace it", path)
	}
	return nil
}

// isStream reports whether path is a device, a pipe or a socket: something
// written to, never replaced.
func isStream(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0
}

// output is where export and anchor write: stdout, or the --out file.
//
// A file is written beside its destination and renamed over it by commit, so
// a failed or interrupted run leaves no partial file and never truncates the
// one that was there.
type output struct {
	w      *os.File
	file   *atomicFile // a regular --out file, until committed or aborted
	stream *os.File    // a device or pipe named by --out
}

// openOutput opens path for writing, or returns stdout when path is empty.
// The caller has already applied refuseExistingOutput.
func openOutput(path string, stdout *os.File) (*output, error) {
	switch {
	case path == "":
		return &output{w: stdout}, nil
	case isStream(path):
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		return &output{w: f, stream: f}, nil
	}
	a, err := createAtomic(path, 0o666, false)
	if err != nil {
		return nil, err
	}
	return &output{w: a.File, file: a}, nil
}

// commit finishes the output: a file becomes durable and takes its name.
func (o *output) commit() error {
	switch {
	case o.file != nil:
		a := o.file
		o.file = nil
		return a.commit()
	case o.stream != nil:
		f := o.stream
		o.stream = nil
		return f.Close()
	}
	return nil
}

// abort discards an output that was not committed. After commit it does
// nothing, so it can be deferred.
func (o *output) abort() {
	if o.file != nil {
		o.file.abort()
		o.file = nil
	}
	if o.stream != nil {
		_ = o.stream.Close()
		o.stream = nil
	}
}

// toExported converts a stored row to its portable form.
//
// The timestamp is rendered in the EXACT form it was hashed — RFC3339 with six
// fractional digits. Anything else and a verifier re-parsing this file computes
// a different hash and reports a break on an intact chain.
func toExported(r store.Entry) verify.Entry {
	e := verify.Entry{
		EntryID:     r.EntryID,
		EntryType:   r.EntryType,
		Timestamp:   r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
		GlobalSeq:   r.GlobalSeq,
		ContentHash: r.ContentHash,
		ChainHash:   r.ChainHash,
	}
	// v2 is written without a format_version field, exactly as before v3
	// existed, so an export of a v2 chain is byte-identical to what the
	// previous release produced. Only v2 carries a run id and a batch sequence.
	if chainformat.NormalizeFormatVersion(r.FormatVersion) == chainformat.FormatV2 {
		e.RunID = r.RunID
		e.SequenceNum = r.SequenceNum
	} else {
		e.FormatVersion = r.FormatVersion
	}
	return e
}

// entryWriter writes exported entries one at a time, as JSONL or as an
// indented JSON array.
//
// The bytes are the ones a json.Encoder with a two-space indent writes for the
// whole slice, so an export is byte-identical to what earlier releases wrote.
type entryWriter struct {
	w     *bufio.Writer
	jsonl bool
	n     int
}

func newEntryWriter(w io.Writer, jsonl bool) *entryWriter {
	return &entryWriter{w: bufio.NewWriterSize(w, 64<<10), jsonl: jsonl}
}

// write appends one entry.
func (ew *entryWriter) write(e verify.Entry) error {
	var doc []byte
	var err error
	sep := ""
	switch {
	case ew.jsonl:
		doc, err = json.Marshal(e)
	case ew.n == 0:
		sep = "[\n  "
		doc, err = json.MarshalIndent(e, "  ", "  ")
	default:
		sep = ",\n  "
		doc, err = json.MarshalIndent(e, "  ", "  ")
	}
	if err != nil {
		return fmt.Errorf("encode entry %d: %w", ew.n, err)
	}
	ew.n++
	if _, err := ew.w.WriteString(sep); err != nil {
		return err
	}
	if _, err := ew.w.Write(doc); err != nil {
		return err
	}
	if ew.jsonl {
		return ew.w.WriteByte('\n')
	}
	return nil
}

// close ends the array, if there is one, and flushes.
func (ew *entryWriter) close() error {
	if !ew.jsonl {
		end := "\n]\n"
		if ew.n == 0 {
			end = "[]\n"
		}
		if _, err := ew.w.WriteString(end); err != nil {
			return err
		}
	}
	return ew.w.Flush()
}

// cmdInit creates an empty chain database.
func cmdInit(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path to create")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "proof init: --db is required")
		return exitUsage
	}
	if _, err := os.Stat(*dbPath); err == nil {
		fmt.Fprintf(stderr, "proof init: %s already exists; refusing to overwrite\n", *dbPath)
		return exitUsage
	}
	if dir := filepath.Dir(*dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(stderr, "proof init: %v\n", err)
			return exitIOError
		}
	}
	s, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof init: %v\n", err)
		return exitIOError
	}
	if err := s.Close(); err != nil {
		fmt.Fprintf(stderr, "proof init: %v\n", err)
		return exitIOError
	}
	fmt.Fprintf(stdout, "created %s\n", *dbPath)
	return exitOK
}

// parseInterspersed parses flags that may appear before, after, or between
// positional arguments.
//
// # Description
//
// Go's flag package stops at the first argument that does not start with '-',
// so `cmd file --flag value` leaves `--flag value` unparsed and looking like
// two more positionals. Every modern CLI accepts the interleaved form, and an
// operator who types it should not get a confusing "expected exactly one file".
//
// This repeatedly hands the remainder back to the SAME FlagSet, so flag parsing
// stays the flag package's job — including knowing which flags consume the
// token after them. Nothing here inspects a flag name.
//
// # Inputs
//
//   - fs: a FlagSet with its flags already declared
//   - args: the raw arguments, minus the verb
//
// # Outputs
//
//   - []string: the positional arguments, in the order given
//   - error: whatever fs.Parse returned; fs has already reported it
//
// # Example
//
//	positional, err := parseInterspersed(fs, args)
//
// # Limitations
//
//   - A positional that begins with '-' is indistinguishable from a flag, as
//     everywhere else. Use "--" or "./-name".
//
// # Assumptions
//
//   - fs uses flag.ContinueOnError, so a parse failure returns rather than
//     exiting the process out from under the caller.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}
