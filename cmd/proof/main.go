// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command proof verifies and inspects AleutianChain audit chains.
//
// # Description
//
// A single static binary with no network access, no credentials, and no cloud
// dependencies. It reads local files the caller points it at and nothing else.
// Those constraints are the product: an agent or auditor can check a chain
// without an account and without trusting the party that produced it.
//
// # Subcommands
//
//	proof verify <entries.json>   check a chain's linkage
//	proof export --db <path>      dump a chain to portable JSON
//	proof init --db <path>        create an empty chain database
//
// # Exit codes
//
//	0  verification passed / command succeeded
//	1  verification FAILED — the chain is broken
//	2  usage error
//	3  I/O or parse error
//
// The distinction between 1 and 3 matters in a script: "the chain is broken" and
// "I could not read the file" call for different responses, and collapsing them
// into "non-zero" loses that.
package main

import (
	ctx "context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
func run(args []string, stdout, stderr *os.File) int {
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
	case "append":
		return cmdAppend(args[1:], stdout, stderr)
	case "import":
		return cmdImport(args[1:], stdout, stderr)
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
	fmt.Fprint(w, `proof — verify AleutianChain audit chains

usage:
  proof verify <entries.json> [--json] [--max-breaks N]
               [--anchor <anchor.json>] [--previous <prev.json>]
               [--key <public.pem>] [--key-trust platform|provided|self]
  proof export --db <path> --chain <id> [--out <path>] [--jsonl]
  proof init   --db <path>
  proof append --db <path> --chain <id> [--format-v2]   < entries.jsonl
  proof import --db <path> --chain <id>                 < exported.jsonl
  proof keygen [--alg x-wing] [--out-dir .] [--slot primary|backup|dual]
               [--name LABEL] [--op-vault VAULT] [--force]
  proof anchor --db <path> --chain <id> --subject <s> --key <private.pem>
               [--previous <anchor.json>] [--out <path>]

exit: 0 ok · 1 chain broken · 2 usage · 3 io error · 4 chain busy

verify reads only the files you name. No network, no credentials.

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

	entries, err := loadEntries(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitIOError
	}

	res, err := verify.Chain(entries, verify.Options{MaxBreaks: *maxBreaks})
	if err != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitIOError
	}

	anchorRes, aerr := verifyAnchorFlags(opts, entries)
	if aerr != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", aerr)
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
			if b.Expected != "" {
				fmt.Fprintf(w, "       expected %s…\n       actual   %s…\n",
					b.Expected[:32], b.Actual[:32])
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
		fmt.Fprintln(w, "\n  Proven:     nothing was edited under you.")
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

// loadEntries reads exported entries as a JSON array or as JSONL.
//
// The format is sniffed rather than flagged: a caller verifying a file someone
// handed them should not have to know which shape it is.
func loadEntries(path string) ([]verify.Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseEntries(raw, path)
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

// parseEntries decodes a JSON array or JSONL, whichever it was handed.
func parseEntries(raw []byte, path string) ([]verify.Entry, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("%s is empty", path)
	}

	if strings.HasPrefix(trimmed, "[") {
		var entries []verify.Entry
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return nil, fmt.Errorf("parse %s as a JSON array: %w", path, err)
		}
		return entries, nil
	}

	var entries []verify.Entry
	for i, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e verify.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("parse %s line %d: %w", path, i+1, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// cmdExport dumps a chain to portable JSON.
func cmdExport(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to export")
	outPath := fs.String("out", "", "write here instead of stdout")
	asJSONL := fs.Bool("jsonl", false, "one entry per line instead of a JSON array")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" {
		fmt.Fprintln(stderr, "proof export: --db and --chain are required")
		return exitUsage
	}

	s, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	defer s.Close()

	rows, err := s.Range(ctx.Background(), *chainID, 0, 1<<62, 0)
	if err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}

	entries := make([]verify.Entry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, toExported(r))
	}

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "proof export: %v\n", err)
			return exitIOError
		}
		defer f.Close()
		out = f
	}
	if err := writeEntries(out, entries, *asJSONL); err != nil {
		fmt.Fprintf(stderr, "proof export: %v\n", err)
		return exitIOError
	}
	return exitOK
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

func writeEntries(w *os.File, entries []verify.Entry, jsonl bool) error {
	if jsonl {
		enc := json.NewEncoder(w)
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return fmt.Errorf("encode entry %s: %w", e.EntryID, err)
			}
		}
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
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
