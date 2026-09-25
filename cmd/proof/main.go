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
  proof export --db <path> --chain <id> [--out <path>] [--jsonl]
  proof init   --db <path>
  proof keygen [--alg x-wing] [--out-dir .] [--slot primary|backup|dual]
               [--name LABEL] [--op-vault VAULT] [--force]
  proof anchor --db <path> --chain <id> --subject <s> --key <private.pem>
               [--previous <anchor.json>] [--out <path>]

exit: 0 ok · 1 chain broken · 2 usage · 3 io error

verify reads only the file you name. No network, no credentials.

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
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "proof verify: expected exactly one entries file")
		return exitUsage
	}

	entries, err := loadEntries(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitIOError
	}

	res, err := verify.Chain(entries, verify.Options{MaxBreaks: *maxBreaks})
	if err != nil {
		fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitIOError
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "proof verify: encode result: %v\n", err)
			return exitIOError
		}
	} else {
		printResult(stdout, res)
	}
	if res.Verdict == verify.VerdictBroken {
		return exitBroken
	}
	return exitOK
}

// printResult renders a human-readable verdict.
//
// The wording is deliberate. It reports what was actually established — that
// nothing was edited — and states plainly what was NOT, because a reader who
// sees "verified" will otherwise assume the stronger claim.
func printResult(w *os.File, res verify.Result) {
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
		fmt.Fprintln(w, "  NOT proven: that this is the whole chain. Entries could have been")
		fmt.Fprintln(w, "              removed from the front and the rest re-linked; detecting")
		fmt.Fprintln(w, "              that needs an anchor, which was not checked here.")
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
