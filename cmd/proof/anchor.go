// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	ctx "context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/internal/mem"
	"github.com/aleutian-ai/proof/keyfile"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// cmdAnchor produces a signed anchor over a stored chain.
//
// This verb lives in the human CLI and NEVER on the MCP surface. It takes a
// private key, and MCP results reach a model provider; cmd/proof-mcp's
// TestNoKeyMaterialTools fails the build if a key-handling tool is registered.
// The same rule that keeps `keygen` here keeps this here.
func cmdAnchor(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("anchor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "chain database path")
	chainID := fs.String("chain", "", "chain id to anchor")
	subject := fs.String("subject", "", "what this chain is about: a stable pseudonym or opaque id, NEVER personal data")
	keyPath := fs.String("key", "", "ML-DSA-65 private key (PKCS#8 PEM, from `proof keygen`)")
	prevPath := fs.String("previous", "", "the previous anchor's JSON; omit for the first anchor in a chain")
	outPath := fs.String("out", "", "write the anchor here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch {
	case *dbPath == "":
		fmt.Fprintln(stderr, "proof anchor: --db is required")
		return exitUsage
	case *chainID == "":
		fmt.Fprintln(stderr, "proof anchor: --chain is required")
		return exitUsage
	case *subject == "":
		fmt.Fprintln(stderr, "proof anchor: --subject is required. It is inside the signed\n"+
			"bytes, so an anchor cannot be replayed onto another chain — and so it can\n"+
			"never be erased or corrected afterwards. Use a stable pseudonym or an\n"+
			"opaque id, never a name, an email address or a device hostname.")
		return exitUsage
	case *keyPath == "":
		fmt.Fprintln(stderr, "proof anchor: --key is required (an ML-DSA-65 private key from `proof keygen`)")
		return exitUsage
	}

	signer, err := loadSigner(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof anchor: %v\n", err)
		return exitIOError
	}
	defer signer.Close()

	entries, err := readChain(*dbPath, *chainID)
	if err != nil {
		fmt.Fprintf(stderr, "proof anchor: %v\n", err)
		return exitIOError
	}
	if len(entries) == 0 {
		fmt.Fprintf(stderr, "proof anchor: chain %q has no entries\n", *chainID)
		return exitIOError
	}

	var previous *anchor.Anchor
	if *prevPath != "" {
		previous, err = loadAnchorFile(*prevPath)
		if err != nil {
			fmt.Fprintf(stderr, "proof anchor: %v\n", err)
			return exitIOError
		}
	}

	built, err := build.Anchor(ctx.Background(), build.Input{
		Subject:  *subject,
		Entries:  entries,
		Previous: previous,
	})
	if err != nil {
		// A broken chain is a VERDICT, not an I/O failure. It shares an exit
		// code with `proof verify` so a script can treat "this chain is broken"
		// the same way whichever verb discovered it.
		if errors.Is(err, build.ErrChainBroken) {
			fmt.Fprintf(stderr, "proof anchor: %v\n", err)
			return exitBroken
		}
		fmt.Fprintf(stderr, "proof anchor: %v\n", err)
		return exitIOError
	}

	signed, err := anchor.SignAnchor(ctx.Background(), signer, built)
	if err != nil {
		fmt.Fprintf(stderr, "proof anchor: %v\n", err)
		return exitIOError
	}

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "proof anchor: %v\n", err)
			return exitIOError
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(signed); err != nil {
		fmt.Fprintf(stderr, "proof anchor: encode anchor: %v\n", err)
		return exitIOError
	}

	// The summary goes to stderr when the anchor itself is going to stdout, so
	// `proof anchor … > a.json` produces a clean file rather than one with a
	// human report pasted on top.
	report := stderr
	if *outPath != "" {
		report = stdout
	}
	printAnchorSummary(report, signed, previous)
	return exitOK
}

// printAnchorSummary renders what was produced, and what it does not establish.
func printAnchorSummary(w *os.File, a anchor.Anchor, previous *anchor.Anchor) {
	fmt.Fprintf(w, "\nanchored %d entries\n\n", a.EntryCount)
	fmt.Fprintf(w, "  anchor id   %s\n", a.AnchorID)
	fmt.Fprintf(w, "  subject     %s\n", a.Subject)
	fmt.Fprintf(w, "  range       %s … %s\n", a.Range.StartEntryID, a.Range.EndEntryID)
	fmt.Fprintf(w, "  key id      %s\n", a.SigningKeyID)
	if previous == nil {
		fmt.Fprintf(w, "  previous    (none — this is the first anchor in the chain)\n")
	} else {
		fmt.Fprintf(w, "  previous    %s\n", previous.AnchorID)
	}

	fmt.Fprintln(w, "\n  Proven:     these entries link, and nothing was edited under you.")
	fmt.Fprintln(w, "  NOT proven: that this anchor is an independent witness. It becomes")
	fmt.Fprintln(w, "              one only when it reaches a reader by a path you cannot")
	fmt.Fprintln(w, "              rewrite. Kept beside the chain it describes, it proves")
	fmt.Fprintln(w, "              consistency and nothing more.")

	if previous != nil {
		fmt.Fprintf(w, "\n  To verify this anchor, a reader needs the PREVIOUS anchor's chain\n"+
			"  hash. It is inside this one's signature and is not recoverable from\n"+
			"  this file alone:\n\n    %s\n", previous.ChainHash)
	}
}

// zeroizeSeed scrubs the seed once the signer has copied it.
//
// It is a variable for one reason: the scrub is otherwise unobservable — the
// slice goes out of scope immediately, so no test can tell a working call from
// a deleted one, and a mutation deleting it survived. Replacing this lets a
// test hold the backing array and check it. Nothing but the test replaces it.
//
// Same seam, same justification, as keygen.go's selfTestFn.
var zeroizeSeed = mem.Zeroize

// loadSigner reads an ML-DSA-65 private key and returns a signer.
//
// The seed is zeroized as soon as the signer has copied it, so the CLI holds
// the key material for as short a window as it can. That narrows one window; it
// does not empty the process — see anchor.MLDSA65Signer's limitations.
func loadSigner(path string) (*anchor.MLDSA65Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	alg, seed, err := keyfile.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	defer zeroizeSeed(seed)

	if alg != keyfile.MLDSA65 {
		// Name what was supplied and what is needed. "wrong algorithm" sends an
		// operator to check the wrong thing.
		return nil, fmt.Errorf("%s holds a %s key, but anchors are signed with ML-DSA-65. "+
			"Generate one with: proof keygen --alg ml-dsa-65", path, alg)
	}

	s, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	return s, nil
}

// loadAnchorFile reads an anchor from JSON.
func loadAnchorFile(path string) (*anchor.Anchor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var a anchor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("parse %s as an anchor: %w", path, err)
	}
	if a.ChainHash == "" {
		return nil, fmt.Errorf("%s has no chain_hash; the next anchor commits to it, "+
			"so it cannot be chained from", path)
	}
	return &a, nil
}

// readChain loads every entry of a chain in ascending sequence order.
func readChain(dbPath, chainID string) ([]verify.Entry, error) {
	s, err := boltstore.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	rows, err := s.Range(ctx.Background(), chainID, 0, 1<<62, 0)
	if err != nil {
		return nil, err
	}
	entries := make([]verify.Entry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, toExported(r))
	}
	return entries, nil
}
