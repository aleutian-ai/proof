// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

// disclosure is what an operator hands a third party, together with the content
// itself, to prove one salted-commitment entry. Nothing in it is secret any more
// once it is handed over: disclosing an entry means revealing its nonce.
type disclosure struct {
	Chain      string `json:"chain"`
	EntryID    string `json:"entry_id"`
	EntryType  string `json:"entry_type"`
	GlobalSeq  int64  `json:"global_seq"`
	Timestamp  string `json:"timestamp"`
	Commitment string `json:"commitment"`
	Nonce      string `json:"nonce"`
}

// cmdDisclose proves that given content is what a salted-commitment entry holds.
//
// The nonce comes from the local nonce file that proof-mcp's commit tool writes
// beside the database. The command refuses to emit a disclosure that does not
// verify, so an operator cannot hand over a proof that fails.
func cmdDisclose(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("disclose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "evidence database")
	chainID := fs.String("chain", "", "chain the entry is on")
	entryID := fs.String("entry", "", "entry id to disclose")
	contentPath := fs.String("content", "", "file holding the entry's original content")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" || *entryID == "" || *contentPath == "" {
		fmt.Fprintln(stderr, "proof disclose: --db, --chain, --entry and --content are required")
		return exitUsage
	}

	if _, err := os.Lstat(*dbPath); err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}
	entries, err := readChain(*dbPath, *chainID)
	if err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}
	var entry *verify.Entry
	for i := range entries {
		if entries[i].EntryID == *entryID {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		fmt.Fprintf(stderr, "proof disclose: no entry %q on chain %q\n", *entryID, *chainID)
		return exitIOError
	}

	// Read-only, so nothing is created: with no nonce file there is no nonce.
	var nonce []byte
	if _, lerr := os.Lstat(noncestore.PathFor(*dbPath)); errors.Is(lerr, os.ErrNotExist) {
		err = noncestore.ErrNotFound
	} else {
		ns, oerr := noncestore.OpenReadOnly(noncestore.PathFor(*dbPath), 5*time.Second)
		if oerr != nil {
			fmt.Fprintf(stderr, "proof disclose: %v\n", oerr)
			return exitIOError
		}
		nonce, err = ns.Get(*chainID, *entryID)
		ns.Close()
	}
	if errors.Is(err, noncestore.ErrNotFound) {
		fmt.Fprintf(stderr, "proof disclose: no nonce stored for %s. Either it was a "+
			"content_hash entry (no salt to disclose), or its nonce was forgotten — in "+
			"which case the entry can no longer be opened by anyone.\n", *entryID)
		return exitIOError
	}
	if err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}

	content, err := os.ReadFile(*contentPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}
	if !commitment.Verify(entry.ContentHash, nonce, content) {
		fmt.Fprintf(stderr, "proof disclose: %s does not open entry %s: this is not the "+
			"content that was committed\n", *contentPath, *entryID)
		return exitBroken
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(disclosure{
		Chain: *chainID, EntryID: entry.EntryID, EntryType: entry.EntryType,
		GlobalSeq: entry.GlobalSeq, Timestamp: entry.Timestamp,
		Commitment: entry.ContentHash, Nonce: hex.EncodeToString(nonce),
	}); err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}
	return exitOK
}

// cmdForget erases one entry's nonce, so the entry can never be opened again.
//
// The chain still verifies: it holds only the commitment. What forget cannot
// reach is every OTHER copy of the nonce or the content — backups, earlier
// disclosures, and the conversation the content passed through. It says so.
func cmdForget(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "evidence database")
	chainID := fs.String("chain", "", "chain the entry is on")
	entryID := fs.String("entry", "", "entry id whose nonce to erase")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" || *entryID == "" {
		fmt.Fprintln(stderr, "proof forget: --db, --chain and --entry are required")
		return exitUsage
	}
	// Nothing is created here: a mistyped --db must fail, not make an empty
	// database and nonce file and report that the nonce was forgotten.
	if _, err := os.Lstat(*dbPath); err != nil {
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	entries, err := readChain(*dbPath, *chainID)
	if err != nil {
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	if !slices.ContainsFunc(entries, func(e verify.Entry) bool { return e.EntryID == *entryID }) {
		fmt.Fprintf(stderr, "proof forget: no entry %q on chain %q; nothing was forgotten\n", *entryID, *chainID)
		return exitIOError
	}
	// The evidence database's lock is what serializes writers of the nonce
	// file. Held here because forget replaces that file with a rewritten copy.
	st, err := boltstore.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	defer st.Close()

	noncePath := noncestore.PathFor(*dbPath)
	switch err := noncestore.Forget(noncePath, *chainID, *entryID, 5*time.Second); {
	case errors.Is(err, noncestore.ErrNotFound), errors.Is(err, noncestore.ErrNoFile):
		fmt.Fprintf(stdout, "no nonce is stored for %s on %s: it was forgotten already, or the entry "+
			"never had one (a content_hash entry). Nothing was deleted.\n", *entryID, *chainID)
		return exitOK
	case err != nil:
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	fmt.Fprintf(stdout, "forgot the nonce for %s on %s, and rewrote %s so its bytes are not left\n"+
		"in the file. The chain still verifies.\n"+
		"Not reached by this: backups and snapshots of that file, the storage device's own\n"+
		"spare blocks, anyone the entry was disclosed to, and any conversation or log the\n"+
		"content passed through.\n",
		*entryID, *chainID, noncePath)
	return exitOK
}
