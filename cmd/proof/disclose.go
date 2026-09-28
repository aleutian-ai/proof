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
	"time"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/internal/noncestore"
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

	ns, err := noncestore.Open(noncestore.PathFor(*dbPath), 5*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "proof disclose: %v\n", err)
		return exitIOError
	}
	nonce, err := ns.Get(*chainID, *entryID)
	ns.Close()
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
	ns, err := noncestore.Open(noncestore.PathFor(*dbPath), 5*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	defer ns.Close()
	if err := ns.Delete(*chainID, *entryID); err != nil {
		fmt.Fprintf(stderr, "proof forget: %v\n", err)
		return exitIOError
	}
	fmt.Fprintf(stdout, "forgot the nonce for %s on %s. The chain still verifies.\n"+
		"Not reached by this: backups of %s, anyone it was disclosed to, and any\n"+
		"conversation or log the content passed through.\n",
		*entryID, *chainID, noncestore.PathFor(*dbPath))
	return exitOK
}
