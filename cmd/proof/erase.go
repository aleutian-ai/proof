// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	ctx "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/internal/noncestore"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// cmdErase erases one v4 entry in place (docs/format-spec.md §5.0).
//
// The entry loses its id, type, content hash and salt, and keeps its position,
// timestamp, leaf hash and chain hash, so the chain still verifies and an
// anchor over it still binds. Its nonce, if it has one, is forgotten, and both
// files are rewritten so the removed bytes are not left in them. A v2 or v3
// entry is not erased in place: those formats are frozen, and `proof forget`
// destroys its nonce instead.
func cmdErase(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "evidence database")
	chainID := fs.String("chain", "", "chain the entry is on")
	seq := fs.Int64("seq", -1, "global_seq of the entry to erase")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dbPath == "" || *chainID == "" || *seq < 0 {
		fmt.Fprintln(stderr, "proof erase: --db, --chain and --seq are required")
		return exitUsage
	}
	// Nothing is created here: a mistyped --db must fail, not make an empty
	// database and report that nothing was found in it.
	if _, err := os.Lstat(*dbPath); err != nil {
		fmt.Fprintf(stderr, "proof erase: %v\n", err)
		return exitIOError
	}

	// A symlink is refused: the nonce file and the compaction are found by
	// --db's own name, and through a link they would be found beside the link.
	st, err := boltstore.Open(*dbPath, boltstore.WithNoFollow())
	if err != nil {
		fmt.Fprintf(stderr, "proof erase: %v\n", err)
		if errors.Is(err, boltstore.ErrLocked) {
			return exitBusy
		}
		return exitIOError
	}

	// The order makes every step retryable by running the same command: the
	// nonce is forgotten while the entry still names it, then the entry is
	// erased, then the database is rewritten whatever came before. An entry
	// erased first would leave a nonce keyed under an id nothing holds any
	// more, which `proof forget` could not be pointed at.
	got, err := st.Range(ctx.Background(), *chainID, *seq, *seq, 1)
	switch {
	case err != nil:
		st.Close()
		fmt.Fprintf(stderr, "proof erase: %v\n", err)
		return exitIOError
	case len(got) == 0:
		st.Close()
		fmt.Fprintf(stderr, "proof erase: no entry at global_seq %d on chain %q; nothing was erased\n", *seq, *chainID)
		return exitUsage
	case got[0].FormatVersion != chainformat.FormatV4:
		st.Close()
		fmt.Fprintf(stderr, "proof erase: the entry at global_seq %d is not v4. v2 and v3 entries are not "+
			"erased in place (their formats are frozen); `proof forget` destroys a salted entry's nonce\n", *seq)
		return exitUsage
	}
	already := got[0].Erased

	// The nonce file is serialised by the evidence database's lock, held here.
	noncePath := noncestore.PathFor(*dbPath)
	nonce := "it had no stored nonce (a content_hash entry)"
	if already {
		// Its id is gone, so its nonce can no longer be looked up; a nonce
		// forgotten by an earlier run whose rewrite was interrupted is still
		// cleared from the file's free pages here.
		nonce = "its nonce file was rewritten"
		if _, err := os.Lstat(noncePath); errors.Is(err, os.ErrNotExist) {
			nonce = "there is no nonce file"
		} else if err := noncestore.Compact(noncePath, 5*time.Second); err != nil {
			st.Close()
			fmt.Fprintf(stderr, "proof erase: rewriting %s failed: %v. Run `proof erase` again to retry\n", noncePath, err)
			return exitIOError
		}
	} else {
		switch err := noncestore.Forget(noncePath, *chainID, got[0].EntryID, 5*time.Second); {
		case errors.Is(err, noncestore.ErrNotFound), errors.Is(err, noncestore.ErrNoFile):
		case err != nil:
			st.Close()
			fmt.Fprintf(stderr, "proof erase: nothing was erased: forgetting the entry's nonce failed: %v. "+
				"Run `proof erase` again to retry\n", err)
			return exitIOError
		default:
			nonce = "its nonce was forgotten and " + noncePath + " rewritten"
		}
		if _, err := st.Erase(ctx.Background(), *chainID, *seq); err != nil {
			st.Close()
			fmt.Fprintf(stderr, "proof erase: %v. Run `proof erase` again to retry\n", err)
			return exitIOError
		}
	}
	if err := st.Close(); err != nil {
		fmt.Fprintf(stderr, "proof erase: %v\n", err)
		return exitIOError
	}
	if err := boltstore.CompactFile(*dbPath); err != nil {
		fmt.Fprintf(stderr, "proof erase: the entry is erased, but rewriting %s failed, so its old bytes "+
			"may remain in the file's free pages: %v. Run `proof erase` again to retry\n", *dbPath, err)
		return exitIOError
	}
	if already {
		fmt.Fprintf(stdout, "the entry at global_seq %d on %s was erased already; %s, and %s was rewritten\n"+
			"so no removed bytes are left in it.\n", *seq, *chainID, nonce, *dbPath)
		return exitOK
	}
	fmt.Fprintf(stdout, "erased the entry at global_seq %d on %s: its id, type, content hash and salt are\n"+
		"gone, %s, and %s was rewritten so the removed bytes are not left in it.\n"+
		"The chain still verifies, and an anchor over it still binds.\n"+
		"Not reached by this: backups and snapshots of those files, the storage device's own\n"+
		"spare blocks, earlier exports, and anyone the entry was disclosed to.\n",
		*seq, *chainID, nonce, *dbPath)
	return exitOK
}
