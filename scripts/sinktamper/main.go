// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build sinktamper

// Command sinktamper edits one stored event in a sink's secrets file, the way
// someone with write access to the folder could. It exists ONLY so
// scripts/container-check.sh can show that such an edit is caught (Verify
// reports the entry MODIFIED, on that chain alone). It is behind the sinktamper
// build tag, so a plain `go build ./...` or `go install ./...` never produces
// it, and it is never built into a release or an image.
//
//	go build -tags sinktamper ./scripts/sinktamper
//	sinktamper --dir sink-data --chain events.<hex> [--entry sink-<hex>] --content '{"user":"u-82","event":"edited"}'
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

func main() {
	dir := flag.String("dir", "sink-data", "the sink folder")
	chain := flag.String("chain", "", "the chain whose stored event to replace")
	entry := flag.String("entry", "", "the entry id to replace (default: the chain's first stored event)")
	content := flag.String("content", "", "the new bytes")
	flag.Parse()
	if *chain == "" || *content == "" {
		fmt.Fprintln(os.Stderr, "usage: sinktamper --dir D --chain C [--entry E] --content BYTES")
		os.Exit(2)
	}
	if err := tamper(filepath.Join(*dir, "evidence.db.secrets"), *chain, *entry, []byte(*content)); err != nil {
		fmt.Fprintf(os.Stderr, "sinktamper: %v\n", err)
		os.Exit(1)
	}
}

// tamper replaces one existing content row of chain: entry's, or the chain's
// first when entry is empty. It refuses a missing file (bbolt would create one)
// and gives up rather than wait forever on a held lock.
func tamper(path, chain, entry string, content []byte) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("content"))
		if b == nil {
			return fmt.Errorf("%s has no content bucket", path)
		}
		prefix := append([]byte(chain), 0)
		var key []byte
		if entry != "" {
			key = append(prefix, entry...)
			if b.Get(key) == nil {
				return errors.New("no stored event with that entry id on that chain")
			}
		} else {
			k, _ := b.Cursor().Seek(prefix)
			if k == nil || !bytes.HasPrefix(k, prefix) {
				return errors.New("no stored event on that chain")
			}
			key = append([]byte(nil), k...)
		}
		return b.Put(key, content)
	})
}
