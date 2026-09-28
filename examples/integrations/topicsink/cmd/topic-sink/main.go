// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command topic-sink commits a keyed stream of JSON events to one proof chain
// per key, and checkpoints, verifies and erases each chain on its own.
//
//	topic-sink commit -key user < events.jsonl     route each line by its "user" field
//	topic-sink checkpoint -key-file ml-dsa-65-private.pem
//	topic-sink verify -pub-file ml-dsa-65-public.pem
//	topic-sink erase -chain u-81
//
// Everything lives in one folder (-dir, default ./sink-data). The signing key
// comes from `proof keygen --alg ml-dsa-65`. See package topicsink for the
// layout and what each step guarantees.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/examples/integrations/topicsink"
	"github.com/aleutian-ai/proof/keyfile"
)

// maxLine caps one input line. Longer than a record may be, so an oversized
// record is refused by the sink with its real reason rather than by the scanner.
const maxLine = 1 << 20

const (
	exitOK      = 0
	exitFailed  = 1 // an operation failed, or verification found problems
	exitUsage   = 2
	usageString = "usage: topic-sink commit|checkpoint|verify|erase [-dir D] [flags]\n" +
		"  commit     -key FIELD      JSONL on stdin, routed by FIELD\n" +
		"  checkpoint -key-file PEM   ML-DSA-65 private key from `proof keygen`\n" +
		"  verify     -pub-file PEM   its public key\n" +
		"  erase      -chain ID"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, usageString)
		return exitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "folder holding the evidence file, nonces, content and checkpoints")
	key := fs.String("key", "", "commit: the JSON field to route by")
	keyFile := fs.String("key-file", "", "checkpoint: ML-DSA-65 private key (PEM)")
	pubFile := fs.String("pub-file", "", "verify: ML-DSA-65 public key (PEM)")
	chain := fs.String("chain", "", "erase: the chain to erase")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "topic-sink %s: unexpected argument %q\n", cmd, fs.Arg(0))
		return exitUsage
	}

	need := map[string]*string{"commit": key, "checkpoint": keyFile, "verify": pubFile, "erase": chain}
	flagName := map[string]string{"commit": "-key", "checkpoint": "-key-file", "verify": "-pub-file", "erase": "-chain"}
	v, known := need[cmd]
	if !known {
		fmt.Fprintln(stderr, usageString)
		return exitUsage
	}
	if *v == "" {
		fmt.Fprintf(stderr, "topic-sink %s: %s is required\n", cmd, flagName[cmd])
		return exitUsage
	}

	sink, err := topicsink.Open(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "topic-sink: %v\n", err)
		return exitFailed
	}
	ctx := context.Background()
	switch cmd {
	case "commit":
		err = cmdCommit(ctx, sink, *key, stdin, stdout)
	case "checkpoint":
		err = cmdCheckpoint(ctx, sink, *keyFile, stdout)
	case "verify":
		err = cmdVerify(ctx, sink, *pubFile, stdout)
	case "erase":
		err = cmdErase(ctx, sink, *chain, stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "topic-sink %s: %v\n", cmd, err)
		return exitFailed
	}
	return exitOK
}

// cmdCommit reads JSONL and commits it in batches of topicsink.MaxBatch.
//
// Every line of a batch is parsed before the batch is committed, so a bad line
// stops the run with the lines before its batch committed and none after.
func cmdCommit(ctx context.Context, sink *topicsink.Sink, field string, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	totals := map[string]int{}
	var order []string
	var batch []topicsink.Record
	lines := 0

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		done, err := sink.Commit(ctx, batch)
		for _, c := range done {
			if totals[c.Chain] == 0 {
				order = append(order, c.Chain)
			}
			totals[c.Chain] += c.Entries
		}
		batch = batch[:0]
		return err
	}

	// Totals are printed however the run ends: a failure in a later batch does
	// not undo the batches before it, and the operator needs to know about them.
	defer func() {
		for _, c := range order {
			fmt.Fprintf(out, "committed %4d → chain %s\n", totals[c], c)
		}
	}()

	for sc.Scan() {
		lines++
		line := sc.Bytes() // committed exactly as it arrived; only blank lines are skipped
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		r, err := topicsink.RecordFromJSON(line, field)
		if err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
		if _, err := topicsink.ChainFor(r.Key); err != nil {
			return fmt.Errorf("line %d: %w", lines, err)
		}
		batch = append(batch, r)
		if len(batch) == topicsink.MaxBatch {
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
	if len(order) == 0 {
		return errors.New("no events on stdin")
	}
	return nil
}

func cmdCheckpoint(ctx context.Context, sink *topicsink.Sink, keyFile string, out io.Writer) error {
	pem, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	alg, seed, err := keyfile.ParsePrivateKey(pem)
	if err != nil {
		return fmt.Errorf("parse %s: %w", keyFile, err)
	}
	defer clear(seed)
	if alg != keyfile.MLDSA65 {
		return fmt.Errorf("%s holds a %s key; checkpoints are signed with ML-DSA-65 "+
			"(proof keygen --alg ml-dsa-65)", keyFile, alg)
	}
	signer, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		return err
	}
	defer signer.Close()

	done, err := sink.Checkpoint(ctx, signer)
	for _, c := range done {
		fmt.Fprintf(out, "checkpoint %s signed over %s\n", c.File, plural(int(c.Entries), "entry", "entries"))
	}
	if err != nil {
		return err
	}
	if len(done) == 0 {
		fmt.Fprintln(out, "nothing new since the last checkpoints")
	}
	return nil
}

func cmdVerify(ctx context.Context, sink *topicsink.Sink, pubFile string, out io.Writer) error {
	pem, err := os.ReadFile(pubFile)
	if err != nil {
		return err
	}
	alg, pub, err := keyfile.ParsePublicKey(pem)
	if err != nil {
		return fmt.Errorf("parse %s: %w", pubFile, err)
	}
	if alg != keyfile.MLDSA65 {
		return fmt.Errorf("%s holds a %s key, want ML-DSA-65", pubFile, alg)
	}
	id, err := keyfile.KeyIDHex(alg, pub)
	if err != nil {
		return err
	}
	ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	if err != nil {
		return err
	}

	rep, err := sink.Verify(ctx, ring)
	if err != nil {
		return err
	}
	if len(rep.Chains) == 0 {
		return errors.New("the evidence file has no chains")
	}
	bad := 0
	for _, c := range rep.Chains {
		verdict := "verifies"
		if len(c.Problems) > 0 {
			verdict = "FAILS"
			bad++
		}
		fmt.Fprintf(out, "chain %-12s %-8s %s: %d opened, %d erased · %s, %d unanchored\n",
			c.Chain, verdict, plural(c.Entries, "entry", "entries"), c.Opened, c.Erased,
			plural(c.Checkpoints, "checkpoint", "checkpoints"), c.Unanchored)
		for _, p := range c.Problems {
			fmt.Fprintf(out, "    %s\n", p)
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d chains failed", bad, len(rep.Chains))
	}
	fmt.Fprintf(out, "all %d chains verify\n", len(rep.Chains))
	return nil
}

func cmdErase(ctx context.Context, sink *topicsink.Sink, chain string, out io.Writer) error {
	res, err := sink.Erase(ctx, chain)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "erased %s on chain %s; the erasure is entry %s.\n"+
		"Their content and nonces are deleted: no one can open them again, and the chain still verifies.\n"+
		"Not reached by this: backups of %s, anyone an event or nonce was disclosed to,\n"+
		"and the chain id itself, which stays in the chain and its checkpoints.\n",
		plural(res.Events, "event", "events"), res.Chain, res.ErasureEntryID, strings.TrimSuffix(sink.DBPath(), "evidence.db"))
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
