// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build bundlefixture

// Command bundlefixture builds a real sink with fixed keys and exports it with
// `sink.Export`, for the bundle conformance vectors (`_72c`). It writes the
// bundle together with a description of what it BUILT (chains, events,
// erasure positions, checkpoints), so scripts/bundle-vectors.py derives the
// expected result from the construction and the spec, never by verifying the
// bundle. It is behind the bundlefixture build tag: never built into a
// release or an image.
//
//	go run -tags bundlefixture ./scripts/bundlefixture > scripts/bundlefixture/real_export.json
//
// Chain ids, entry ids, nonces and timestamps are random, so a regenerated
// fixture differs: regenerate deliberately, then rerun bundle-vectors.py.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/sink"
)

// The seeds the vectors use (scripts/bundle-vectors.py): checkpoint key 0x11…,
// record key 0x22….
var (
	checkpointSeed = bytes.Repeat([]byte{0x11}, 32)
	recordSeed     = bytes.Repeat([]byte{0x22}, 32)
)

type builtChain struct {
	ChainID                  string `json:"chain_id"`
	Entries                  int    `json:"entries"`
	Events                   int    `json:"events"`
	ErasureIndex             int    `json:"erasure_index"` // -1: none
	Checkpoints              int    `json:"checkpoints"`
	LastCheckpointEntryCount int    `json:"last_checkpoint_entry_count"`
	DisclosedEvents          int    `json:"disclosed_events"`
	RecordSigned             bool   `json:"record_signed"` // every entry, the erasure too
}

type output struct {
	Comment   string       `json:"_comment"`
	BundleB64 string       `json:"bundle_b64"`
	Built     []builtChain `json:"built"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bundlefixture:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "bundlefixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	rs, err := sink.NewMLDSA65RecordSigner(recordSeed)
	if err != nil {
		return err
	}
	defer rs.Close()
	cp, err := anchor.NewMLDSA65Signer(checkpointSeed)
	if err != nil {
		return err
	}
	s, err := sink.Open(dir, sink.WithRecordSigner(rs))
	if err != nil {
		return err
	}

	// Three subjects: u-1 three events, u-2 two, u-3 one.
	counts := map[string]int{"u-1": 3, "u-2": 2, "u-3": 1}
	var recs []sink.Record
	for _, subj := range []string{"u-1", "u-2", "u-1", "u-3", "u-2", "u-1"} {
		recs = append(recs, sink.Record{Class: "events", Subject: subj,
			Content: []byte(fmt.Sprintf(`{"subject":"%s","n":%d}`, subj, len(recs)))})
	}
	if _, err := s.Commit(ctx, recs); err != nil {
		return err
	}
	pairs, err := s.ChainSubjects(ctx)
	if err != nil {
		return err
	}
	chainOf := map[string]string{}
	for _, p := range pairs {
		chainOf[p.Subject] = p.Chain
	}
	if _, err := s.Checkpoint(ctx, cp, nil); err != nil {
		return err
	}
	// Erase u-2, then checkpoint again: only u-2's chain has new entries, so
	// only it gets a second checkpoint, which covers its erasure.
	if _, err := s.EraseSubject(ctx, "u-2"); err != nil {
		return err
	}
	if _, err := s.Checkpoint(ctx, cp, nil); err != nil {
		return err
	}

	var buf bytes.Buffer
	if _, err := s.Export(ctx, sink.ExportSelection{All: true, Disclose: sink.DiscloseAll}, &buf); err != nil {
		return err
	}
	out := output{
		Comment: "A real proof sink export (scripts/bundlefixture), with the facts of what was built. " +
			"Keys: checkpoint seed 0x11 x32, record seed 0x22 x32. bundle-vectors.py derives the expected " +
			"result from `built` and the spec, never by verifying the bundle.",
		BundleB64: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}
	for _, subj := range []string{"u-1", "u-2", "u-3"} {
		b := builtChain{ChainID: chainOf[subj], Events: counts[subj], ErasureIndex: -1, Checkpoints: 1,
			Entries: counts[subj], LastCheckpointEntryCount: counts[subj], DisclosedEvents: counts[subj],
			RecordSigned: true}
		if subj == "u-2" {
			b.Entries = counts[subj] + 1
			b.ErasureIndex = counts[subj]
			b.Checkpoints = 2
			b.LastCheckpointEntryCount = b.Entries
			b.DisclosedEvents = 0
		}
		out.Built = append(out.Built, b)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
