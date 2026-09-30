// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// Commit events about two users, checkpoint every chain, erase one user, and verify.
func Example() {
	ctx := context.Background()
	dir, _ := os.MkdirTemp("", "sink-example")
	defer os.RemoveAll(dir)
	s, err := sink.Open(dir)
	if err != nil {
		panic(err)
	}

	// Subjects must already be pseudonyms: the rule refuses, never transforms.
	if !sink.ValidSubject("jo@example.com") {
		fmt.Println("refused an email as a subject")
	}

	recs := []sink.Record{
		{Class: "events", Subject: "u-81", Content: []byte(`{"event":"login"}`), Source: "EVIDENCE@1:1"},
		{Class: "events", Subject: "u-82", Content: []byte(`{"event":"login"}`), Source: "EVIDENCE@1:2"},
		{Class: "events", Subject: "u-81", Content: []byte(`{"event":"logout"}`), Source: "EVIDENCE@1:3"},
	}
	out, err := s.Commit(ctx, recs)
	if err != nil {
		panic(err)
	}
	// One outcome per record, in order, naming neither subject nor chain.
	fmt.Println("committed:", out[0].Committed, out[1].Committed, out[2].Committed)

	// Which chain holds whom is secret-index material, read deliberately. The
	// demo keeps it only to label the report below.
	rows, err := s.ChainSubjects(ctx)
	if err != nil {
		panic(err)
	}
	subjectOf := map[string]string{}
	for _, r := range rows {
		subjectOf[r.Chain] = r.Subject
	}
	fmt.Println("opaque chains:", len(rows))

	// The first record again, as after a crash between commit and ack.
	again, _ := s.Commit(ctx, recs[:1])
	fmt.Printf("redelivered: committed %v, duplicate %v\n", again[0].Committed, again[0].Duplicate)

	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	_, _ = rand.Read(seed)
	signer, _ := anchor.NewMLDSA65Signer(seed)
	defer signer.Close()
	if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
		panic(err)
	}
	if _, err := s.EraseSubject(ctx, "u-81"); err != nil {
		panic(err)
	}

	id, pub, _ := anchor.KeyIDOf(signer)
	ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	rep, err := s.Verify(ctx, ring)
	if err != nil {
		panic(err)
	}
	// Report order follows the random chain ids, so print in subject order.
	lines := map[string]string{}
	for _, c := range rep.Chains {
		lines[subjectOf[c.Chain]] = fmt.Sprintf("%s: %d opened, %d erased", subjectOf[c.Chain], c.Opened, c.Erased)
	}
	fmt.Println(lines["u-81"])
	fmt.Println(lines["u-82"])
	fmt.Println("verifies:", rep.OK())
	// Output:
	// refused an email as a subject
	// committed: true true true
	// opaque chains: 2
	// redelivered: committed true, duplicate true
	// u-81: 0 opened, 2 erased
	// u-82: 1 opened, 0 erased
	// verifies: true
}
