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

// Commit a keyed stream, checkpoint every chain, erase one user, and verify.
func Example() {
	ctx := context.Background()
	dir, _ := os.MkdirTemp("", "sink-example")
	defer os.RemoveAll(dir)
	s, err := sink.Open(dir)
	if err != nil {
		panic(err)
	}

	// Routing keys must already be pseudonyms: ChainFor refuses, never transforms.
	if _, err := sink.ChainFor("jo@example.com"); err != nil {
		fmt.Println("refused an email as a key")
	}

	done, err := s.Commit(ctx, []sink.Record{
		{Key: "u-81", Content: []byte(`{"event":"login"}`), Source: "EVIDENCE@1:1"},
		{Key: "u-82", Content: []byte(`{"event":"login"}`), Source: "EVIDENCE@1:2"},
		{Key: "u-81", Content: []byte(`{"event":"logout"}`), Source: "EVIDENCE@1:3"},
	})
	if err != nil {
		panic(err)
	}
	for _, d := range done {
		fmt.Printf("%s: %d committed\n", d.Chain, d.Entries)
	}

	// The same records again, as after a crash between commit and ack.
	again, _ := s.Commit(ctx, []sink.Record{{Key: "u-81", Content: []byte(`{"event":"login"}`), Source: "EVIDENCE@1:1"}})
	fmt.Printf("redelivered: %d committed, %d duplicate\n", again[0].Entries, again[0].Duplicates)

	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	_, _ = rand.Read(seed)
	signer, _ := anchor.NewMLDSA65Signer(seed)
	defer signer.Close()
	if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
		panic(err)
	}
	if _, err := s.Erase(ctx, "u-81"); err != nil {
		panic(err)
	}

	id, pub, _ := anchor.KeyIDOf(signer)
	ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{id: pub})
	rep, err := s.Verify(ctx, ring)
	if err != nil {
		panic(err)
	}
	for _, c := range rep.Chains {
		fmt.Printf("%s: %d opened, %d erased\n", c.Chain, c.Opened, c.Erased)
	}
	fmt.Println("verifies:", rep.OK())
	// Output:
	// refused an email as a key
	// u-81: 2 committed
	// u-82: 1 committed
	// redelivered: 0 committed, 1 duplicate
	// u-81: 0 opened, 2 erased
	// u-82: 1 opened, 0 erased
	// verifies: true
}
