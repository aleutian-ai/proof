// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package commitment_test

import (
	"context"
	"fmt"
	"time"

	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/verify"
)

// Commit unencrypted records with salted commitments, then disclose one of them
// to a third party, who checks it with no secret at all.
func Example() {
	records := [][]byte{
		[]byte(`{"subject":"u-81","consent":"yes"}`),
		[]byte(`{"subject":"u-82","consent":"no"}`),
	}

	// 1. COMMIT. The chain gets only the commitments; content and nonces stay
	//    with you.
	st := memory.New()
	l, _ := linker.New(st)
	nonces := make([][]byte, len(records))
	var batch []linker.Input
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for i, r := range records {
		c, nonce, err := commitment.Salted(r)
		if err != nil {
			panic(err)
		}
		nonces[i] = nonce
		// The subject id lives INSIDE the committed content, never in the entry
		// id or type: those stay public, and erasing the content must erase the
		// link to the person too.
		batch = append(batch, linker.Input{
			EntryID: fmt.Sprintf("rec-%d", i), EntryType: "consent.record.v1",
			Timestamp: now, IngestedAt: now, ContentHash: c,
		})
	}
	if _, err := l.Append(context.Background(), "consents", batch); err != nil {
		panic(err)
	}

	// The chain can be published. Guessing is useless: hashing
	// {"subject":"u-81","consent":"yes"} does not match without the nonce.
	rows, _ := st.Range(context.Background(), "consents", 0, 10, 0)
	entries := make([]verify.Entry, len(rows))
	for i, r := range rows {
		entries[i] = verify.Entry{
			EntryID: r.EntryID, EntryType: r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion, GlobalSeq: r.GlobalSeq,
			ContentHash: r.ContentHash, ChainHash: r.ChainHash,
		}
	}

	// 2. DISCLOSE record 1 only: its content and its nonce. Record 0 stays hidden.
	disclosedContent, disclosedNonce := records[1], nonces[1]

	// 3. A third party VERIFIES the chain, then the disclosure against it.
	res, _ := verify.Chain(entries, verify.Options{})
	fmt.Println("chain intact:", len(res.Breaks) == 0)
	fmt.Println("record 1 matches the chain:",
		commitment.Verify(entries[1].ContentHash, disclosedNonce, disclosedContent))
	fmt.Println("altered record 1 matches:",
		commitment.Verify(entries[1].ContentHash, disclosedNonce, []byte(`{"subject":"u-82","consent":"yes"}`)))

	// Output:
	// chain intact: true
	// record 1 matches the chain: true
	// altered record 1 matches: false
}
