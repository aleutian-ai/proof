// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package linker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/store/memory"
)

// failingState writes entries normally but cannot save the head record.
type failingState struct{ *memory.Store }

func (f failingState) PutState(context.Context, *store.State) error {
	return errors.New("disk full")
}

// TestAppend_HeadStateStaleStillReportsTheAppend: the entries are durable, so
// the caller must get the Result as well as the error — otherwise it retries and
// commits the same evidence twice.
func TestAppend_HeadStateStaleStillReportsTheAppend(t *testing.T) {
	mem := memory.New()
	l, err := New(failingState{mem})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	res, err := l.Append(context.Background(), "c", []Input{
		{EntryID: "e1", EntryType: "t", Timestamp: now, IngestedAt: now, ContentHash: strings.Repeat("a", 128)},
	})
	if !errors.Is(err, ErrHeadStateStale) {
		t.Fatalf("got %v, want ErrHeadStateStale", err)
	}
	if res.Appended != 1 || res.HeadHash == "" {
		t.Fatalf("the Result was dropped: %+v", res)
	}
	rows, _ := mem.Range(context.Background(), "c", 0, 10, 0)
	if len(rows) != 1 || rows[0].ChainHash != res.HeadHash {
		t.Fatal("the reported head does not match what was stored")
	}
}
