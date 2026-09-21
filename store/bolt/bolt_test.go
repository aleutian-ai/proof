// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bolt_test

import (
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/proof/store"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/store/storetest"
)

// TestConformance runs the shared adapter suite, unmodified.
//
// "Unmodified" is the property being demonstrated: this adapter and the
// in-memory one are interchangeable because they satisfy the same checked
// contract, not because someone asserted they do.
func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := boltstore.Open(filepath.Join(t.TempDir(), "chain.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
