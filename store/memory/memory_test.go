// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"testing"

	"github.com/aleutian-ai/proof/store"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/store/storetest"
)

// TestConformance runs the shared adapter suite.
//
// Every store adapter runs this same suite unmodified. An adapter that needs a
// weakened version of it is not interchangeable with the others, which is the
// whole property the port exists to provide.
func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return memory.New() })
}
