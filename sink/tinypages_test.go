// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"os"
	"time"
)

// SINK_TINY_PAGES=1 runs the whole suite with one chain, one key and a deadline already past
// per page (so only the one-unit-per-page guarantee makes progress), so every test crosses page boundaries everywhere: paged Verify and
// Checkpoint must give exactly what one long pass gave.
func init() {
	if os.Getenv("SINK_TINY_PAGES") != "" {
		pageMaxChains, pageMaxKeys, pageBudget, pageGap = 1, 1, -time.Second, 0
	}
}
