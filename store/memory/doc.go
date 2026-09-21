// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package memory implements [store] entirely in memory.
//
// # Description
//
// A first-class adapter, not just a test double. Verifying a chain handed over
// on stdin should not create a file, and an ephemeral session has no reason to
// touch disk at all.
//
// # Limitations
//
//   - Not durable. Contents are lost when the process exits.
package memory
