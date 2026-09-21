// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package bolt implements [store] over go.etcd.io/bbolt.
//
// # Description
//
// The default adapter. bbolt is a single-file B+tree with one writer, no
// background goroutines, and near-instant open — which matches this workload
// closely: the chain is inherently single-writer, and the primary deployment is
// a short-lived subprocess that may be spawned and killed many times per
// session.
//
// Secondary indexes are explicit buckets maintained in the same transaction as
// the entry write, so an entry and its index entries commit atomically or not
// at all.
//
// # Assumptions
//
//   - Sequence numbers are encoded big-endian; see [store] for why.
package bolt
