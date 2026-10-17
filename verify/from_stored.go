// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/store"
)

// FromStored converts a stored entry to the exported form this package
// verifies.
//
// # Description
//
// The timestamp is rendered in the exact form it was hashed, [TimestampLayout];
// any other and the chain hash recomputed from it differs. A v2 entry is
// written as it was before format versions existed: no format_version, and its
// run id and batch sequence, which are v2 hash inputs. Every other entry
// carries its format_version and no run fields, and a v4 entry its salt, leaf
// hash and erased flag. Converting in one place is what keeps an exporter
// from dropping a field a format hashes.
//
// # Inputs
//
//   - r: a stored entry
//
// # Outputs
//
//   - Entry: the entry as an export carries it
//
// # Example
//
//	for _, r := range rows {
//	    w.Add(verify.FromStored(r))
//	}
//
// # Limitations
//
//   - None.
//
// # Assumptions
//
//   - r.Timestamp is the time that was hashed, at microsecond precision.
func FromStored(r store.Entry) Entry {
	e := Entry{
		EntryID:     r.EntryID,
		EntryType:   r.EntryType,
		Timestamp:   r.Timestamp.UTC().Format(TimestampLayout),
		GlobalSeq:   r.GlobalSeq,
		ContentHash: r.ContentHash,
		ChainHash:   r.ChainHash,
		Salt:        r.Salt,
		LeafHash:    r.LeafHash,
		Erased:      r.Erased,
	}
	if chainformat.NormalizeFormatVersion(r.FormatVersion) == chainformat.FormatV2 {
		e.RunID = r.RunID
		e.SequenceNum = r.SequenceNum
	} else {
		e.FormatVersion = r.FormatVersion
	}
	return e
}
