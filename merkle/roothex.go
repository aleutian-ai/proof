// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package merkle

import (
	"encoding/hex"
	"fmt"
)

// RootHex computes the RFC-9162 Merkle tree root over hex-encoded leaf content hashes and
// returns it as lowercase hex (chainlinker_modernization_02f / ADR 003 D3).
//
// # Description
//
// The single reproducible root computation shared by the anchor generator (sign side, for
// the D6 re-derive-before-sign check), the proof endpoints, and the SDK verifiers. Each
// input is the entry's content_hash column (128-char hex); this decodes each to its 64
// RAW bytes before leaf-hashing — the hex-decode discipline the ADR pins to keep Go/
// Python/JS byte-identical (hashing the ASCII hex instead of the raw bytes is the likeliest
// cross-language divergence).
//
// # Inputs
//
//   - contentHashesHex: the entries' content_hash values (lowercase hex), in global_seq order.
//
// # Outputs
//
//   - string: the tree root as lowercase hex (EmptyRoot for zero leaves).
//   - error: if any leaf is not valid hex OR does not decode to exactly HashSize bytes.
func RootHex(contentHashesHex []string) (string, error) {
	raw := make([][]byte, len(contentHashesHex))
	for i, h := range contentHashesHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("merkle: leaf %d content_hash hex decode: %w", i, err)
		}
		if len(b) != HashSize {
			return "", fmt.Errorf("merkle: leaf %d content_hash decodes to %d bytes, want %d", i, len(b), HashSize)
		}
		raw[i] = b
	}
	return hex.EncodeToString(FrontierFromLeaves(raw).Root()), nil
}
