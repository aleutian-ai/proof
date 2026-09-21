// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package bundle verifies export bundles — the form in which evidence leaves
// the system.
//
// # Description
//
// A bundle is a directory: a manifest listing every file with its SHA-512, the
// chain extracts themselves, and the anchors covering them. The manifest carries
// a `manifest_root` binding the inventory together, and that root is what a
// signature covers.
//
// This package answers two different questions, and keeping them apart matters:
//
//	ManifestRoot(files)   does the INVENTORY match what was signed?
//	VerifyDir(dir)        do the FILES ON DISK match the inventory?
//
// Either alone is insufficient. The root is computed over the manifest's
// CLAIMED hashes, so a bundle whose root checks out may still contain a swapped
// file; re-hashing the files without checking the root proves only that the
// bundle is self-consistent, which an attacker who rewrote both can arrange.
//
// # Limitations
//
//   - Verifies structure and content addressing. Whether the SIGNATURE over the
//     root is trustworthy is anchor.VerifySignature's question.
package bundle

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
)

// ManifestRootDomain is the TLV domain-separation prefix for a bundle's
// manifest_root. It must byte-match the producer.
//
// v2: the root commits to ONLY path + SHA-512 per file. Kind, Bytes and RowCount
// are informational — a verifier cannot reproduce them from file bytes, so
// binding them would add cross-language drift surface with no integrity benefit.
// What a signature must pin is "which file, and what content".
const ManifestRootDomain = "aleutian.compliance_bundle.v2:"

// ErrManifestRoot is returned when the inputs cannot produce a well-defined root.
var ErrManifestRoot = errors.New("bundle: invalid manifest inputs")

// sha512HexRe matches a SHA-512 digest in lowercase hex.
//
// Lowercase is enforced deliberately: hex.DecodeString alone accepts uppercase,
// which would produce a valid root here and then fail a lowercase re-hash
// comparison downstream — a mismatch that looks like tampering.
var sha512HexRe = regexp.MustCompile(`^[0-9a-f]{128}$`)

// FileEntry is one row of a bundle manifest's files[] array.
//
// Kind, Bytes and RowCount are informational and are NOT bound into the signed
// root (v2). Changing them cannot change the root, which is asserted by test.
type FileEntry struct {
	Path     string `json:"path"`
	SHA512   string `json:"sha512"`
	Kind     string `json:"kind,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	RowCount *int64 `json:"row_count,omitempty"`
}

// ManifestRoot recomputes a bundle's manifest_root.
//
// # Description
//
// Recipe:
//
//	"aleutian.compliance_bundle.v2:" ‖ u32_be(N) ‖
//	  foreach file, sorted by path:
//	      u32_be(len(path)) ‖ path
//	      u32_be(64)        ‖ sha512_raw
//
// All integers big-endian. Length-prefixing every field is what makes the
// encoding unambiguous — without it, a path ending in bytes that look like the
// next field's start could shift a boundary, the same class of flaw the
// '|'-delimited anchor chain hash has (see anchor.ValidateChainHashDelimiters).
// Here it is structurally impossible rather than guarded against.
//
// Sorts a COPY, so callers may pass files in manifest order.
//
// # Inputs
//
//   - files: the manifest's files[] entries
//
// # Outputs
//
//   - string: 128-char lowercase hex SHA-512
//   - error: ErrManifestRoot on a duplicate path, a malformed SHA-512, or an
//     overflowing count or path length
//
// # Example
//
//	root, err := bundle.ManifestRoot(manifest.Files)
//	if err != nil {
//	    return err
//	}
//	if root != manifest.ManifestRoot {
//	    return errors.New("bundle inventory was altered after signing")
//	}
//
// # Limitations
//
//   - Hashes the CLAIMED sha512 values; it does not read files. Pair with
//     VerifyDir to bind those claims to actual bytes.
//
// # Assumptions
//
//   - Paths are the bundle-relative paths the producer used
func ManifestRoot(files []FileEntry) (string, error) {
	if int64(len(files)) > int64(math.MaxUint32) {
		return "", fmt.Errorf("%w: file count %d exceeds uint32", ErrManifestRoot, len(files))
	}

	sorted := make([]FileEntry, len(files))
	copy(sorted, files)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	h := sha512.New()
	h.Write([]byte(ManifestRootDomain))

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(sorted)))
	h.Write(u32[:])

	for i, f := range sorted {
		// A duplicate path makes the inventory ambiguous: two entries for one
		// path would let a file be swapped while the root still resolved. An
		// ambiguous inventory must NOT hash to a well-defined root.
		if i > 0 && f.Path == sorted[i-1].Path {
			return "", fmt.Errorf("%w: duplicate path %q", ErrManifestRoot, f.Path)
		}
		if !sha512HexRe.MatchString(f.SHA512) {
			// Do not echo the value; the path is enough to locate the problem.
			return "", fmt.Errorf("%w: file %d (%q): sha512 must be 128 lowercase hex chars",
				ErrManifestRoot, i, f.Path)
		}
		raw, err := hex.DecodeString(f.SHA512)
		if err != nil || len(raw) != 64 {
			return "", fmt.Errorf("%w: file %d (%q): sha512 hex decode failed", ErrManifestRoot, i, f.Path)
		}
		if int64(len(f.Path)) > int64(math.MaxUint32) {
			return "", fmt.Errorf("%w: file %d: path length overflows uint32", ErrManifestRoot, i)
		}

		binary.BigEndian.PutUint32(u32[:], uint32(len(f.Path)))
		h.Write(u32[:])
		h.Write([]byte(f.Path))

		binary.BigEndian.PutUint32(u32[:], 64)
		h.Write(u32[:])
		h.Write(raw)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
