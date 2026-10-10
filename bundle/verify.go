// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultMaxFileBytes caps any single file a verifier will hash.
//
// A manifest is untrusted input. Without a cap, a bundle claiming a petabyte
// file turns verification into a denial of service against the verifier.
const DefaultMaxFileBytes int64 = 512 << 20 // 512 MiB

// Problem is one reason a bundle failed verification.
type Problem struct {
	// Path is the bundle-relative path, or empty for a bundle-wide problem.
	Path string `json:"path,omitempty"`

	// Kind classifies the problem for machine dispatch.
	Kind ProblemKind `json:"kind"`

	// Detail explains it. Never contains file contents.
	Detail string `json:"detail"`
}

// ProblemKind classifies a bundle verification failure.
type ProblemKind string

const (
	// ProblemMissingFile: the manifest lists a file the bundle does not contain.
	ProblemMissingFile ProblemKind = "missing_file"

	// ProblemContentMismatch: the file exists but its bytes do not hash to the
	// value the manifest claims. The bundle was altered after it was built.
	ProblemContentMismatch ProblemKind = "content_mismatch"

	// ProblemUnlistedFile: the bundle contains a file the manifest does not list.
	// Not automatically an attack, but it is unaccounted-for content inside
	// something presented as a complete record.
	ProblemUnlistedFile ProblemKind = "unlisted_file"

	// ProblemUnreadable: the file could not be read, was not a regular file, or
	// exceeded the size cap.
	ProblemUnreadable ProblemKind = "unreadable"

	// ProblemUnsafePath: a manifest path tried to escape the bundle directory.
	ProblemUnsafePath ProblemKind = "unsafe_path"

	// ProblemRootMismatch: the recomputed manifest_root differs from the claim.
	ProblemRootMismatch ProblemKind = "root_mismatch"
)

// ErrEmptyManifest is returned for a manifest that lists no files. Nothing was
// checked, so there is nothing to call intact.
var ErrEmptyManifest = errors.New("bundle: the manifest lists no files; verifying nothing proves nothing")

// DirResult reports whether the files on disk match a manifest.
type DirResult struct {
	// Intact is true only when there are no problems at all.
	Intact bool `json:"intact"`

	// FilesChecked is how many listed files were hashed.
	FilesChecked int `json:"files_checked"`

	// Problems is every failure found. Verification does NOT stop at the first —
	// a caller repairing a bundle needs the full list, and stopping early would
	// leak which file was checked first.
	Problems []Problem `json:"problems,omitempty"`

	// Proven and NotProven state the claim in plain language, in the payload
	// rather than the docs, so a caller relaying this must actively discard the
	// caveat rather than remember to add it.
	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

// VerifyDir checks that a bundle directory's contents match its manifest.
//
// # Description
//
// For every file the manifest lists: resolve the path safely, confirm it is a
// regular file within the size cap, stream it through SHA-512, and compare
// against the claimed digest. Then check for files present but unlisted, and
// recompute the manifest_root over the inventory.
//
// **This is the half that binds claims to bytes.** ManifestRoot alone hashes what
// the manifest SAYS; this confirms what the bundle CONTAINS. A bundle that passes
// both is internally consistent — which is still not the same as trustworthy,
// because whoever built it could have made both consistent. Only a signature over
// the root, verified against a key you trust, closes that.
//
// # Inputs
//
//   - dir: the bundle directory
//   - files: the manifest's files[] entries
//   - claimedRoot: the manifest's manifest_root; empty skips the root check
//   - maxFileBytes: per-file size cap; <= 0 uses DefaultMaxFileBytes
//
// # Outputs
//
//   - DirResult: every problem found, not merely the first
//   - error: only for failures that prevent verification entirely: dir
//     unreadable, or [ErrEmptyManifest]
//
// # Example
//
//	res, err := bundle.VerifyDir(dir, m.Files, m.ManifestRoot, 0)
//	if err != nil {
//	    return err
//	}
//	if !res.Intact {
//	    for _, p := range res.Problems {
//	        log.Printf("%s: %s", p.Kind, p.Detail)
//	    }
//	}
//
// # Limitations
//
//   - Does not verify any signature. See anchor.VerifySignature and D14.
//   - Follows no symlinks, in any path component: a listed path that is a
//     symlink, or that passes through a symlinked directory, is reported
//     unreadable, not chased. Every file is opened through an [os.Root] on dir,
//     so a path swapped for a symlink mid-check still cannot leave the bundle.
//
// # Assumptions
//
//   - dir is a path the caller intends to read; this function never writes
func VerifyDir(dir string, files []FileEntry, claimedRoot string, maxFileBytes int64) (DirResult, error) {
	if maxFileBytes <= 0 {
		maxFileBytes = DefaultMaxFileBytes
	}
	info, err := os.Stat(dir)
	if err != nil {
		return DirResult{}, fmt.Errorf("bundle: open %s: %w", dir, err)
	}
	if !info.IsDir() {
		return DirResult{}, fmt.Errorf("bundle: %s is not a directory", dir)
	}
	if len(files) == 0 {
		return DirResult{}, ErrEmptyManifest
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return DirResult{}, fmt.Errorf("bundle: open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	res := DirResult{
		Proven: "every file listed in the manifest is present and its bytes match " +
			"the digest the manifest claims",
		NotProven: "that the manifest itself is genuine — no signature was checked, so " +
			"whoever built this bundle could have made the files and the manifest agree",
	}

	listed := make(map[string]struct{}, len(files))
	for _, f := range files {
		listed[f.Path] = struct{}{}

		rel, perr := safePath(dir, f.Path)
		if perr != nil {
			res.Problems = append(res.Problems, Problem{
				Path: f.Path, Kind: ProblemUnsafePath, Detail: perr.Error(),
			})
			continue
		}
		got, herr := hashRegularFile(root, rel, maxFileBytes)
		if herr != nil {
			kind := ProblemUnreadable
			if errors.Is(herr, fs.ErrNotExist) {
				kind = ProblemMissingFile
			}
			res.Problems = append(res.Problems, Problem{
				Path: f.Path, Kind: kind, Detail: herr.Error(),
			})
			continue
		}
		res.FilesChecked++
		if got != f.SHA512 {
			// Report that it differs, never the digests themselves — a verifier
			// error should not become an oracle over content it just refused.
			res.Problems = append(res.Problems, Problem{
				Path: f.Path, Kind: ProblemContentMismatch,
				Detail: "file contents do not match the digest the manifest claims",
			})
		}
	}

	extra, err := unlistedFiles(dir, listed)
	if err != nil {
		return DirResult{}, err
	}
	for _, p := range extra {
		res.Problems = append(res.Problems, Problem{
			Path: p, Kind: ProblemUnlistedFile,
			Detail: "present in the bundle but not listed in the manifest",
		})
	}

	if claimedRoot != "" {
		root, rerr := ManifestRoot(files)
		if rerr != nil {
			res.Problems = append(res.Problems, Problem{
				Kind: ProblemRootMismatch, Detail: rerr.Error(),
			})
		} else if root != claimedRoot {
			res.Problems = append(res.Problems, Problem{
				Kind:   ProblemRootMismatch,
				Detail: "recomputed manifest_root does not match the manifest's claim",
			})
		}
	}

	res.Intact = len(res.Problems) == 0
	return res, nil
}

// safePath checks a manifest-supplied relative path and returns it relative to
// dir, cleaned, with the host's separators.
//
// A manifest is untrusted. Without this, an attacker controlling it could point
// the verifier at /etc/shadow and learn — from whether the digest matched —
// something about a file outside the bundle entirely.
func safePath(dir, relSlash string) (string, error) {
	if relSlash == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(relSlash, '\x00') {
		return "", errors.New("path contains NUL")
	}
	rel := filepath.FromSlash(relSlash)
	if filepath.IsAbs(rel) {
		return "", errors.New("path is absolute")
	}
	joined := filepath.Join(dir, rel)
	back, err := filepath.Rel(dir, joined)
	if err != nil {
		return "", err
	}
	if back == "." || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes the bundle directory")
	}
	return back, nil
}

// errNotRegular is what a listed path that is not a plain file reports.
var errNotRegular = errors.New("not a regular file (symlink or special file)")

// hashRegularFile streams the file at rel, inside root, through SHA-512,
// refusing anything that is not a regular file reached through real
// directories, or that exceeds cap.
//
// Every component is Lstat'ed, not only the last: a manifest could otherwise
// name a path through a symlinked directory and have a file outside the bundle
// hashed. The checks and the open all go through root, so a component swapped
// for a symlink between the check and the open is refused by the open.
func hashRegularFile(root *os.Root, rel string, cap int64) (string, error) {
	parts := strings.Split(rel, string(filepath.Separator))
	for i := range parts[:len(parts)-1] {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", errors.New("a directory in the path is a symlink or not a directory")
		}
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errNotRegular
	}
	f, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	// The size that is capped and read is the opened file's, not the one seen
	// before the open.
	if info, err = f.Stat(); err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errNotRegular
	}
	if info.Size() > cap {
		return "", fmt.Errorf("file is %d bytes, exceeding the %d-byte cap", info.Size(), cap)
	}

	h := sha512.New()
	if _, err := io.CopyN(h, f, info.Size()); err != nil && err != io.EOF {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unlistedFiles returns bundle-relative paths present on disk but absent from
// the manifest, sorted.
func unlistedFiles(dir string, listed map[string]struct{}) ([]string, error) {
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		if _, ok := listed[slash]; !ok {
			found = append(found, slash)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bundle: walk %s: %w", dir, err)
	}
	sort.Strings(found)
	return found, nil
}
