// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/aleutian-ai/proof/internal/osfile"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// MaxKeyFileBytes is the largest key file read (bundle-format §6). A valid
// one is about 2.7 KB.
const MaxKeyFileBytes = 16 << 10

// publicKeySize is an ML-DSA-65 public key, in bytes.
const publicKeySize = 1952

// The refusals of a key or bundle file. None carries the file's content.
var (
	// ErrKeyFile is a key file that is not what bundle-format §6 defines.
	ErrKeyFile = errors.New("exportbundle: not an ML-DSA-65 public key file")
	// ErrNotRegular is a path that is not a regular file.
	ErrNotRegular = errors.New("exportbundle: not a regular file")
)

// spkiPrefix is everything before the key in the RFC 9881 SubjectPublicKeyInfo
// of an ML-DSA-65 public key: the outer SEQUENCE, the AlgorithmIdentifier
// (id-ml-dsa-65, parameters absent) and the BIT STRING header.
var spkiPrefix = []byte{
	0x30, 0x82, 0x07, 0xb2,
	0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
	0x03, 0x82, 0x07, 0xa1, 0x00,
}

// keyFilePattern is the whole text of a key file (§6): one PUBLIC KEY block,
// no headers, base64 lines of any width ending LF or CRLF, and nothing but
// whitespace around it.
var keyFilePattern = regexp.MustCompile(
	`\A[ \t\r\n]*-----BEGIN PUBLIC KEY-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----[ \t\r\n]*\z`)

// PublicKey is an ML-DSA-65 public key a verifier trusts, with its computed
// key id. The zero value is not a key; make one with NewPublicKey,
// ParsePublicKeyPEM or ReadPublicKeyFile.
type PublicKey struct {
	id  string
	raw []byte
}

// Trust is the two key sets of bundle-format §6. A dimension is checked
// exactly when its set is not empty.
type Trust struct {
	// Checkpoint holds the keys trusted for checkpoints.
	Checkpoint []PublicKey
	// Record holds the keys trusted for record signatures.
	Record []PublicKey
}

// NewPublicKey makes a trusted key from a raw ML-DSA-65 public key.
//
// # Description
//
// Checks the length and computes the key id (format-spec §9.6), which is what
// signatures are matched by.
//
// # Inputs
//
//   - raw: the 1952-byte public key. It is copied.
//
// # Outputs
//
//   - PublicKey: the key and its id
//   - error: ErrKeyFile when raw is not an ML-DSA-65 public key
//
// # Example
//
//	key, err := exportbundle.NewPublicKey(raw)
//
// # Limitations
//
//   - Says nothing about whether the key should be trusted: that is the
//     caller's decision.
//
// # Assumptions
//
//   - raw came from somewhere other than the bundle being verified.
func NewPublicKey(raw []byte) (PublicKey, error) {
	if len(raw) != publicKeySize {
		return PublicKey{}, fmt.Errorf("%w: the key is %d bytes, not %d", ErrKeyFile, len(raw), publicKeySize)
	}
	// A key the signature code cannot load would make every signature read
	// as a bad one: refuse it here, as the key's fault.
	if err := mldsa.Verify(mldsa.MLDSA65, raw, nil, make([]byte, signatureSize)); errors.Is(err, mldsa.ErrInvalidKey) {
		return PublicKey{}, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	id, err := keyfile.KeyIDHex(keyfile.MLDSA65, raw)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: key id: %v", ErrKeyFile, err)
	}
	return PublicKey{id: id, raw: bytes.Clone(raw)}, nil
}

// ParsePublicKeyPEM reads the text of a key file as bundle-format §6 defines
// it.
//
// # Description
//
// Stricter than a general PEM reader, so that every implementation accepts
// the same files: exactly one block, labelled PUBLIC KEY, without headers,
// with a canonical base64 body, holding exactly the RFC 9881
// SubjectPublicKeyInfo of an ML-DSA-65 key, and nothing but whitespace around
// it.
//
// # Inputs
//
//   - data: the file's bytes, at most MaxKeyFileBytes
//
// # Outputs
//
//   - PublicKey: the key and its id
//   - error: ErrKeyFile, with which rule failed and nothing from the file
//
// # Example
//
//	key, err := exportbundle.ParsePublicKeyPEM(pemBytes)
//
// # Limitations
//
//   - Reads ML-DSA-65 only: bundle v1 has no other algorithm.
//
// # Assumptions
//
//   - As NewPublicKey.
func ParsePublicKeyPEM(data []byte) (PublicKey, error) {
	if len(data) > MaxKeyFileBytes {
		return PublicKey{}, fmt.Errorf("%w: over %d bytes", ErrKeyFile, MaxKeyFileBytes)
	}
	m := keyFilePattern.FindSubmatch(data)
	if m == nil {
		return PublicKey{}, fmt.Errorf("%w: want exactly one PUBLIC KEY block, without headers, and only whitespace around it", ErrKeyFile)
	}
	body := strings.NewReplacer("\r", "", "\n", "").Replace(string(m[1]))
	der, ok := decodeCanonicalBase64(body)
	if !ok {
		return PublicKey{}, fmt.Errorf("%w: the body is not canonical base64", ErrKeyFile)
	}
	if len(der) != len(spkiPrefix)+publicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return PublicKey{}, fmt.Errorf("%w: the block is not the SubjectPublicKeyInfo of an ML-DSA-65 key", ErrKeyFile)
	}
	return NewPublicKey(der[len(spkiPrefix):])
}

// ReadPublicKeyFile reads a key file from disk.
//
// # Description
//
// Opens the path once, refuses anything but a regular file, reads at most
// MaxKeyFileBytes and one more byte, and parses what it read with
// ParsePublicKeyPEM.
//
// # Inputs
//
//   - path: the key file
//
// # Outputs
//
//   - PublicKey: the key and its id
//   - error: the open or read error, ErrNotRegular, or ErrKeyFile
//
// # Example
//
//	key, err := exportbundle.ReadPublicKeyFile("checkpoint-public.pem")
//
// # Limitations
//
//   - As ParsePublicKeyPEM.
//
// # Assumptions
//
//   - The file is the verifier's own, obtained out of band.
func ReadPublicKeyFile(path string) (PublicKey, error) {
	data, err := readRegular(path, MaxKeyFileBytes)
	if err != nil {
		return PublicKey{}, err
	}
	key, err := ParsePublicKeyPEM(data)
	if err != nil {
		return PublicKey{}, fmt.Errorf("key file %s: %w", path, err)
	}
	return key, nil
}

// ReadBundleFile reads a bundle file from disk, up to a size limit.
//
// # Description
//
// Opens the path once, refuses anything but a regular file, and reads at most
// limit bytes and one more. A file over the limit is returned cut at limit+1
// bytes, which Verify then reports as unreadable (`too-large`): the verdict on
// an oversized bundle is the verifier's, not a file error.
//
// # Inputs
//
//   - path: the bundle file
//   - limit: the size limit in bytes; Limits.BundleBytes
//
// # Outputs
//
//   - []byte: the file's bytes, at most limit+1 of them
//   - error: the open or read error, or ErrNotRegular
//
// # Example
//
//	data, err := exportbundle.ReadBundleFile(path, exportbundle.DefaultLimits().BundleBytes)
//
// # Limitations
//
//   - Holds the whole bundle in memory.
//
// # Assumptions
//
//   - limit is positive.
func ReadBundleFile(path string, limit int) ([]byte, error) {
	return readRegular(path, limit)
}

// ID returns the key's id: 32 lowercase hex characters (format-spec §9.6).
//
// # Description
//
// The id is computed from the key, never read from a file or a bundle.
//
// # Inputs
//
// None.
//
// # Outputs
//
//   - string: the key id, or "" for the zero PublicKey
//
// # Example
//
//	fmt.Println(key.ID())
//
// # Limitations
//
//   - An id names a key; it does not make it trusted.
//
// # Assumptions
//
//   - The key was made by this package.
func (k PublicKey) ID() string { return k.id }

// readRegular opens path once, requires a regular file, and reads at most
// limit+1 bytes of it. It allocates for the file's size, not for the limit.
func readRegular(path string, limit int) ([]byte, error) {
	// Non-blocking, so that opening a FIFO returns instead of waiting for a
	// writer; the check below then refuses it.
	f, err := os.OpenFile(path, os.O_RDONLY|osfile.NonBlock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	most := int64(limit) + 1
	buf := make([]byte, min(info.Size(), most))
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	buf = buf[:n]
	if int64(n) == info.Size() && int64(n) < most {
		// The file may have grown since Stat: take what is there, to the limit.
		rest, err := io.ReadAll(io.LimitReader(f, most-int64(n)))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		buf = append(buf, rest...)
	}
	return buf, nil
}
