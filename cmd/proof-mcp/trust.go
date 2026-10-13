// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
)

// ---------------------------------------------------------------------------
// Key trust
//
// What a verified signature establishes depends on where the key came from, and
// a tool call cannot be believed about that: its arguments come from a model.
// So the trust level is never an argument. A key named in a tool call is always
// "provided". Only the human who launches the server can bind a key to
// "platform" or "self", with --trusted-key.
// ---------------------------------------------------------------------------

// maxPublicKeyPEMBytes bounds a PEM-encoded ML-DSA-65 public key file.
//
// An ML-DSA-65 public key is anchor.PublicKeySize (1952) bytes RAW. PEM adds
// SPKI framing, base64 expansion (4 out per 3 in), line breaks and the BEGIN/END
// armour: `proof keygen` writes 2726 bytes. 4 KiB leaves room for any reasonable
// encoder's line width while still refusing a file that is obviously not a key.
//
// The previous bound was anchor.PublicKeySize+1 — correct for RAW bytes, and the
// reason this server could not read a single key `proof keygen` produced
// (aleutianchain_54).
const maxPublicKeyPEMBytes = 4 << 10

// trustedKey is a public key the human bound to a trust level at launch.
type trustedKey struct {
	trust anchor.Trust
	pub   []byte // raw ML-DSA-65 public key
}

// trustedKeyFlag collects the repeatable --trusted-key LEVEL=PATH flag. Each
// key file is read when the flag is parsed, so a bad one fails the launch.
type trustedKeyFlag struct {
	keys []trustedKey
}

// String implements flag.Value.
func (f *trustedKeyFlag) String() string {
	return fmt.Sprintf("%d key(s)", len(f.keys))
}

// Set implements flag.Value.
func (f *trustedKeyFlag) Set(arg string) error {
	k, err := parseTrustedKey(arg)
	if err != nil {
		return err
	}
	for _, have := range f.keys {
		if !bytes.Equal(have.pub, k.pub) {
			continue
		}
		if have.trust != k.trust {
			return fmt.Errorf("the same key is bound as both %s and %s; choose one", have.trust, k.trust)
		}
		return nil
	}
	f.keys = append(f.keys, k)
	return nil
}

// parseTrustedKey reads one LEVEL=PATH value.
//
// The path is the human's choice, so it is not held to --root. Errors may name
// the path and the parse failure: they go to stderr at launch, not to a model.
func parseTrustedKey(arg string) (trustedKey, error) {
	level, path, ok := strings.Cut(arg, "=")
	if !ok || path == "" {
		return trustedKey{}, fmt.Errorf("want LEVEL=PATH, e.g. platform=./aleutian-public.pem")
	}
	var trust anchor.Trust
	switch level {
	case string(anchor.TrustPlatform):
		trust = anchor.TrustPlatform
	case string(anchor.TrustSelf):
		trust = anchor.TrustSelf
	case string(anchor.TrustProvided):
		return trustedKey{}, fmt.Errorf("level must be platform or self: provided is what a key " +
			"named in a tool call already is")
	default:
		return trustedKey{}, fmt.Errorf("level must be platform or self, got %q", level)
	}

	f, err := os.Open(path)
	if err != nil {
		return trustedKey{}, err
	}
	defer f.Close()
	pemBytes, err := readRegular(f, path, maxPublicKeyPEMBytes)
	if err != nil {
		return trustedKey{}, err
	}
	alg, pub, err := keyfile.ParsePublicKey(pemBytes)
	if err != nil {
		return trustedKey{}, fmt.Errorf("%s is not a PEM-encoded public key "+
			"(expected one from `proof keygen --alg ml-dsa-65`): %w", path, err)
	}
	if alg != keyfile.MLDSA65 {
		return trustedKey{}, fmt.Errorf("%s holds a %s public key, but anchors are signed "+
			"with ML-DSA-65", path, alg)
	}
	return trustedKey{trust: trust, pub: pub}, nil
}

// loadPublicKey reads a PEM-encoded ML-DSA-65 public key named in a tool call.
//
// Parsing goes through keyfile.ParsePublicKey — the SAME function the CLI's
// `proof verify --key` uses, so the two surfaces agree with `proof keygen` about
// what a key file is (aleutianchain_54).
//
// The parser's own error is NOT passed on. It can quote the file's PEM label or
// a decoded byte, and this error is returned to a model.
func (c serverConfig) loadPublicKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("public_key_path is required")
	}
	pemBytes, err := c.root.read(path, maxPublicKeyPEMBytes)
	if err != nil {
		return nil, publicKeyFileError(err)
	}
	alg, pub, err := keyfile.ParsePublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a PEM-encoded public key "+
			"(expected one from `proof keygen --alg ml-dsa-65`)", path)
	}
	if alg != keyfile.MLDSA65 {
		// Name what was supplied AND what is needed. "wrong algorithm" sends a
		// reader to check the wrong thing.
		return nil, fmt.Errorf("%s holds a %s public key, but anchors are signed "+
			"with ML-DSA-65", path, alg)
	}
	return pub, nil
}

// publicKeyFileError labels a read failure as being about the key file, except
// the outside-the-root answer, which stays exactly the same for every argument.
func publicKeyFileError(err error) error {
	if errors.Is(err, errOutsideRoot) {
		return err
	}
	return fmt.Errorf("public key file: %w", err)
}

// trustOf returns what a key named in a tool call establishes.
//
// It is "provided" unless its bytes are a key the human bound at launch. The
// tool call names the key; it never names the level.
func (c serverConfig) trustOf(pub []byte) anchor.Trust {
	for _, k := range c.trusted {
		if bytes.Equal(k.pub, pub) {
			return k.trust
		}
	}
	return anchor.TrustProvided
}

// trustedKeyRing returns a key source holding the launch-bound key that
// verifies this anchor's signature, or nil if none does.
//
// Launch-bound keys carry no key id, so each is tried against the signature
// itself. A key that verifies it is the signer's key, whatever id the anchor
// names.
func (c serverConfig) trustedKeyRing(a anchor.Anchor) *anchor.KeyRing {
	for _, k := range c.trusted {
		ring, err := anchor.NewKeyRing(k.trust, map[string][]byte{a.SigningKeyID: k.pub})
		if err != nil {
			continue
		}
		if _, err := anchor.VerifySignature(a, ring); err == nil {
			return ring
		}
	}
	return nil
}
