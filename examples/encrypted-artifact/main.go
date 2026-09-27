// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command encrypted-artifact shows proof composed with encryption it does not own.
//
// proof is the integrity layer, not the confidentiality layer.
//
// It encrypts nothing itself, on purpose. This example encrypts with Cloudflare's
// circl (HPKE with the X-Wing post-quantum KEM), keeps private keys in 1Password,
// stores the encrypted items in an ordinary folder, and uses proof only for what
// proof does: commit each item to a chain, anchor checkpoints, and verify.
//
//	encrypt → store → COMMIT → ANCHOR → VERIFY → decrypt
//	                  └──────── proof ─────────┘
//
//	encrypted-artifact init          create an encryption key and a signing key
//	encrypted-artifact commit FILE…  encrypt each file into items/, commit its hash
//	encrypted-artifact checkpoint    anchor a signed checkpoint over the chain so far
//	encrypted-artifact verify        check the chain, the checkpoints, and every item
//	encrypted-artifact open ID       decrypt one item to stdout
//
// Everything lives in one folder (-dir, default ./artifact-data):
//
//	items/<id>.sealed    the encrypted items: HPKE enc ‖ ciphertext
//	chain.db             the proof chain (fingerprints only, never content)
//	anchors/NNNN.json    signed checkpoints
//	keys/*.pem           PUBLIC keys: safe to share
//	subject              the chain's name, bound into every checkpoint
//
// Private keys never touch that folder. With -keystore op (the default) they are
// stored as 1Password documents; -keystore file writes them to <dir>/secrets/
// instead, which is only for trying the example without 1Password.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/anchor/build"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/linker"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
	"github.com/aleutian-ai/proof/verify"
)

const (
	chainID   = "artifacts"
	entryType = "sealed.item.v1"

	// hpkeInfo binds every ciphertext to this application, so an item sealed by
	// some other program under the same key cannot be passed off as one of ours.
	hpkeInfo = "proof example encrypted-artifact v1"

	// Names of the two private keys in the keystore.
	encryptionKeyName = "encrypted-artifact-xwing-private"
	signingKeyName    = "encrypted-artifact-mldsa65-private"
)

// suite is HPKE (RFC 9180) with X-Wing as the KEM: post-quantum key agreement,
// then HKDF, then AES-256-GCM for the data itself.
var suite = hpke.NewSuite(hpke.KEM_XWING, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

// xwing is the KEM on its own, for generating and loading keys.
var xwing = hpke.KEM_XWING.Scheme()

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "artifact-data", "folder holding items, chain, checkpoints and public keys")
	store := fs.String("keystore", "op", "where private keys live: op (1Password) or file (demo only)")
	vault := fs.String("vault", "Private", "1Password vault, with -keystore op")
	_ = fs.Parse(args)

	ks, err := newKeystore(*store, *vault, *dir)
	if err != nil {
		fail(err)
	}
	ctx := context.Background()

	switch cmd {
	case "init":
		err = cmdInit(*dir, ks)
	case "commit":
		err = cmdCommit(ctx, *dir, fs.Args())
	case "checkpoint":
		err = cmdCheckpoint(ctx, *dir, ks)
	case "verify":
		err = cmdVerify(*dir)
	case "open":
		if fs.NArg() != 1 {
			usage()
		}
		err = cmdOpen(*dir, ks, fs.Arg(0), os.Stdout)
	default:
		usage()
	}
	if err != nil {
		fail(err)
	}
}

// ---------------------------------------------------------------------------
// init: two key pairs. Private halves go to the keystore, public halves to keys/.
// ---------------------------------------------------------------------------

func cmdInit(dir string, ks keystore) error {
	for _, d := range []string{"items", "anchors", "keys"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}

	// Encryption key: X-Wing, from a 32-byte seed. Stored in the standard
	// PKCS#8 form proof's keyfile package reads, so it is not a private format.
	xwSeed := make([]byte, xwing.SeedSize())
	if _, err := rand.Read(xwSeed); err != nil {
		return err
	}
	xwPub, _ := xwing.DeriveKeyPair(xwSeed)
	xwPubRaw, err := xwPub.MarshalBinary()
	if err != nil {
		return err
	}
	if err := storeKeyPair(dir, ks, keyfile.XWing, encryptionKeyName, "xwing-public.pem", xwSeed, xwPubRaw); err != nil {
		return err
	}

	// Signing key: ML-DSA-65, which proof uses for checkpoints. The same PEM works
	// with `proof anchor --key` and `proof verify --key`.
	sigSeed := make([]byte, keyfile.MLDSA65.SeedSize())
	if _, err := rand.Read(sigSeed); err != nil {
		return err
	}
	signer, err := anchor.NewMLDSA65Signer(sigSeed)
	if err != nil {
		return err
	}
	defer signer.Close()
	keyID, sigPubRaw, err := anchor.KeyIDOf(signer)
	if err != nil {
		return err
	}
	if err := storeKeyPair(dir, ks, keyfile.MLDSA65, signingKeyName, "mldsa65-public.pem", sigSeed, sigPubRaw); err != nil {
		return err
	}

	// The subject names this chain inside every signed checkpoint. It can never
	// be changed or erased afterwards, so it is random, never a person's name.
	subj := make([]byte, 8)
	if _, err := rand.Read(subj); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "subject"), []byte("artifacts-"+hex.EncodeToString(subj)), 0o600); err != nil {
		return err
	}

	fmt.Printf("initialised %s\n  encryption key  X-Wing (private half in %s)\n  signing key     ML-DSA-65, key id %s\n",
		dir, ks.describe(), keyID)
	return nil
}

func storeKeyPair(dir string, ks keystore, alg keyfile.Algorithm, name, pubFile string, seed, pub []byte) error {
	privPEM, err := keyfile.MarshalPrivateKey(alg, seed)
	if err != nil {
		return err
	}
	if err := ks.put(name, privPEM); err != nil {
		return fmt.Errorf("store %s: %w", name, err)
	}
	pubPEM, err := keyfile.MarshalPublicKey(alg, pub)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "keys", pubFile), pubPEM, 0o644)
}

// ---------------------------------------------------------------------------
// commit: encrypt → store in items/ → commit the ciphertext's hash to the chain.
// Needs only the PUBLIC encryption key, so anyone can commit; only the key
// holder can read.
// ---------------------------------------------------------------------------

func cmdCommit(ctx context.Context, dir string, files []string) error {
	if len(files) == 0 {
		return errors.New("commit: name at least one file")
	}
	pub, err := loadEncryptionPublicKey(dir)
	if err != nil {
		return err
	}

	var batch []linker.Input
	for _, f := range files {
		plaintext, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		id, err := newItemID()
		if err != nil {
			return err
		}

		sender, err := suite.NewSender(pub, []byte(hpkeInfo))
		if err != nil {
			return err
		}
		enc, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			return err
		}
		// The item id is authenticated data: the ciphertext is bound to its chain
		// entry, so renaming or swapping files makes decryption fail.
		ct, err := sealer.Seal(plaintext, []byte(id))
		if err != nil {
			return err
		}
		sealed := append(enc, ct...)
		if err := os.WriteFile(itemPath(dir, id), sealed, 0o600); err != nil {
			return err
		}

		// The chain gets the fingerprint of the ENCRYPTED bytes. It never sees the
		// plaintext, so the chain can be shared without leaking anything.
		sum := sha512.Sum512(sealed)
		now := time.Now().UTC()
		batch = append(batch, linker.Input{
			EntryID: id, EntryType: entryType, Timestamp: now,
			ContentHash: hex.EncodeToString(sum[:]), IngestedAt: now,
		})
		fmt.Printf("encrypted %s → items/%s.sealed (%d bytes)\n", f, id, len(sealed))
	}

	st, err := boltstore.Open(filepath.Join(dir, "chain.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	l, err := linker.New(st)
	if err != nil {
		return err
	}
	res, err := l.Append(ctx, chainID, batch)
	if err != nil {
		return err
	}
	fmt.Printf("committed %d entries to the chain\n", res.Appended)
	return nil
}

// ---------------------------------------------------------------------------
// checkpoint: sign an anchor over the whole chain with the private signing key.
// ---------------------------------------------------------------------------

func cmdCheckpoint(ctx context.Context, dir string, ks keystore) error {
	entries, err := readChain(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("checkpoint: the chain is empty")
	}
	subject, err := os.ReadFile(filepath.Join(dir, "subject"))
	if err != nil {
		return err
	}
	anchors, err := readAnchors(dir)
	if err != nil {
		return err
	}
	var previous *anchor.Anchor
	if len(anchors) > 0 {
		previous = &anchors[len(anchors)-1]
	}

	privPEM, err := ks.get(signingKeyName)
	if err != nil {
		return err
	}
	_, seed, err := keyfile.ParsePrivateKey(privPEM)
	if err != nil {
		return err
	}
	signer, err := anchor.NewMLDSA65Signer(seed)
	clear(seed)
	if err != nil {
		return err
	}
	defer signer.Close()

	// build.Anchor verifies the chain before it will claim anything about it.
	unsigned, err := build.Anchor(ctx, build.Input{
		Subject: string(subject), Entries: entries, Previous: previous,
	})
	if err != nil {
		return err
	}
	signed, err := anchor.SignAnchor(ctx, signer, unsigned)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%04d.json", len(anchors)+1)
	if err := os.WriteFile(filepath.Join(dir, "anchors", name), raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("checkpoint anchors/%s signed over %d entries\n", name, signed.EntryCount)
	return nil
}

// ---------------------------------------------------------------------------
// verify: needs NO private key. Anyone holding the folder and the public
// signing key can run it.
// ---------------------------------------------------------------------------

func cmdVerify(dir string) error {
	entries, err := readChain(dir)
	if err != nil {
		return err
	}

	// 1. The chain links: no entry edited, reordered or removed from the middle.
	res, err := verify.Chain(entries, verify.Options{})
	if err != nil {
		return err
	}
	if len(res.Breaks) > 0 {
		return fmt.Errorf("chain BROKEN at entry %d: %s", res.FirstBreak, res.Breaks[0].Type)
	}
	fmt.Printf("chain        intact, %d entries\n", res.EntriesVerified)

	// 2. Every stored item still matches the fingerprint the chain recorded.
	for _, e := range entries {
		sealed, err := os.ReadFile(itemPath(dir, e.EntryID))
		if errors.Is(err, os.ErrNotExist) {
			// Erasure here means destroying the KEY, which leaves the ciphertext in
			// place. A missing file means data the chain says existed was removed.
			return fmt.Errorf("item %s is MISSING: the chain records it, but its file is gone", e.EntryID)
		}
		if err != nil {
			return fmt.Errorf("item %s: %w", e.EntryID, err)
		}
		sum := sha512.Sum512(sealed)
		if hex.EncodeToString(sum[:]) != e.ContentHash {
			return fmt.Errorf("item %s was MODIFIED: it no longer matches the chain", e.EntryID)
		}
	}
	fmt.Printf("items        all %d encrypted files match the chain\n", len(entries))

	// 3. Each checkpoint is genuinely signed and commits to this chain. This is
	// what catches entries removed from the FRONT, which step 1 alone cannot.
	anchors, err := readAnchors(dir)
	if err != nil {
		return err
	}
	pubPEM, err := os.ReadFile(filepath.Join(dir, "keys", "mldsa65-public.pem"))
	if err != nil {
		return err
	}
	_, pub, err := keyfile.ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	previousHash := anchor.SeedAnchorHash
	for i, a := range anchors {
		ring, err := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{a.SigningKeyID: pub})
		if err != nil {
			return err
		}
		// A checkpoint commits to the chain AS IT WAS when signed, so it is checked
		// against the entries it covers, not against entries added since.
		if a.EntryCount < 1 || a.EntryCount > int64(len(entries)) {
			return fmt.Errorf("checkpoint %04d claims %d entries; the chain has %d",
				i+1, a.EntryCount, len(entries))
		}
		br, err := verify.VerifyAnchor(a, entries[:a.EntryCount], previousHash, ring)
		if err != nil {
			return fmt.Errorf("checkpoint %04d: %w", i+1, err)
		}
		if !br.Bound || !br.SignatureVerified {
			return fmt.Errorf("checkpoint %04d does NOT verify: %s", i+1, br.Detail)
		}
		fmt.Printf("checkpoint   %04d signed, covers %d entries\n", i+1, br.EntriesCovered)
		previousHash = a.ChainHash
	}
	if len(anchors) == 0 {
		fmt.Println("checkpoint   none yet: run `encrypted-artifact checkpoint`")
	}
	return nil
}

// ---------------------------------------------------------------------------
// open: the only step that needs the private ENCRYPTION key.
// ---------------------------------------------------------------------------

func cmdOpen(dir string, ks keystore, id string, out io.Writer) error {
	sealed, err := os.ReadFile(itemPath(dir, id))
	if err != nil {
		return err
	}
	encLen := xwing.CiphertextSize()
	if len(sealed) < encLen {
		return fmt.Errorf("item %s is too short to be sealed", id)
	}

	privPEM, err := ks.get(encryptionKeyName)
	if err != nil {
		return err
	}
	_, seed, err := keyfile.ParsePrivateKey(privPEM)
	if err != nil {
		return err
	}
	_, priv := xwing.DeriveKeyPair(seed)
	clear(seed)

	receiver, err := suite.NewReceiver(priv, []byte(hpkeInfo))
	if err != nil {
		return err
	}
	opener, err := receiver.Setup(sealed[:encLen])
	if err != nil {
		return err
	}
	plaintext, err := opener.Open(sealed[encLen:], []byte(id))
	if err != nil {
		return fmt.Errorf("item %s could not be decrypted: wrong key, or the file was altered", id)
	}
	_, err = out.Write(plaintext)
	return err
}

// ---------------------------------------------------------------------------
// Keystores. 1Password is the real one; file exists so the example can be
// tried without it.
// ---------------------------------------------------------------------------

type keystore interface {
	put(name string, secret []byte) error
	get(name string) ([]byte, error)
	describe() string
}

func newKeystore(kind, vault, dir string) (keystore, error) {
	switch kind {
	case "op":
		return opKeystore{vault: vault}, nil
	case "file":
		return fileKeystore{dir: filepath.Join(dir, "secrets")}, nil
	}
	return nil, fmt.Errorf("-keystore must be op or file, got %q", kind)
}

// opKeystore stores each private key as a 1Password DOCUMENT.
//
// The key reaches `op` as a file, never as a command-line argument, because
// arguments are visible to every process on the machine. The temporary file is
// mode 0600 in a private directory and removed immediately.
type opKeystore struct{ vault string }

func (o opKeystore) put(name string, secret []byte) error {
	tmp, err := os.MkdirTemp("", "encrypted-artifact-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	path := filepath.Join(tmp, name+".pem")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return err
	}
	out, err := exec.Command("op", "document", "create", path,
		"--vault", o.vault, "--title", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("op document create: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (o opKeystore) get(name string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("op", "document", "get", name, "--vault", o.vault)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("op document get %s: %s", name, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (o opKeystore) describe() string { return "1Password vault " + o.vault }

// fileKeystore is for trying the example only: the private keys sit on disk
// next to the data they protect.
type fileKeystore struct{ dir string }

func (f fileKeystore) put(name string, secret []byte) error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(f.dir, name+".pem"), secret, 0o600)
}

func (f fileKeystore) get(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, name+".pem"))
}

func (f fileKeystore) describe() string { return f.dir + " (demo only)" }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// loadEncryptionPublicKey reads keys/xwing-public.pem.
func loadEncryptionPublicKey(dir string) (kem.PublicKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "keys", "xwing-public.pem"))
	if err != nil {
		return nil, err
	}
	alg, pub, err := keyfile.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	if alg != keyfile.XWing {
		return nil, fmt.Errorf("keys/xwing-public.pem holds a %s key, want X-Wing", alg)
	}
	return xwing.UnmarshalBinaryPublicKey(pub)
}

func itemPath(dir, id string) string { return filepath.Join(dir, "items", id+".sealed") }

func newItemID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "item-" + hex.EncodeToString(b), nil
}

// readChain returns the chain's entries in order, in the export form verify reads.
func readChain(dir string) ([]verify.Entry, error) {
	st, err := boltstore.Open(filepath.Join(dir, "chain.db"))
	if err != nil {
		return nil, err
	}
	defer st.Close()
	rows, err := st.Range(context.Background(), chainID, 0, 1<<62, 0)
	if err != nil {
		return nil, err
	}
	entries := make([]verify.Entry, len(rows))
	for i, r := range rows {
		entries[i] = verify.Entry{
			EntryID: r.EntryID, EntryType: r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion, GlobalSeq: r.GlobalSeq,
			ContentHash: r.ContentHash, ChainHash: r.ChainHash,
		}
	}
	return entries, nil
}

func readAnchors(dir string) ([]anchor.Anchor, error) {
	names, err := filepath.Glob(filepath.Join(dir, "anchors", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]anchor.Anchor, 0, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		var a anchor.Anchor
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: encrypted-artifact init|commit FILE…|checkpoint|verify|open ID [-dir D] [-keystore op|file] [-vault V]")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "encrypted-artifact:", err)
	os.Exit(1)
}
