// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
)

// The signatures file (evidence.db.signatures, shared with the evidence file:
// pseudonymous personal data, revealing no more than evidence.db does, plus the
// record key ids) holds a signing sink's record signatures
// (docs/sink-format.md, Record signatures):
//
//	signatures:  chain ‖ 0x00 ‖ entry id        →  key id (16 bytes) ‖ ML-DSA-65 signature (3309 bytes)
//	meta:        "record_signing"               →  "ml-dsa-65": this sink signs its records
//	meta:        "record_key" ‖ 0x00 ‖ key id   →  empty: every record key this sink has signed with
//
// Rows are written in ONE durable transaction BEFORE the evidence transaction
// that commits their entries: ordered durability, so a committed entry of a
// signing sink never lacks its signature on disk. (A crash in between leaves a
// signature with no entry; it names no subject.) Signatures chain through
// previous_hash, so such an orphan can only ever stand in at a chain's tail.
// Erasure ADDS the signatures of its erasure entries and never deletes a row:
// a signature covers a salted commitment whose nonce erasure deletes, and it
// keeps the erased chain verifiable. The file is compacted with the other
// files on every erasure, so rows a failed commit deleted leave its free pages.
//
// The signing mode is set by the first commit whose signatures were STORED,
// even if its append then fails (fail closed). A signer failure stores nothing
// and sets nothing.

var (
	signaturesBucket = []byte("signatures")
	metaBucket       = []byte("meta")

	metaRecordSigning = []byte("record_signing")
	metaRecordKey     = []byte("record_key\x00")
)

// recordSigningAlgorithm is the only value of meta.record_signing.
const recordSigningAlgorithm = "ml-dsa-65"

// signatureRowSize is a stored value's exact size.
const signatureRowSize = keyfile.KeyIDSize + anchor.SignatureSize

// signatureRow is one record's signature and the key id that made it.
type signatureRow struct {
	keyID string // 32 lowercase hex
	sig   []byte
}

// signaturesStore is the open signatures file.
type signaturesStore struct{ db *bolt.DB }

// openSignatures opens (creating if needed) the signatures file for writing.
func openSignatures(path string, lockTimeout time.Duration) (*signaturesStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	isNew := created(path)
	db, err := bolt.Open(path, 0o600, boltOptions(lockTimeout, false))
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	// Only write when the buckets are missing: a bbolt write transaction
	// rewrites the file's meta page even when it changes nothing, and an open
	// must not touch the file (a refused call writes nothing at all).
	ready := false
	if err := db.View(func(tx *bolt.Tx) error {
		ready = tx.Bucket(signaturesBucket) != nil && tx.Bucket(metaBucket) != nil
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("sink: read %s: %w", path, err)
	}
	if !ready {
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, b := range [][]byte{signaturesBucket, metaBucket} {
				if _, err := tx.CreateBucketIfNotExists(b); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			db.Close()
			return nil, fmt.Errorf("sink: initialise %s: %w", path, err)
		}
	}
	if err := syncNewFile(path, isNew); err != nil {
		db.Close()
		return nil, err
	}
	return &signaturesStore{db: db}, nil
}

// openSignaturesReadOnly opens the signatures file for reading (a shared lock),
// creating and changing nothing. It returns nil when there is none, and also
// for a file with NO buckets at all: a crash between bbolt creating the file
// and the transaction that adds its buckets leaves one, it holds nothing, and
// treating it as absent lets the next writer with a signer repair it. A file
// with only one of the two buckets is refused.
func openSignaturesReadOnly(path string, lockTimeout time.Duration) (*signaturesStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	db, err := bolt.Open(path, 0o600, boltOptions(lockTimeout, true))
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	empty := false
	if err := db.View(func(tx *bolt.Tx) error {
		sb, mb := tx.Bucket(signaturesBucket), tx.Bucket(metaBucket)
		switch {
		case sb == nil && mb == nil:
			k, _ := tx.Cursor().First()
			empty = k == nil // no bucket of any name
			if !empty {
				return fmt.Errorf("sink: %s is not a signatures file", path)
			}
		case sb == nil || mb == nil:
			return fmt.Errorf("sink: %s is not a signatures file", path)
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	if empty {
		db.Close()
		return nil, nil
	}
	return &signaturesStore{db: db}, nil
}

func (s *signaturesStore) Close() error { return s.db.Close() }

// putAll writes the rows of several chains (chain → entry id → row) in ONE
// transaction, together with the sink's signing mode and every key id used.
// Any invalid row refuses the whole call: nothing is written.
func (s *signaturesStore) putAll(rows map[string]map[string]signatureRow) error {
	n := 0
	for _, byEntry := range rows {
		n += len(byEntry)
	}
	if n == 0 {
		return errors.New("sink: store signatures: no rows (an empty call must not set the signing mode)")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		sb, mb := tx.Bucket(signaturesBucket), tx.Bucket(metaBucket)
		keyIDs := map[string]bool{}
		for chain, byEntry := range rows {
			if !ValidChainID(chain) {
				return errors.New("sink: store signatures: not a chain id this sink mints")
			}
			for id, row := range byEntry {
				if !entryIDPattern.MatchString(id) {
					return errors.New("sink: store signatures: not an entry id this sink assigns")
				}
				if !lowerHex32.MatchString(row.keyID) {
					return errors.New("sink: store signatures: key id is not 32 lowercase hex")
				}
				if len(row.sig) != anchor.SignatureSize {
					return fmt.Errorf("sink: store signatures: signature is %d bytes, want %d",
						len(row.sig), anchor.SignatureSize)
				}
				raw, _ := hex.DecodeString(row.keyID) // checked above
				v := make([]byte, 0, signatureRowSize)
				v = append(append(v, raw...), row.sig...)
				if err := sb.Put(rowKey(chain, id), v); err != nil {
					return fmt.Errorf("sink: store signature: %w", err)
				}
				keyIDs[row.keyID] = true
			}
		}
		for id := range keyIDs {
			if err := mb.Put(append(bytes.Clone(metaRecordKey), id...), []byte{}); err != nil {
				return fmt.Errorf("sink: record the key id: %w", err)
			}
		}
		if err := mb.Put(metaRecordSigning, []byte(recordSigningAlgorithm)); err != nil {
			return fmt.Errorf("sink: record the signing mode: %w", err)
		}
		return nil
	})
}

// deleteRows removes the signatures of the given entries (chain → entry ids)
// in ONE transaction: the cleanup of a failed commit. The key ids used stay
// recorded. A row that is not there is not an error.
func (s *signaturesStore) deleteRows(ids map[string][]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(signaturesBucket)
		for chain, list := range ids {
			for _, id := range list {
				if err := b.Delete(rowKey(chain, id)); err != nil {
					return fmt.Errorf("sink: delete signature: %w", err)
				}
			}
		}
		return nil
	})
}

// get returns an entry's signature row. found is false when there is none;
// malformed is true when the stored value is not exactly key id ‖ signature,
// in which case nothing is copied (a crafted file could hold anything).
func (s *signaturesStore) get(chain, entryID string) (row signatureRow, found, malformed bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(signaturesBucket).Get(rowKey(chain, entryID))
		if v == nil {
			return nil
		}
		found = true
		if len(v) != signatureRowSize {
			malformed = true
			return nil
		}
		row = signatureRow{
			keyID: hex.EncodeToString(v[:keyfile.KeyIDSize]),
			sig:   bytes.Clone(v[keyfile.KeyIDSize:]),
		}
		return nil
	})
	return row, found, malformed, err
}

// signing reports whether this sink signs its records (R3: set by the first
// stored signatures, never cleared). A marker with any other value than
// the one this sink writes is an error: the file was altered.
func (s *signaturesStore) signing() (bool, error) {
	on := false
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(metaBucket).Get(metaRecordSigning)
		switch {
		case v == nil:
		case string(v) == recordSigningAlgorithm:
			on = true
		default:
			return errors.New("sink: the signatures file's signing mode is not one this sink writes")
		}
		return nil
	})
	return on, err
}

// hasRecordKey reports whether this sink has signed records with the key id
// (32 lowercase hex): Checkpoint warns when its own key is one of them. A
// lookup, not a listing: the file may be crafted, and nothing here returns what
// it holds.
func (s *signaturesStore) hasRecordKey(id string) (bool, error) {
	if !lowerHex32.MatchString(id) {
		return false, errors.New("sink: not a key id")
	}
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(metaBucket).Get(append(bytes.Clone(metaRecordKey), id...)) != nil
		return nil
	})
	return found, err
}

// rowIDs lists the entry ids that have a signature row on a chain.
func (s *signaturesStore) rowIDs(chain string) ([]string, error) {
	prefix := rowKey(chain, "")
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(signaturesBucket).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			ids = append(ids, string(k[len(prefix):]))
		}
		return nil
	})
	return ids, err
}

// chainsWithRows lists, once each, every chain that has a signature row, one
// seek per chain (as secretsStore.chainsWithRows).
func (s *signaturesStore) chainsWithRows() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(signaturesBucket).Cursor()
		for k, _ := c.First(); k != nil; {
			i := bytes.IndexByte(k, 0)
			if i < 0 {
				k, _ = c.Next() // malformed; counted by malformedKeys
				continue
			}
			chain := string(k[:i])
			out = append(out, chain)
			k, _ = c.Seek(append([]byte(chain), 1))
		}
		return nil
	})
	return out, err
}

// malformedKeys counts the signature rows whose key is not chain ‖ 0x00 ‖
// entry id with a valid chain id and entry id: never written by the sink, and
// never shown (a crafted key could hold anything).
func (s *signaturesStore) malformedKeys() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(signaturesBucket).ForEach(func(k, _ []byte) error {
			i := bytes.IndexByte(k, 0)
			if i < 0 || !ValidChainID(string(k[:i])) || !entryIDPattern.Match(k[i+1:]) {
				n++
			}
			return nil
		})
	})
	return n, err
}

// deleteChain removes every signature row of a chain, in ONE transaction. Only
// for a chain with NO entries (a first commit that never reached it): there is
// no entry whose signature must survive, and rows left behind would make the
// erased chain look REMOVED for good. It returns how many it removed.
func (s *signaturesStore) deleteChain(chain string) (int, error) {
	prefix := rowKey(chain, "")
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(signaturesBucket)
		c := b.Cursor()
		var doomed [][]byte
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			doomed = append(doomed, bytes.Clone(k))
		}
		for _, k := range doomed {
			if err := b.Delete(k); err != nil {
				return fmt.Errorf("sink: delete signature: %w", err)
			}
			n++
		}
		return nil
	})
	return n, err
}
