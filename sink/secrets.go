// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The secrets file (evidence.db.secrets, SECRET) holds the two halves of what
// opens an event's commitment: the event's exact bytes, and its nonce.
//
//	content:  chain ‖ 0x00 ‖ entry id  →  the exact bytes committed (or an erasure record)
//	nonces:   chain ‖ 0x00 ‖ entry id  →  32-byte nonce
//
// Both are written in ONE transaction, which is durable before the evidence
// transaction that commits the entries (docs/sink-format.md §7): a committed
// entry can never point at content that did not reach the disk. Erasure deletes
// rows and then rewrites the file, so erased content leaves the live file, as
// the nonces always did.

var (
	contentBucket = []byte("content")
	noncesBucket  = []byte("nonces")
)

// secret is one entry's content and nonce, as written by Commit. An erasure
// record has content and no nonce.
type secret struct {
	content []byte
	nonce   []byte
}

// secretsStore is the open secrets file.
type secretsStore struct{ db *bolt.DB }

// openSecrets opens (creating if needed) the secrets file for writing.
func openSecrets(path string, lockTimeout time.Duration) (*secretsStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	isNew := created(path)
	db, err := bolt.Open(path, 0o600, boltOptions(lockTimeout, false))
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{contentBucket, noncesBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("sink: initialise %s: %w", path, err)
	}
	if err := syncNewFile(path, isNew); err != nil {
		db.Close()
		return nil, err
	}
	return &secretsStore{db: db}, nil
}

// openSecretsReadOnly opens the secrets file for reading (a shared lock),
// creating and changing nothing. It returns nil when there is none: every
// event then reports as unopenable, which is the truth. A file without both
// buckets is refused.
func openSecretsReadOnly(path string, lockTimeout time.Duration) (*secretsStore, error) {
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
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(contentBucket) == nil || tx.Bucket(noncesBucket) == nil {
			return fmt.Errorf("sink: %s is not a secrets file", path)
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &secretsStore{db: db}, nil
}

func (s *secretsStore) Close() error { return s.db.Close() }

// rowKey is chain ‖ 0x00 ‖ entry id: the key of every per-entry row, secret
// (content, nonces) or public (signatures). Neither id can hold a NUL, so a key
// splits one way.
func rowKey(chain, entryID string) []byte {
	k := make([]byte, 0, len(chain)+1+len(entryID))
	k = append(k, chain...)
	k = append(k, 0)
	return append(k, entryID...)
}

// putAll writes the rows of several chains (chain → entry id → secret) in ONE
// transaction. A nil nonce writes no nonce (an erasure record).
func (s *secretsStore) putAll(rows map[string]map[string]secret) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		cb, nb := tx.Bucket(contentBucket), tx.Bucket(noncesBucket)
		for chain, byEntry := range rows {
			for id, sec := range byEntry {
				if err := cb.Put(rowKey(chain, id), sec.content); err != nil {
					return fmt.Errorf("sink: store content: %w", err)
				}
				if sec.nonce != nil {
					if err := nb.Put(rowKey(chain, id), sec.nonce); err != nil {
						return fmt.Errorf("sink: store nonce: %w", err)
					}
				}
			}
		}
		return nil
	})
}

// deleteRows removes the content and nonces of the given entries (chain →
// entry ids) in ONE transaction. A row that is not there is not an error.
func (s *secretsStore) deleteRows(ids map[string][]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		cb, nb := tx.Bucket(contentBucket), tx.Bucket(noncesBucket)
		for chain, list := range ids {
			for _, id := range list {
				if err := cb.Delete(rowKey(chain, id)); err != nil {
					return fmt.Errorf("sink: delete content: %w", err)
				}
				if err := nb.Delete(rowKey(chain, id)); err != nil {
					return fmt.Errorf("sink: delete nonce: %w", err)
				}
			}
		}
		return nil
	})
}

// get returns an entry's content and nonce; a nil slice means that half is
// absent. Sizes are checked before anything is copied (a crafted file could
// hold huge values): content over MaxContentBytes is reported as tooBig and not
// copied, and a nonce that is not 32 bytes comes back empty (non-nil), which
// opens nothing.
func (s *secretsStore) get(chain, entryID string) (content, nonce []byte, tooBig bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(contentBucket).Get(rowKey(chain, entryID)); v != nil {
			if len(v) > MaxContentBytes {
				tooBig = true
			} else {
				content = append([]byte(nil), v...)
			}
		}
		if v := tx.Bucket(noncesBucket).Get(rowKey(chain, entryID)); v != nil {
			nonce = []byte{}
			if len(v) == 32 {
				nonce = append(nonce, v...)
			}
		}
		return nil
	})
	return content, nonce, tooBig, err
}

// contentIDs lists the entry ids that have a content row on a chain.
func (s *secretsStore) contentIDs(chain string) ([]string, error) {
	return s.idsIn(chain, contentBucket)
}

// rowIDs lists, once each, the entry ids that have a content OR a nonce row on
// a chain.
func (s *secretsStore) rowIDs(chain string) ([]string, error) {
	c, err := s.idsIn(chain, contentBucket)
	if err != nil {
		return nil, err
	}
	n, err := s.idsIn(chain, noncesBucket)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range append(c, n...) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *secretsStore) idsIn(chain string, bucket []byte) ([]string, error) {
	prefix := rowKey(chain, "")
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			ids = append(ids, string(k[len(prefix):]))
		}
		return nil
	})
	return ids, err
}

// malformedKeys counts the rows whose key is not chain ‖ 0x00 ‖ entry id with a
// valid chain id and a valid entry id. The sink never writes such a row; one
// that exists was planted, and the prefix scans of erase and Verify would miss
// it, so it is counted (never shown: a crafted key could hold anything).
func (s *secretsStore) malformedKeys() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{contentBucket, noncesBucket} {
			if err := tx.Bucket(b).ForEach(func(k, _ []byte) error {
				i := bytes.IndexByte(k, 0)
				if i < 0 || !ValidChainID(string(k[:i])) || !entryIDPattern.Match(k[i+1:]) {
					n++
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

// chainsWithRows lists, once each, every chain that has a content or nonce row.
// Keys are chain ‖ 0x00 ‖ entry id, and a valid chain id holds no NUL, so the
// chain is everything before the first NUL. After each chain it seeks past that
// chain's rows, so the cost is one step per chain, not per row.
func (s *secretsStore) chainsWithRows() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{contentBucket, noncesBucket} {
			c := tx.Bucket(b).Cursor()
			for k, _ := c.First(); k != nil; {
				i := bytes.IndexByte(k, 0)
				if i < 0 {
					k, _ = c.Next() // malformed; counted by malformedKeys
					continue
				}
				chain := string(k[:i])
				if !seen[chain] {
					seen[chain] = true
					out = append(out, chain)
				}
				// chain ‖ 0x01 sorts after every chain ‖ 0x00 ‖ … key.
				k, _ = c.Seek(append([]byte(chain), 1))
			}
		}
		return nil
	})
	return out, err
}

// eraseChain removes, in ONE transaction, every nonce of a chain and every
// content row except the genuine erasure records in keep, each kept only while
// it holds exactly its record (anything else in a record's place may be
// content). A kept record whose row is missing is written back: the record is
// public and fixed, and without it Verify would report the erasure broken for
// good. A row keyed by the bare chain id (no entry id, never written by the
// sink) goes too. It returns how many rows it removed.
func (s *secretsStore) eraseChain(chain string, keep map[string][]byte) (int, error) {
	prefix := rowKey(chain, "")
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{noncesBucket, contentBucket} {
			bucket := tx.Bucket(b)
			c := bucket.Cursor()
			var doomed [][]byte
			for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				if bytes.Equal(b, contentBucket) {
					if want, ok := keep[string(k[len(prefix):])]; ok && bytes.Equal(v, want) {
						continue
					}
				}
				doomed = append(doomed, append([]byte(nil), k...))
			}
			if bucket.Get([]byte(chain)) != nil {
				doomed = append(doomed, []byte(chain))
			}
			for _, k := range doomed {
				if err := bucket.Delete(k); err != nil {
					return fmt.Errorf("sink: erase: %w", err)
				}
				n++
			}
		}
		cb := tx.Bucket(contentBucket)
		for id, record := range keep {
			if cb.Get(rowKey(chain, id)) == nil {
				if err := cb.Put(rowKey(chain, id), record); err != nil {
					return fmt.Errorf("sink: restore an erasure record: %w", err)
				}
			}
		}
		return nil
	})
	return n, err
}
