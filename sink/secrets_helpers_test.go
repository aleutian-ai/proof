// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

// Content now lives in evidence.db.secrets (_74c). These stand in for the file
// operations the tests used to tamper with content: each opens the secrets file
// directly, as someone editing it would.

func withSecrets(s *Sink, fn func(tx *bolt.Tx) error) error {
	db, err := bolt.Open(s.secretsPath(), 0o600, &bolt.Options{Timeout: DefaultLockTimeout})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{contentBucket, noncesBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// viewSecrets reads the secrets file read-only: a reading helper must never
// create the file or its buckets, or it would hide what it is checking.
func viewSecrets(s *Sink, fn func(tx *bolt.Tx) error) error {
	db, err := bolt.Open(s.secretsPath(), 0o600, &bolt.Options{Timeout: DefaultLockTimeout, ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(contentBucket) == nil || tx.Bucket(noncesBucket) == nil {
			return fmt.Errorf("%s is not a secrets file", s.secretsPath())
		}
		return fn(tx)
	})
}

// writeContent replaces (or creates) an entry's content row.
func writeContent(s *Sink, chain, id string, data []byte) error {
	return withSecrets(s, func(tx *bolt.Tx) error {
		return tx.Bucket(contentBucket).Put(rowKey(chain, id), data)
	})
}

// removeContent deletes an entry's content row.
func removeContent(s *Sink, chain, id string) error {
	return withSecrets(s, func(tx *bolt.Tx) error {
		if tx.Bucket(contentBucket).Get(rowKey(chain, id)) == nil {
			return fmt.Errorf("content of %s: %w", id, os.ErrNotExist)
		}
		return tx.Bucket(contentBucket).Delete(rowKey(chain, id))
	})
}

// removeNonce deletes an entry's nonce.
func removeNonce(s *Sink, chain, id string) error {
	return withSecrets(s, func(tx *bolt.Tx) error {
		return tx.Bucket(noncesBucket).Delete(rowKey(chain, id))
	})
}

// readContent returns an entry's content row; a missing row is os.ErrNotExist.
func readContent(s *Sink, chain, id string) ([]byte, error) {
	var out []byte
	err := viewSecrets(s, func(tx *bolt.Tx) error {
		v := tx.Bucket(contentBucket).Get(rowKey(chain, id))
		if v == nil {
			return fmt.Errorf("content of %s: %w", id, os.ErrNotExist)
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// statContent reports whether an entry's content row exists, as os.Stat does
// for a file: an error wrapping os.ErrNotExist when it does not.
func statContent(s *Sink, chain, id string) (bool, error) {
	_, err := readContent(s, chain, id)
	return err == nil, err
}

// writeNonce replaces (or creates) an entry's nonce.
func writeNonce(s *Sink, chain, id string, nonce []byte) error {
	return withSecrets(s, func(tx *bolt.Tx) error {
		return tx.Bucket(noncesBucket).Put(rowKey(chain, id), nonce)
	})
}

// hasNonce reports whether an entry's nonce is stored.
func hasNonce(s *Sink, chain, id string) (bool, error) {
	found := false
	err := viewSecrets(s, func(tx *bolt.Tx) error {
		found = tx.Bucket(noncesBucket).Get(rowKey(chain, id)) != nil
		return nil
	})
	return found, err
}

// secretRowCount counts every content and nonce row, of every chain.
func secretRowCount(s *Sink) (int, error) {
	if _, err := os.Stat(s.secretsPath()); os.IsNotExist(err) {
		return 0, nil
	}
	n := 0
	err := viewSecrets(s, func(tx *bolt.Tx) error {
		n = tx.Bucket(contentBucket).Stats().KeyN + tx.Bucket(noncesBucket).Stats().KeyN
		return nil
	})
	return n, err
}

// readNonce returns an entry's nonce; a missing one is os.ErrNotExist.
func readNonce(s *Sink, chain, id string) ([]byte, error) {
	var out []byte
	err := viewSecrets(s, func(tx *bolt.Tx) error {
		v := tx.Bucket(noncesBucket).Get(rowKey(chain, id))
		if v == nil {
			return fmt.Errorf("nonce of %s: %w", id, os.ErrNotExist)
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}
