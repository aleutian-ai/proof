// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package noncestore keeps the nonces of salted commitments in a local file
// beside the evidence database.
//
// # Description
//
// A salted commitment can only ever be disclosed with its nonce. When the MCP
// server makes one on an agent's behalf, the agent cannot keep it: a model has
// no durable storage, and a nonce returned into the conversation goes to the
// model provider's transcript, where the operator cannot erase it. So the server
// keeps it here instead, and returns nothing secret.
//
// The file is SEPARATE from the evidence database on purpose. The evidence is
// meant to be shared; nonces are the secret that keeps it unguessable. Erasing
// an item means deleting its nonce here (and its content wherever that lives).
//
// Keys are chainID ‖ 0x00 ‖ entryID. Chain ids never contain NUL (the store
// refuses them), so a key cannot be read as belonging to another chain.
package noncestore

import (
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("nonces")

// ErrNotFound is returned when no nonce is stored for an entry.
var ErrNotFound = errors.New("noncestore: no nonce stored for that entry")

// Store is an open nonce file. Not safe for use by more than one process at a
// time: bbolt's file lock enforces that.
type Store struct{ db *bolt.DB }

// PathFor names the nonce file that belongs to an evidence database.
func PathFor(dbPath string) string { return dbPath + ".nonces" }

// Open opens (creating if needed) a nonce file, waiting up to lockTimeout for
// another process to release it.
func Open(path string, lockTimeout time.Duration) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, fmt.Errorf("noncestore: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("noncestore: initialise %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close releases the file.
func (s *Store) Close() error { return s.db.Close() }

func key(chainID, entryID string) []byte {
	k := make([]byte, 0, len(chainID)+1+len(entryID))
	k = append(k, chainID...)
	k = append(k, 0)
	return append(k, entryID...)
}

// PutBatch stores nonces for a chain's entries in one atomic transaction.
func (s *Store) PutBatch(chainID string, nonces map[string][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for id, n := range nonces {
			if err := b.Put(key(chainID, id), n); err != nil {
				return fmt.Errorf("noncestore: put %s: %w", id, err)
			}
		}
		return nil
	})
}

// Get returns an entry's nonce, or ErrNotFound.
func (s *Store) Get(chainID, entryID string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucket).Get(key(chainID, entryID))
		if v == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// Delete removes an entry's nonce. Deleting a nonce that is not there is not an
// error: the outcome the caller wants — no nonce stored — already holds.
func (s *Store) Delete(chainID, entryID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Delete(key(chainID, entryID))
	})
}
