// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The sources file makes Commit idempotent for records that carry a Source.
//
// A streaming consumer acknowledges a message after committing it. A crash
// between the two makes the broker deliver the message again. To recognise it,
// the sink records, BEFORE each append, where every sourced record will land:
//
//	chain ‖ 0x00 ‖ source  →  entry id ‖ big-endian global_seq
//
// On a later Commit of the same source the position is checked against the
// chain. The entry is there → the record is a duplicate. It is not → the earlier
// attempt stopped before its append, and the record is committed now.
//
// Positions, not content: a source names where a message sat upstream (a stream
// sequence, an offset), never what it said. But a position maps the chain's
// events to exact upstream messages, so erasure deletes the chain's rows and
// rewrites the file. A redelivery arriving after an erasure is therefore
// committed again, to the subject's new chain.

var sourcesBucket = []byte("sources")

// MaxSourceBytes caps a Record's Source.
const MaxSourceBytes = 256

// position is where a sourced record was, or will be, committed.
type position struct {
	entryID string
	seq     int64
}

// sourcesStore is the open sources file.
type sourcesStore struct{ db *bolt.DB }

func openSources(path string, lockTimeout time.Duration) (*sourcesStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	isNew := created(path)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(sourcesBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("sink: initialise %s: %w", path, err)
	}
	if err := syncNewFile(path, isNew); err != nil {
		db.Close()
		return nil, err
	}
	return &sourcesStore{db: db}, nil
}

func (s *sourcesStore) Close() error { return s.db.Close() }

func sourceKey(chain, source string) []byte {
	k := make([]byte, 0, len(chain)+1+len(source))
	k = append(k, chain...)
	k = append(k, 0)
	return append(k, source...)
}

// get returns a source's recorded position, and whether there is one.
func (s *sourcesStore) get(chain, source string) (position, bool, error) {
	var p position
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(sourcesBucket).Get(sourceKey(chain, source))
		if v == nil {
			return nil
		}
		if len(v) < 8 {
			return errors.New("sink: a sources record is truncated")
		}
		found = true
		p = position{entryID: string(v[:len(v)-8]), seq: int64(binary.BigEndian.Uint64(v[len(v)-8:]))}
		return nil
	})
	return p, found, err
}

// putAll records positions for several chains (chain → source → position) in
// ONE transaction.
func (s *sourcesStore) putAll(positions map[string]map[string]position) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(sourcesBucket)
		for chain, bySource := range positions {
			for src, p := range bySource {
				v := make([]byte, 0, len(p.entryID)+8)
				v = append(v, p.entryID...)
				v = binary.BigEndian.AppendUint64(v, uint64(p.seq))
				if err := b.Put(sourceKey(chain, src), v); err != nil {
					return fmt.Errorf("sink: record source: %w", err)
				}
			}
		}
		return nil
	})
}

// deleteChain removes every recorded position of one chain, in one
// transaction, and returns how many it removed.
func (s *sourcesStore) deleteChain(chain string) (int, error) {
	prefix := sourceKey(chain, "")
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(sourcesBucket).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Seek(prefix) {
			if err := c.Delete(); err != nil {
				return fmt.Errorf("sink: delete source: %w", err)
			}
			n++
		}
		return nil
	})
	return n, err
}
