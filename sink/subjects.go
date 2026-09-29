// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The subject index (evidence.db.subjects, SECRET) is the only place the sink
// records which subject a chain is about. Chain ids are opaque, so without it
// the shareable artifacts (evidence.db, checkpoints) never name a subject.
//
//	forward:  subject ‖ 0x00 ‖ class  →  chain id
//	reverse:  chain id                →  class ‖ 0x00 ‖ subject
//
// Forward and reverse rows are written, and removed, in ONE transaction, so the
// index never disagrees with itself. A new pair's rows are written BEFORE its
// chain gets its first entry, so a chain never exists without its row
// (docs/AleutianChain/subject_index_design.md, "Crash consistency").

var (
	forwardBucket = []byte("forward")
	reverseBucket = []byte("reverse")
)

// subjectsStore is the open subject index.
type subjectsStore struct{ db *bolt.DB }

func openSubjects(path string, lockTimeout time.Duration) (*subjectsStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{forwardBucket, reverseBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("sink: initialise %s: %w", path, err)
	}
	return &subjectsStore{db: db}, nil
}

func (s *subjectsStore) Close() error { return s.db.Close() }

func forwardKey(subject, class string) []byte {
	k := make([]byte, 0, len(subject)+1+len(class))
	k = append(k, subject...)
	k = append(k, 0)
	return append(k, class...)
}

func reverseValue(class, subject string) []byte {
	v := make([]byte, 0, len(class)+1+len(subject))
	v = append(v, class...)
	v = append(v, 0)
	return append(v, subject...)
}

// lookup returns the chain of a (subject, class) pair, if it has one.
func (s *subjectsStore) lookup(subject, class string) (string, bool, error) {
	var chain string
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(forwardBucket).Get(forwardKey(subject, class)); v != nil {
			chain = string(v)
		}
		return nil
	})
	return chain, chain != "", err
}

// bind records that chain holds the (subject, class) pair's evidence: forward
// and reverse rows, one transaction. It refuses to overwrite either: a pair
// has one chain, and a chain one pair.
func (s *subjectsStore) bind(subject, class, chain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		fw, rv := tx.Bucket(forwardBucket), tx.Bucket(reverseBucket)
		if fw.Get(forwardKey(subject, class)) != nil {
			return fmt.Errorf("sink: the subject already has a chain in class %s", class)
		}
		if rv.Get([]byte(chain)) != nil {
			return fmt.Errorf("sink: chain %s is already bound", chain)
		}
		if err := fw.Put(forwardKey(subject, class), []byte(chain)); err != nil {
			return err
		}
		return rv.Put([]byte(chain), reverseValue(class, subject))
	})
}

// owner returns the (class, subject) a chain is bound to, if any.
func (s *subjectsStore) owner(chain string) (class, subject string, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(reverseBucket).Get([]byte(chain))
		if v == nil {
			return nil
		}
		i := bytes.IndexByte(v, 0)
		if i < 0 {
			return fmt.Errorf("sink: a reverse index row is malformed")
		}
		class, subject, ok = string(v[:i]), string(v[i+1:]), true
		return nil
	})
	return class, subject, ok, err
}
