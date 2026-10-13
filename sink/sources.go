// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/internal/safebolt"
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
type sourcesStore struct{ db *safebolt.DB }

func openSources(path string, lockTimeout time.Duration) (*sourcesStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	isNew := created(path)
	db, err := safebolt.Open(path, 0o600, boltOptions(lockTimeout, false))
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

// openSourcesReadOnly opens the sources file for reading (a shared lock),
// creating and changing nothing. It returns nil when there is none: a sink
// that never saw a Source has no sources file. A file without the bucket is
// refused: it is not a sources file.
func openSourcesReadOnly(path string, lockTimeout time.Duration) (*sourcesStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	db, err := safebolt.Open(path, 0o600, boltOptions(lockTimeout, true))
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(sourcesBucket) == nil {
			return fmt.Errorf("sink: %s is not a sources file: %w", path, ErrCorrupt)
		}
		return nil
	}); err != nil {
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

// positionValue is a position as stored: entry id ‖ big-endian global_seq.
func positionValue(p position) []byte {
	v := make([]byte, 0, len(p.entryID)+8)
	v = append(v, p.entryID...)
	return binary.BigEndian.AppendUint64(v, uint64(p.seq))
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
				if err := b.Put(sourceKey(chain, src), positionValue(p)); err != nil {
					return fmt.Errorf("sink: record source: %w", err)
				}
			}
		}
		return nil
	})
}

// deleteRows removes the given positions (chain → source → position) in ONE
// transaction: the cleanup of a failed commit. A row is removed only while it
// still holds exactly that position, so a row written since is never touched.
func (s *sourcesStore) deleteRows(positions map[string]map[string]position) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(sourcesBucket)
		for chain, bySource := range positions {
			for src, p := range bySource {
				k := sourceKey(chain, src)
				if !bytes.Equal(b.Get(k), positionValue(p)) {
					continue
				}
				if err := b.Delete(k); err != nil {
					return fmt.Errorf("sink: delete source: %w", err)
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

// sourceRow is one row of the sources file as a scan sees it: the chain it is
// keyed under and the position it holds. It never carries the source itself,
// which names an upstream message and is not for reports.
type sourceRow struct {
	chain string
	pos   position
	// malformed: the key is not chain ‖ 0x00 ‖ source with a valid chain id, or
	// the value is not a valid entry id ‖ sequence. chain and pos are then empty.
	malformed bool
}

// parseSourceRow reads one stored row.
func parseSourceRow(k, v []byte) sourceRow {
	i := bytes.IndexByte(k, 0)
	if i < 0 || !ValidChainID(string(k[:i])) || len(v) < 8 || !entryIDPattern.Match(v[:len(v)-8]) {
		return sourceRow{malformed: true}
	}
	seq := int64(binary.BigEndian.Uint64(v[len(v)-8:]))
	if seq < 0 {
		return sourceRow{malformed: true}
	}
	return sourceRow{chain: string(k[:i]), pos: position{entryID: string(v[:len(v)-8]), seq: seq}}
}

// rowsAfter returns up to limit rows after the key `after` (nil from the
// first), in key order (so a chain's rows are together), the last key examined
// (the next call's `after`: it holds a source, so it is a cursor only, never
// shown), and whether the file is done.
func (s *sourcesStore) rowsAfter(after []byte, limit int) (rows []sourceRow, next []byte, done bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(sourcesBucket).Cursor()
		var k, v []byte
		if after == nil {
			k, v = c.First()
		} else {
			k, v = c.Seek(after)
			if k != nil && bytes.Equal(k, after) {
				k, v = c.Next()
			}
		}
		for ; k != nil && len(rows) < limit; k, v = c.Next() {
			next = bytes.Clone(k)
			rows = append(rows, parseSourceRow(k, v))
		}
		done = k == nil
		return nil
	})
	return rows, next, done, err
}

// dangling counts, and with remove deletes (in ONE transaction), the rows of
// one chain for which stands reports false: positions no entry stands at.
// stands is asked about a position only; it must not write to this file. A
// malformed row is not a position this sink wrote: reported by Verify, never
// guessed at here.
func (s *sourcesStore) dangling(chain string, stands func(position) (bool, error), remove bool) (int, error) {
	prefix := sourceKey(chain, "")
	n := 0
	scan := func(tx *bolt.Tx) error {
		n = 0
		b := tx.Bucket(sourcesBucket)
		c := b.Cursor()
		var doomed [][]byte
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			row := parseSourceRow(k, v)
			if row.malformed {
				continue
			}
			ok, err := stands(row.pos)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
			n++
			if remove {
				doomed = append(doomed, bytes.Clone(k))
			}
		}
		for _, k := range doomed {
			if err := b.Delete(k); err != nil {
				return fmt.Errorf("sink: delete source: %w", err)
			}
		}
		return nil
	}
	if remove {
		return n, s.db.Update(scan)
	}
	return n, s.db.View(scan)
}

// chainsWithRowsAfter lists up to limit chains with a source row, after *after
// (nil from the first), in order.
func (s *sourcesStore) chainsWithRowsAfter(after *string, limit int) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		out = chainsAfterIn(tx, [][]byte{sourcesBucket}, after, limit)
		return nil
	})
	return out, err
}
