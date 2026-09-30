// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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

// errInconsistentIndex is a subject-index row that disagrees with the rest of
// the index (see bindingOK). The index is then not trusted for that subject:
// nothing is committed or erased through it. The message never names the
// subject, and never suggests restoring an older index: an older copy re-links
// every subject erased since.
var errInconsistentIndex = errors.New("sink: the subject index is inconsistent (a row disagrees " +
	"with its chain); nothing was changed; repair it by hand (restoring an older copy would " +
	"re-link subjects erased since)")

// boundRow is one of a subject's forward rows, checked.
type boundRow struct {
	key   []byte // the forward key
	chain string
}

// bindingOK is THE index consistency rule, used by every reader (commit, erase,
// Verify, ChainSubjects): a valid pair and a valid chain id of the pair's class,
// agreeing in both directions (forward row → chain, reverse row → pair).
func bindingOK(tx *bolt.Tx, subject, class string, chain []byte) bool {
	return ValidClass(class) && ValidSubject(subject) && ValidChainID(string(chain)) &&
		bytes.HasPrefix(chain, []byte(class+".")) &&
		bytes.Equal(tx.Bucket(reverseBucket).Get(chain), reverseValue(class, subject)) &&
		bytes.Equal(tx.Bucket(forwardBucket).Get(forwardKey(subject, class)), chain)
}

// rowsOf returns the subject's forward rows in scope (every class, or just
// class), each checked by bindingOK.
func rowsOf(tx *bolt.Tx, subject, class string) ([]boundRow, error) {
	fw := tx.Bucket(forwardBucket)
	var rows []boundRow
	add := func(k, v []byte, class string) error {
		if !bindingOK(tx, subject, class, v) {
			return errInconsistentIndex
		}
		rows = append(rows, boundRow{key: append([]byte(nil), k...), chain: string(v)})
		return nil
	}
	if class != "" {
		k := forwardKey(subject, class)
		if v := fw.Get(k); v != nil {
			if err := add(k, v, class); err != nil {
				return nil, err
			}
		}
		return rows, nil
	}
	prefix := append([]byte(subject), 0)
	c := fw.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if err := add(k, v, string(k[len(prefix):])); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// lookup returns the chain of a (subject, class) pair, if it has one. A row
// that fails checkBinding is an error, never followed.
func (s *subjectsStore) lookup(subject, class string) (string, bool, error) {
	var chain string
	err := s.db.View(func(tx *bolt.Tx) error {
		rows, err := rowsOf(tx, subject, class)
		if err != nil || len(rows) == 0 {
			return err
		}
		chain = rows[0].chain
		return nil
	})
	return chain, chain != "", err
}

// chainsOf returns the subject's chains in scope (every class, or just class),
// checked, without changing anything: what forget WOULD mark pending.
func (s *subjectsStore) chainsOf(subject, class string) ([]string, error) {
	var chains []string
	err := s.db.View(func(tx *bolt.Tx) error {
		rows, err := rowsOf(tx, subject, class)
		for _, r := range rows {
			chains = append(chains, r.chain)
		}
		return err
	})
	return chains, err
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

// owner returns the (class, subject) a chain is bound to, if any. A pending row
// has no owner. Any other row must be a valid class and subject, of the chain's
// own class, or it is malformed and refused.
func (s *subjectsStore) owner(chain string) (class, subject string, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(reverseBucket).Get([]byte(chain))
		if v == nil || bytes.Equal(v, pendingMarker) {
			return nil // unbound, or pending: no live owner
		}
		i := bytes.IndexByte(v, 0)
		if i < 0 || !ValidClass(string(v[:i])) || !ValidSubject(string(v[i+1:])) ||
			!strings.HasPrefix(chain, string(v[:i])+".") {
			return errors.New("sink: a reverse index row is malformed")
		}
		class, subject, ok = string(v[:i]), string(v[i+1:]), true
		return nil
	})
	return class, subject, ok, err
}

// pendingMarker is the reverse row of a chain whose subject has been forgotten
// but whose erasure is not finished. It holds no subject. It cannot be confused
// with a live row: a live row starts with a class, which starts with [a-z0-9].
var pendingMarker = []byte("\x00pending-erasure")

// taken reports whether a chain id is bound in the index, live or pending. A
// pending chain is still taken: its id must never be minted for a new pair.
func (s *subjectsStore) taken(chain string) (bool, error) {
	var taken bool
	err := s.db.View(func(tx *bolt.Tx) error {
		taken = tx.Bucket(reverseBucket).Get([]byte(chain)) != nil
		return nil
	})
	return taken, err
}

// forget is the FIRST step of erasing a subject: in one transaction, it deletes
// the subject's forward rows (all classes, or just class) and turns each of
// their chains' reverse rows into the pending marker, which holds no subject.
// After it commits, the index no longer knows the subject; a new event for it
// gets a new chain and can never rejoin one of these. It returns the chains now
// pending.
func (s *subjectsStore) forget(subject, class string) ([]string, error) {
	var chains []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		rows, err := rowsOf(tx, subject, class)
		if err != nil {
			return err // nothing forgotten: the transaction is rolled back
		}
		fw, rv := tx.Bucket(forwardBucket), tx.Bucket(reverseBucket)
		for _, r := range rows {
			if err := fw.Delete(r.key); err != nil {
				return err
			}
			if err := rv.Put([]byte(r.chain), pendingMarker); err != nil {
				return err
			}
			chains = append(chains, r.chain)
		}
		return nil
	})
	if err != nil {
		chains = nil
	}
	return chains, err
}

// pending lists every chain whose erasure was started and not finished, of any
// subject: a crash after forget, or part-way through erasing. Ids are returned
// raw; the eraser checks each (ValidChainID) before using it.
func (s *subjectsStore) pending() ([]string, error) {
	var chains []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).ForEach(func(k, v []byte) error {
			if bytes.Equal(v, pendingMarker) {
				chains = append(chains, string(k))
			}
			return nil
		})
	})
	return chains, err
}

// clear removes a pending chain's reverse row, once its erasure is complete. It
// refuses to remove a live row.
func (s *subjectsStore) clear(chain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		rv := tx.Bucket(reverseBucket)
		v := rv.Get([]byte(chain))
		if v == nil {
			return nil
		}
		if !bytes.Equal(v, pendingMarker) {
			return fmt.Errorf("sink: chain %s is live in the index, not pending; not cleared", chain)
		}
		return rv.Delete([]byte(chain))
	})
}

// openSubjectsReadOnly opens the subject index for reading (a shared lock),
// creating and changing nothing. It returns nil when there is no index file.
// A file without the index's buckets is refused: it is not a subject index.
func openSubjectsReadOnly(path string, lockTimeout time.Duration) (*subjectsStore, error) {
	if err := regularOrAbsent(path); err != nil {
		return nil, fmt.Errorf("sink: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout, ReadOnly: true})
	if err != nil {
		return nil, busy(fmt.Errorf("sink: open %s: %w", path, err))
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(forwardBucket) == nil || tx.Bucket(reverseBucket) == nil {
			return fmt.Errorf("sink: %s is not a subject index", path)
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &subjectsStore{db: db}, nil
}

// rowState is a reverse row's state: IndexLive (the row passes bindingOK),
// IndexPending, IndexMalformed, or "" when there is no row.
func rowState(tx *bolt.Tx, chain, v []byte) IndexState {
	switch {
	case v == nil:
		return ""
	case !ValidChainID(string(chain)):
		return IndexMalformed
	case bytes.Equal(v, pendingMarker):
		return IndexPending
	}
	i := bytes.IndexByte(v, 0)
	if i < 0 || !bindingOK(tx, string(v[i+1:]), string(v[:i]), chain) {
		return IndexMalformed
	}
	return IndexLive
}

// indexSnapshot is one read transaction on the subject index: a consistent view
// for a whole Verify run. A nil snapshot is an absent index: no rows.
type indexSnapshot struct{ tx *bolt.Tx }

func (s *subjectsStore) snapshot() (*indexSnapshot, error) {
	tx, err := s.db.Begin(false)
	if err != nil {
		return nil, fmt.Errorf("sink: read the subject index: %w", err)
	}
	return &indexSnapshot{tx: tx}, nil
}

func (x *indexSnapshot) close() {
	if x != nil {
		_ = x.tx.Rollback()
	}
}

// state is a chain's row state (rowState).
func (x *indexSnapshot) state(chain string) IndexState {
	if x == nil {
		return ""
	}
	return rowState(x.tx, []byte(chain), x.tx.Bucket(reverseBucket).Get([]byte(chain)))
}

// eachReverse calls fn for every reverse row, with its state. The key is
// passed raw: it may be anything a crafted file holds, so the caller must not
// print it unless it is a valid chain id.
func (x *indexSnapshot) eachReverse(ctx context.Context, fn func(key []byte, state IndexState)) error {
	if x == nil {
		return nil
	}
	return x.tx.Bucket(reverseBucket).ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fn(k, rowState(x.tx, k, v))
		return nil
	})
}

// eachBadForward calls fn with the value (a would-be chain id, raw) of every
// forward row that fails bindingOK: a row that still names a subject whose
// chain is pending, erased or bound to another pair. The forward KEY holds the
// subject, so it is never passed on.
func (x *indexSnapshot) eachBadForward(ctx context.Context, fn func(chain []byte)) error {
	if x == nil {
		return nil
	}
	return x.tx.Bucket(forwardBucket).ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		i := bytes.IndexByte(k, 0)
		if i < 0 || !bindingOK(x.tx, string(k[:i]), string(k[i+1:]), v) {
			fn(v)
		}
		return nil
	})
}

// liveChains lists every chain with a live row.
func (s *subjectsStore) liveChains() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).ForEach(func(k, v []byte) error {
			if rowState(tx, k, v) == IndexLive {
				out = append(out, string(k))
			}
			return nil
		})
	})
	return out, err
}

// forgetChain turns ONE live chain's rows into a pending erasure: the forward
// row goes and the reverse row becomes the marker, in one transaction. It is
// how resume repairs a relinked chain (a live row on an erased chain). A row
// that is not live is left alone.
func (s *subjectsStore) forgetChain(chain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		rv := tx.Bucket(reverseBucket)
		v := rv.Get([]byte(chain))
		if rowState(tx, []byte(chain), v) != IndexLive {
			return nil
		}
		i := bytes.IndexByte(v, 0)
		if err := tx.Bucket(forwardBucket).Delete(forwardKey(string(v[i+1:]), string(v[:i]))); err != nil {
			return err
		}
		return rv.Put([]byte(chain), pendingMarker)
	})
}

// ChainSubjects returns every live chain's (class, subject), read from the
// secret subject index.
//
// # Description
//
// This is the one call that names subjects. Verify never does; a caller that
// needs to know whose chain is whose (`proof sink verify --show-subjects`)
// asks for it here, deliberately, so crossing the privacy boundary is visible
// in its code. Pending and malformed rows are skipped (a pending row holds no
// subject; Verify reports both).
//
// # Inputs
//
//   - ctx: checked before reading
//
// # Outputs
//
//   - []ChainSubject: in chain-id order; nil when there is no index file. Never a
//     chain that ends with its erasure, even if a restored index re-links it.
//   - error: ctx is done; the folder is not a sink (no evidence file); the
//     index cannot be read; or the folder is busy (ErrBusy)
//
// # Example
//
//	rows, err := s.ChainSubjects(ctx)
//	if err != nil {
//	    return err
//	}
//	// rows is secret-index material: never log it.
//
// # Limitations
//
//   - The result is as sensitive as the index file. Do not log, print or keep it
//     beyond its use; printed, it re-identifies chains after any erasure.
//   - It holds every live row in memory: one entry per (class, subject). For a
//     very large index, that is the whole secret index in memory at once.
//
// # Assumptions
//
//   - Read-only: it takes a shared lock on the evidence file and the index, and
//     creates nothing.
func (s *Sink) ChainSubjects(ctx context.Context) ([]ChainSubject, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("sink: read the subject index: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The evidence file first, as every reader: no reader may hold the index
	// while a writer holds the evidence file.
	st, err := s.openStore(true)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	subj, err := openSubjectsReadOnly(s.subjectsPath(), s.lockTimeout)
	if err != nil || subj == nil {
		return nil, err
	}
	defer subj.Close()
	var out []ChainSubject
	err = subj.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(reverseBucket).ForEach(func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if rowState(tx, k, v) != IndexLive {
				return nil
			}
			// Never name the subject of an erased chain, even when a restored
			// index re-links it (Verify reports that as relinked).
			erased, err := endsWithGenuineErasure(ctx, st, string(k))
			if err != nil || erased {
				return err
			}
			i := bytes.IndexByte(v, 0)
			out = append(out, ChainSubject{Chain: string(k), Class: string(v[:i]), Subject: string(v[i+1:])})
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("sink: read the subject index: %w", err)
	}
	return out, nil
}
