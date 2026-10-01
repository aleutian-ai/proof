// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"fmt"
	"testing"

	bolt "go.etcd.io/bbolt"

	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// Single-pair helpers the tests use to stage states (a bound pair with no
// chain; one chain's positions). Production binds and records positions for
// all pairs of a Commit at once (bindAll, putAll).

// resolveChain returns the chain of one (class, subject) pair, minting AND
// binding one when the pair is new.
func (s *Sink) resolveChain(ctx context.Context, st *boltstore.Store, subj *subjectsStore,
	class, subject string) (string, error) {
	chain, isNew, err := s.resolvePair(ctx, st, subj, class, subject, nil)
	if err != nil || !isNew {
		return chain, err
	}
	if err := subj.bind(subject, class, chain); err != nil {
		return "", err
	}
	return chain, nil
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

// putBatch records positions for one chain in one transaction.
func (s *sourcesStore) putBatch(chain string, positions map[string]position) error {
	return s.putAll(map[string]map[string]position{chain: positions})
}

// presignOne decides (unsigned) the erasure entry of one chain, as eraseSubject
// does before forgetting, for tests that call eraseChain directly. Nil when the
// chain gets no new entry.
func presignOne(t *testing.T, s *Sink, st *boltstore.Store, chain string) *presigned {
	t.Helper()
	pre, err := s.presignErasures(context.Background(), st, nil, []string{chain})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := pre[chain]; ok {
		return &p
	}
	return nil
}
