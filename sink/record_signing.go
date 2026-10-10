// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aleutian-ai/proof/internal/fault"
	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// signaturesWriter is what a call writes to the signatures file, as its
// smallest interface (a test passes one that fails).
type signaturesWriter interface {
	putAll(rows map[string]map[string]signatureRow) error
	deleteRows(ids map[string][]string) error
}

// recordSigning is one call's signing: the signer, its key (derived ONCE per
// call, so every record names the same key and a rotation between calls is
// picked up), the bound on parallel signatures, and the open signatures file.
// nil when the sink does not sign.
type recordSigning struct {
	signer RecordSigner
	key    recordKey
	n      int
	store  *signaturesStore
	writer signaturesWriter // store, or a test's wrapper of it
}

// openRecordSigning enforces the sink's signing mode and, when this Sink signs,
// opens the signatures file and derives the call's key. It runs with the
// evidence file open, before the call writes anything (docs/sink-format.md
// §9.2):
//
//	signing sink,  Sink without a signer      → ErrRecordSignerRequired
//	unsigned sink with entries, Sink signs    → ErrSinkNotSigning
//	no entries yet, Sink signs                → signs (the first put sets the mode)
//
// The returned close function is never nil.
func (s *Sink) openRecordSigning(ctx context.Context, st *boltstore.Store) (*recordSigning, func(), error) {
	noop := func() {}
	signing := false
	ro, err := openSignaturesReadOnly(s.signaturesPath(), s.lockTimeout)
	if err != nil {
		return nil, noop, err
	}
	if ro != nil {
		signing, err = ro.signing()
		ro.Close()
		if err != nil {
			return nil, noop, err
		}
	}
	if s.recordSigner == nil {
		if signing {
			return nil, noop, ErrRecordSignerRequired
		}
		return nil, noop, nil
	}
	if !signing {
		chains, err := st.Chains(ctx)
		if err != nil {
			return nil, noop, fmt.Errorf("sink: read the chains: %w", err)
		}
		if len(chains) > 0 {
			return nil, noop, ErrSinkNotSigning
		}
	}
	key, err := recordKeyOf(s.recordSigner)
	if err != nil {
		return nil, noop, err
	}
	sig, err := openSignatures(s.signaturesPath(), s.lockTimeout)
	if err != nil {
		return nil, noop, err
	}
	rs := &recordSigning{signer: s.recordSigner, key: key, n: s.signConcurrency, store: sig, writer: sig}
	if s.wrapSignatures != nil {
		rs.writer = s.wrapSignatures(sig)
	}
	var once sync.Once
	return rs, func() { once.Do(func() { sig.Close() }) }, nil
}

// signAll signs every record, at most n at a time, and returns the signatures
// in the order given. Each is verified under key before it is returned
// (signRecord), so nothing unverified ever reaches a write. The first failure
// cancels the rest, and signAll returns only after EVERY call it started has
// finished: no signer call outlives it (or the file lock its caller holds).
// Errors name the record's index in jobs, never a chain.
func signAll(ctx context.Context, s RecordSigner, key recordKey, n int, jobs []recordFields) ([][]byte, error) {
	if n < 1 {
		n = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigs := make([][]byte, len(jobs))
	sem := make(chan struct{}, n)
	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
loop:
	for i := range jobs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			sig, err := signRecord(ctx, s, key, jobs[i])
			if err != nil {
				once.Do(func() {
					firstErr = fmt.Errorf("record %d: %w", i, err)
					cancel()
				})
				return
			}
			sigs[i] = sig
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	for _, sig := range sigs {
		if sig == nil {
			// Only a cancelled caller context leaves a record unsigned.
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("sink: sign records: %w", err)
			}
			return nil, errors.New("sink: sign records: a record was left unsigned")
		}
	}
	return sigs, nil
}

// UsesRecordKey reports whether this sink has signed records with the key
// whose id is keyID: every record key it has ever used counts, so the answer
// holds through key rotation.
//
// # Description
//
// For the warning a checkpoint writer prints when its key is also a record key
// (docs/AleutianChain/record_signing_design.md R7). Separate keys are
// recommended, never enforced: the record key is online in the writer, the
// checkpoint key can be kept elsewhere, and a leaked record key should not
// also unpin what the checkpoints pinned. The library only reports the fact.
//
// # Inputs
//
//   - ctx: checked before reading
//   - keyID: 32 lowercase hex (keyfile.KeyIDHex)
//
// # Outputs
//
//   - bool: true when keyID has signed records of this sink
//   - error: an invalid key id, or the signatures file could not be read. A
//     sink without one (it never signed) is false, nil.
//
// # Example
//
//	if used, _ := s.UsesRecordKey(ctx, checkpointKeyID); used {
//	    log.Print("warning: the checkpoint key is also a record key")
//	}
//
// # Limitations
//
//   - Reads the folder's record of keys, which anyone with write access can
//     edit: a convenience for honest operators, not a control.
//
// # Assumptions
//
//   - None.
func (s *Sink) UsesRecordKey(ctx context.Context, keyID string) (_ bool, err error) {
	defer fault.Recover(&err)()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !lowerHex32.MatchString(keyID) {
		return false, errors.New("sink: not a key id (32 lowercase hex)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, err := openSignaturesReadOnly(s.signaturesPath(), s.lockTimeout)
	if err != nil || sig == nil {
		return false, err
	}
	defer sig.Close()
	return sig.hasRecordKey(keyID)
}
