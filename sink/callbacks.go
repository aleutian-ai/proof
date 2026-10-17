// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/internal/fault"
)

// The operations that read the folder run under fault.Recover, which reports a
// panic as a damaged file. What the CALLER handed in runs inside that region
// too: a signer, key sources, a heads store, a report function, a writer. A
// panic in one of those is the caller's bug, not damage. Each is therefore
// called through one of these wrappers (fault.Callback), so its panic comes
// back out of the operation as the caller's own panic, unchanged, and is never
// reported as ErrCorrupt.

// callerKeys is a caller's KeySource.
type callerKeys struct{ src anchor.KeySource }

func (k callerKeys) PublicKey(keyID string) (pub []byte, trust anchor.Trust, err error) {
	fault.Callback(func() { pub, trust, err = k.src.PublicKey(keyID) })
	return pub, trust, err
}

// callerSigner is a caller's checkpoint signer.
type callerSigner struct{ s anchor.ContextSigner }

func (c callerSigner) Public() (pub crypto.PublicKey) {
	fault.Callback(func() { pub = c.s.Public() })
	return pub
}

func (c callerSigner) SignContext(ctx context.Context, msg []byte) (sig []byte, err error) {
	fault.Callback(func() { sig, err = c.s.SignContext(ctx, msg) })
	return sig, err
}

// SignWithContext forwards to a caller's signer that can sign with an ML-DSA
// context string, as a v7 checkpoint is signed. One that cannot is refused here
// with the error anchor.SignCanonical gives, rather than this wrapper hiding
// the difference by signing with the empty context.
func (c callerSigner) SignWithContext(ctx context.Context, msg []byte, mldsaContext string) (sig []byte, err error) {
	cs, ok := c.s.(anchor.ContextStringSigner)
	if !ok {
		return nil, fmt.Errorf("the checkpoint signer (%T) cannot sign with the ML-DSA context %q; "+
			"it must implement anchor.ContextStringSigner", c.s, mldsaContext)
	}
	fault.Callback(func() { sig, err = cs.SignWithContext(ctx, msg, mldsaContext) })
	return sig, err
}

// callerHeads is a caller's CheckpointHeads. It always offers the batch write,
// passing it on when the caller's store has one.
type callerHeads struct{ h CheckpointHeads }

func (c callerHeads) Head(ctx context.Context, chain string) (count int, hash string, ok bool, err error) {
	fault.Callback(func() { count, hash, ok, err = c.h.Head(ctx, chain) })
	return count, hash, ok, err
}

func (c callerHeads) SetHead(ctx context.Context, chain string, count int, hash string) (err error) {
	fault.Callback(func() { err = c.h.SetHead(ctx, chain, count, hash) })
	return err
}

func (c callerHeads) setHeads(ctx context.Context, heads []chainHead) (err error) {
	fault.Callback(func() {
		if b, ok := c.h.(headsBatch); ok {
			err = b.setHeads(ctx, heads)
			return
		}
		for _, h := range heads {
			if err = c.h.SetHead(ctx, h.chain, h.count, h.hash); err != nil {
				return
			}
		}
	})
	return err
}

// callerWriter is a caller's io.Writer.
type callerWriter struct{ w io.Writer }

func (c callerWriter) Write(p []byte) (n int, err error) {
	fault.Callback(func() { n, err = c.w.Write(p) })
	return n, err
}
