// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"crypto"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/proof/anchor"
)

var errCallersBug = errors.New("the caller's bug")

type panickingKeys struct{}

func (panickingKeys) PublicKey(string) ([]byte, anchor.Trust, error) { panic(errCallersBug) }

type panickingSigner struct{ anchor.ContextSigner }

func (panickingSigner) SignContext(context.Context, []byte) ([]byte, error) { panic(errCallersBug) }

type publicPanics struct{}

func (publicPanics) Public() crypto.PublicKey                            { panic(errCallersBug) }
func (publicPanics) SignContext(context.Context, []byte) ([]byte, error) { panic(errCallersBug) }

type panickingHeads struct{}

func (panickingHeads) Head(context.Context, string) (int, string, bool, error) { panic(errCallersBug) }
func (panickingHeads) SetHead(context.Context, string, int, string) error      { panic(errCallersBug) }

type panickingWriter struct{}

func (panickingWriter) Write([]byte) (int, error) { panic(errCallersBug) }

// TestCallersPanic_IsNotReportedAsADamagedFile: a signer, a key source, a heads
// store, a report function or a writer that panics is the caller's bug. Each
// was caught by the operation's guard and returned as ErrCorrupt, "a store
// file is damaged", on a healthy folder. The panic now comes back out of the
// operation as it was raised, and the folder is fine afterwards.
func TestCallersPanic_IsNotReportedAsADamagedFile(t *testing.T) {
	ctx := context.Background()
	s, signer, ring := setup(t)
	if _, err := s.Commit(ctx, events("u-81", 1)); err != nil { // something to checkpoint
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"Checkpoint: the signer signing": func() error {
			_, err := s.Checkpoint(ctx, panickingSigner{signer}, ring)
			return err
		},
		"Checkpoint: the signer's public key": func() error {
			_, err := s.Checkpoint(ctx, publicPanics{}, nil)
			return err
		},
		"Checkpoint: the trusted keys": func() error {
			_, err := s.Checkpoint(ctx, signer, panickingKeys{})
			return err
		},
		"Verify: the record keys": func() error {
			// Record keys are only asked about on a sink that signs.
			signing := openSigning(t, t.TempDir(), testRecordSigner(t, 7))
			if _, err := signing.Commit(ctx, events("u-1", 1)); err != nil {
				t.Fatal(err)
			}
			_, err := signing.Verify(ctx, ring, WithRecordTrust(panickingKeys{}))
			return err
		},
		"Checkpoint: the heads": func() error {
			_, err := s.Checkpoint(ctx, signer, nil, TrackHeads(panickingHeads{}))
			return err
		},
		"Verify: the keys": func() error {
			_, err := s.Verify(ctx, panickingKeys{})
			return err
		},
		"Verify: the heads": func() error {
			_, err := s.Verify(ctx, ring, WithCheckpointHeads(panickingHeads{}))
			return err
		},
		"VerifyEach: the report function": func() error {
			_, err := s.VerifyEach(ctx, ring, func(ChainReport) error { panic(errCallersBug) })
			return err
		},
		"Export: the writer": func() error {
			// Enough chains to fill the exporter's buffer is not needed: the
			// final flush writes.
			_, err := s.Export(ctx, ExportSelection{All: true}, panickingWriter{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			var recovered any
			var returned error
			func() {
				defer func() { recovered = recover() }()
				returned = call()
			}()
			if recovered != errCallersBug {
				t.Fatalf("recovered %v, returned %v; want the caller's own panic back", recovered, returned)
			}
		})
	}
	// The folder was never the problem.
	rep, err := s.Verify(ctx, ring)
	if err != nil || !rep.OK() {
		t.Fatalf("verify after the callers' panics: %+v, %v", rep, err)
	}
	if _, err := s.Export(ctx, ExportSelection{All: true}, io.Discard); err != nil {
		t.Fatalf("export afterwards: %v", err)
	}
	if _, err := s.Checkpoint(ctx, signer, nil, TrackHeads(FileHeads(filepath.Join(t.TempDir(), "h.json")))); err != nil {
		t.Fatalf("checkpoint afterwards: %v", err)
	}
}
