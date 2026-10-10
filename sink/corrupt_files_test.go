// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// damage is one way a store file stops being a database.
type damage struct {
	name  string
	apply func(t *testing.T, path string)
}

// damages are the two ways the review reached a crash: a file cut short, which
// faults in the memory map, and a file whose pages hold the wrong bytes, which
// trips an assertion (or an index out of range) inside bbolt.
var damages = []damage{
	{"truncated", func(t *testing.T, path string) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Keep the two meta pages, so the file still opens, and cut the rest.
		if err := os.Truncate(path, fi.Size()/2); err != nil {
			t.Fatal(err)
		}
	}},
	{"resized to 100000 bytes", func(t *testing.T, path string) {
		// Not a multiple of the page size, and not the size the meta page
		// records: the review's `truncate -s 100000`.
		if err := os.Truncate(path, 100000); err != nil {
			t.Fatal(err)
		}
	}},
	{"pages overwritten", func(t *testing.T, path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Everything after the two meta pages (bbolt's page size is the OS's).
		start := 2 * os.Getpagesize()
		if len(raw) <= start {
			t.Fatalf("%s is %d bytes: no pages after the meta pages", path, len(raw))
		}
		copy(raw[start:], bytes.Repeat([]byte{0xA5}, len(raw)-start))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}},
}

// TestCorruptFiles_AreAnErrorNotACrash: a damaged store file makes an
// operation that reads the folder return an error. It once ended the process (a memory fault, or a
// panic from bbolt), which killed any service embedding the sink and made the
// CLI exit with the status it uses for a usage error.
//
// The error is ErrCorrupt when the storage layer panicked, or an ordinary error
// when bbolt noticed the damage itself. Either is acceptable; a crash is not,
// and neither is a result that reads as a pass.
//
// The operations that write are not here: see ErrCorrupt.
func TestCorruptFiles_AreAnErrorNotACrash(t *testing.T) {
	files := map[string]func(s *Sink) string{
		"evidence": (*Sink).DBPath,
		"secrets":  (*Sink).secretsPath,
		"subjects": (*Sink).subjectsPath,
	}
	ops := map[string]func(ctx context.Context, s *Sink) error{
		"verify": func(ctx context.Context, s *Sink) error {
			rep, err := s.Verify(ctx, nil)
			if err == nil && rep.OK() {
				t.Error("a damaged folder verified")
			}
			return err
		},
		"export": func(ctx context.Context, s *Sink) error {
			_, err := s.Export(ctx, ExportSelection{All: true}, io.Discard)
			return err
		},
		"checkpoint": func(ctx context.Context, s *Sink) error {
			_, err := s.Checkpoint(ctx, nil, nil)
			return err
		},
		"chain subjects": func(ctx context.Context, s *Sink) error {
			_, err := s.ChainSubjects(ctx)
			return err
		},
	}
	for fileName, pathOf := range files {
		for _, d := range damages {
			for opName, op := range ops {
				t.Run(fileName+"/"+d.name+"/"+opName, func(t *testing.T) {
					s, _ := multi(t)
					d.apply(t, pathOf(s))
					// The assertion is that this returns at all.
					err := op(context.Background(), s)
					if errors.Is(err, ErrCorrupt) {
						t.Logf("ErrCorrupt: %v", err)
					}
				})
			}
		}
	}
}

// TestCorruptFiles_EvidenceDamageFailsVerify: whatever else a damaged evidence
// file does, Verify does not report the folder as verifying.
func TestCorruptFiles_EvidenceDamageFailsVerify(t *testing.T) {
	for _, d := range damages {
		t.Run(d.name, func(t *testing.T) {
			s, _ := multi(t)
			d.apply(t, s.DBPath())
			rep, err := s.Verify(context.Background(), nil)
			if err == nil && rep.OK() {
				t.Fatal("a folder with a damaged evidence file verified")
			}
		})
	}
}
