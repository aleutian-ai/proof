// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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
// The operations that write are in TestCorruptFiles_WritesReturn.
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
			_, err := s.Checkpoint(ctx, nil, nil, UntrackedHeads())
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

// damagedFolder is a signing sink with every one of its five files in use,
// built once and copied for each case: u-1 in two classes and u-2 in one, all
// with sources; u-3 forgotten but not yet erased (a pending erasure, so every
// erase call and resume has work to do); and one content row no entry accounts
// for (so repair has work to do).
var damagedFolder struct {
	once sync.Once
	dir  string
	err  error
}

func damagedFolderTemplate(t *testing.T) string {
	t.Helper()
	damagedFolder.once.Do(func() {
		damagedFolder.err = func() error {
			dir, err := os.MkdirTemp("", "sink-damaged-template-")
			if err != nil {
				return err
			}
			damagedFolder.dir = dir
			rs, err := NewMLDSA65RecordSigner(bytes.Repeat([]byte{9}, 32))
			if err != nil {
				return err
			}
			defer rs.Close()
			s, err := Open(dir, WithRecordSigner(rs))
			if err != nil {
				return err
			}
			recs := []Record{
				{Class: "payments", Subject: "u-1", Content: []byte(`{"amount":42}`), Source: "Q:1"},
				{Class: "auth", Subject: "u-1", Content: []byte(`{"login":true}`), Source: "Q:2"},
				{Class: "payments", Subject: "u-2", Content: []byte(`{"amount":7}`), Source: "Q:3"},
				{Class: "payments", Subject: "u-3", Content: []byte(`{"amount":9}`), Source: "Q:4"},
			}
			// Enough rows that every file has pages after its meta pages and
			// freelist: a file of three pages has nothing for damage to hit.
			for i := 0; i < 60; i++ {
				recs = append(recs, Record{Class: "payments", Subject: "u-2",
					Content: bytes.Repeat([]byte{'x'}, 900), Source: "Q:bulk-" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
			}
			if _, err := s.Commit(context.Background(), recs); err != nil {
				return err
			}
			subj, err := openSubjects(s.subjectsPath(), DefaultLockTimeout)
			if err != nil {
				return err
			}
			chains, err := subj.forget("u-3", "")
			subj.Close()
			if err != nil {
				return err
			}
			// A leftover of a commit that never appended, on the pending chain's
			// neighbour: a content row under an id no entry has.
			_ = chains
			sec, err := openSecrets(s.secretsPath(), DefaultLockTimeout)
			if err != nil {
				return err
			}
			defer sec.Close()
			st, err := s.openStore(true)
			if err != nil {
				return err
			}
			defer st.Close()
			all, err := st.Chains(context.Background())
			if err != nil {
				return err
			}
			return sec.putAll(map[string]map[string]secret{all[0]: {"sink-" + string(bytes.Repeat([]byte{'c'}, 32)): {
				content: []byte("left over"), nonce: bytes.Repeat([]byte{1}, 32)}}})
		}()
	})
	if damagedFolder.err != nil {
		t.Fatal(damagedFolder.err)
	}
	return damagedFolder.dir
}

// copyFolder copies the template's files into a fresh folder.
func copyFolder(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

func TestMain(m *testing.M) {
	code := m.Run()
	if damagedFolder.dir != "" {
		os.RemoveAll(damagedFolder.dir)
	}
	os.Exit(code)
}

// returns runs op and fails the test if it has not returned in time: a hang
// is the failure this guards, and waiting for the suite's own timeout would
// hide which case it was.
func returns(t *testing.T, what string, op func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not return: it hangs on a damaged file", what)
		return nil
	}
}

// TestCorruptFiles_WritesReturn: the operations that write (commit, the three
// erase calls, repair) return an error on a damaged file, whichever file it is
// and however it is damaged. They once panicked, and recovering the panic where
// the operation ends hung instead: bbolt's Close waited on the writer lock the
// failed transaction still held.
//
// Each case runs twice. With the check a Sink makes before it first writes, a
// truncated or overwritten file is refused with ErrCorrupt before anything is
// written. Without it (WithoutIntegrityCheck) the damage is met inside the
// operation, by whichever read or write reaches it, and that must return too.
// Either way the operation is run a second time on the same Sink: a handle
// abandoned by the first must not leave its file locked, so the second returns
// promptly, and not as "busy".
func TestCorruptFiles_WritesReturn(t *testing.T) {
	template := damagedFolderTemplate(t)
	files := map[string]string{
		"evidence":   "",
		"secrets":    ".secrets",
		"sources":    ".sources",
		"subjects":   ".subjects",
		"signatures": ".signatures",
	}
	ops := map[string]func(ctx context.Context, s *Sink) error{
		"commit": func(ctx context.Context, s *Sink) error {
			_, err := s.Commit(ctx, []Record{
				{Class: "payments", Subject: "u-1", Content: []byte(`{"amount":1}`), Source: "Q:10"},
				{Class: "auth", Subject: "u-9", Content: []byte(`{"login":false}`), Source: "Q:11"},
			})
			return err
		},
		"erase subject": func(ctx context.Context, s *Sink) error {
			_, err := s.EraseSubject(ctx, "u-1")
			return err
		},
		"erase class": func(ctx context.Context, s *Sink) error {
			_, err := s.EraseSubjectClass(ctx, "u-1", "payments")
			return err
		},
		"resume": func(ctx context.Context, s *Sink) error {
			_, err := s.ResumeErasures(ctx)
			return err
		},
		"repair": func(ctx context.Context, s *Sink) error {
			_, err := s.Repair(ctx)
			return err
		},
	}
	for fileName, suffix := range files {
		for _, d := range damages {
			for opName, op := range ops {
				for _, checked := range []bool{true, false} {
					name := fileName + "/" + d.name + "/" + opName + "/check on"
					if !checked {
						name = fileName + "/" + d.name + "/" + opName + "/check off"
					}
					t.Run(name, func(t *testing.T) {
						t.Parallel() // each case has its own folder; an erase is a second of fsyncs
						dir := copyFolder(t, template)
						d.apply(t, filepath.Join(dir, dbName+suffix))
						rs := testRecordSigner(t, 9)
						opts := []Option{WithRecordSigner(rs), WithLockTimeout(2 * time.Second)}
						if !checked {
							opts = append(opts, WithoutIntegrityCheck())
						}
						s, err := Open(dir, opts...)
						if err != nil {
							t.Fatal(err)
						}
						ctx := context.Background()
						err = returns(t, opName, func() error { return op(ctx, s) })
						if errors.Is(err, ErrCorrupt) {
							t.Logf("ErrCorrupt: %.200v", err)
						}
						// A file that is cut short or overwritten is always caught by
						// the check, before the operation starts. (Resizing a small
						// file to 100000 bytes can leave it intact.)
						if checked && d.name != "resized to 100000 bytes" && !errors.Is(err, ErrCorrupt) {
							t.Errorf("with the check on, err = %v; want ErrCorrupt", err)
						}
						// Again, on the same Sink: nothing the first call abandoned
						// may still hold a file.
						start := time.Now()
						err = returns(t, opName+" (again)", func() error { return op(ctx, s) })
						if errors.Is(err, ErrBusy) {
							t.Errorf("the second call found the folder busy: a file was left locked (%v)", err)
						}
						if took := time.Since(start); took > 10*time.Second {
							t.Errorf("the second call took %v", took)
						}
					})
				}
			}
		}
	}
}

// TestCorruptFiles_CheckRefusesBeforeWriting: with the check on, a commit to a
// folder with a damaged file changes nothing at all: no file of the folder is
// written.
func TestCorruptFiles_CheckRefusesBeforeWriting(t *testing.T) {
	template := damagedFolderTemplate(t)
	dir := copyFolder(t, template)
	damages[2].apply(t, filepath.Join(dir, dbName+".secrets")) // pages overwritten
	before := map[string][]byte{}
	for _, suffix := range []string{"", ".secrets", ".sources", ".subjects", ".signatures"} {
		raw, err := os.ReadFile(filepath.Join(dir, dbName+suffix))
		if err != nil {
			t.Fatal(err)
		}
		before[suffix] = raw
	}
	s, err := Open(dir, WithRecordSigner(testRecordSigner(t, 9)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Commit(context.Background(), []Record{{Class: "auth", Subject: "u-9", Content: []byte("x")}})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v; want ErrCorrupt", err)
	}
	for suffix, raw := range before {
		now, err := os.ReadFile(filepath.Join(dir, dbName+suffix))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, now) {
			t.Errorf("evidence.db%s was written although the commit was refused", suffix)
		}
	}
}
