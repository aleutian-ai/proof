// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"errors"
	"time"

	boltstore "github.com/aleutian-ai/proof/store/bolt"
)

// Verify and Checkpoint read the folder a PAGE at a time: they open the files
// (the evidence file under a shared lock), do a bounded amount of work, and
// close them, so a writer waits at most about one page, never the whole run
// (docs/AleutianChain/verify_paging_design.md). A chain is never split across
// pages: everything about one chain is read under one lock hold.

// Page bounds. Variables only so tests can shrink them.
var (
	// pageBudget ends a page once this much time has passed (after at least
	// one chain).
	pageBudget = 50 * time.Millisecond
	// pageMaxChains ends a page after this many chains.
	pageMaxChains = 4096
	// pageMaxKeys bounds one CHUNK of a key scan (the cross-chain sweep): a
	// page runs chunk after chunk until its time is up, so this bounds how far
	// a page can overrun pageBudget, not how much a page does.
	pageMaxKeys = 1024
	// pageGap is the pause between pages, with nothing held. It must exceed
	// bbolt's lock retry interval (50 ms): bbolt never blocks on the file lock,
	// it retries every 50 ms, so a writer waiting for the evidence file only
	// gets in during a gap at least that long.
	pageGap = 60 * time.Millisecond
	// betweenPages runs after a page released everything: a test hook (a
	// writer commits there). nil outside tests.
	betweenPages func()
)

// pageFiles are the files one page reads: all read-only. ix, sec and sig
// are nil when their file is absent; sigErr is set (and sig possibly nil)
// when the signatures file is not one this sink writes.
type pageFiles struct {
	f       *folder
	st      *boltstore.Store
	sec     *secretsStore
	sig     *signaturesStore
	subj    *subjectsStore
	ix      *indexSnapshot
	signing bool
	sigErr  error
}

// openPage opens what a page reads. With all false, only the folder and the
// evidence file (Checkpoint's needs).
func (s *Sink) openPage(all bool) (*pageFiles, error) {
	p := &pageFiles{}
	var err error
	if p.f, err = s.openFolder(false); err != nil {
		return nil, err
	}
	if p.st, err = s.openStore(true); err != nil {
		p.close()
		return nil, err
	}
	if !all {
		return p, nil
	}
	if p.sec, err = openSecretsReadOnly(s.secretsPath(), s.lockTimeout); err != nil {
		p.close()
		return nil, err
	}
	p.sig, err = openSignaturesReadOnly(s.signaturesPath(), s.lockTimeout)
	switch {
	case errors.Is(err, errNotSignaturesFile):
		p.sig, p.sigErr = nil, err
	case err != nil:
		p.close()
		return nil, err
	}
	if p.sig != nil {
		p.signing, err = p.sig.signing()
		switch {
		case errors.Is(err, errNotSignaturesFile):
			p.signing, p.sigErr = true, err
		case err != nil:
			p.close()
			return nil, err
		}
	}
	if p.subj, err = openSubjectsReadOnly(s.subjectsPath(), s.lockTimeout); err != nil {
		p.close()
		return nil, err
	}
	if p.subj != nil {
		if p.ix, err = p.subj.snapshot(); err != nil {
			p.close()
			return nil, err
		}
	}
	return p, nil
}

func (p *pageFiles) close() {
	p.ix.close()
	if p.subj != nil {
		p.subj.Close()
	}
	if p.sig != nil {
		p.sig.Close()
	}
	if p.sec != nil {
		p.sec.Close()
	}
	if p.st != nil {
		p.st.Close()
	}
	if p.f != nil {
		p.f.Close()
	}
}

// inPages runs step a page at a time, until it reports done: each call with
// the files open and Sink.mu held, released between calls. step gets the
// time its page should end by and must stop then (after at least one unit of
// work). flush runs after each page, with nothing held: the place to hand
// results to a caller.
func (s *Sink) inPages(ctx context.Context, all bool,
	step func(p *pageFiles, deadline time.Time) (done bool, err error), flush func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := func() (bool, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			p, err := s.openPage(all)
			if err != nil {
				return false, err
			}
			defer p.close()
			return step(p, time.Now().Add(pageBudget))
		}()
		if err != nil {
			return err
		}
		if flush != nil {
			if err := flush(); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
		if betweenPages != nil {
			betweenPages()
		}
		if pageGap > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pageGap):
			}
		}
	}
}
