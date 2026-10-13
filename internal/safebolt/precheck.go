// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package safebolt

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
)

// bbolt's file layout, as far as the check before opening needs it. The format
// has not changed since bbolt's first release (version 2).
const (
	boltMagic   = 0xED0CDAED
	boltVersion = 2

	pageHeaderSize = 16 // id u64, flags u16, count u16, overflow u32
	metaSize       = 64 // magic .. checksum, after the page header
	// Offsets inside a page.
	offFlags    = 8
	offCount    = 10
	offOverflow = 12
	offMagic    = pageHeaderSize
	offVersion  = pageHeaderSize + 4
	offPageSize = pageHeaderSize + 8
	offRoot     = pageHeaderSize + 16
	offFreelist = pageHeaderSize + 32
	offHighPgid = pageHeaderSize + 40
	offTxid     = pageHeaderSize + 48
	offChecksum = pageHeaderSize + 56

	freelistPageFlag = 0x10
	// noFreelist is the freelist page id of a file written without one.
	noFreelist = ^uint64(0)
	// bigCount in a freelist page's count means the real count is the page's
	// first 8-byte value.
	bigCount = 0xFFFF

	minPageSize = 1 << 10
	maxPageSize = 1 << 16
)

// boltMeta is the fields of a meta page the check reads.
type boltMeta struct {
	pageSize uint64
	root     uint64
	freelist uint64
	highPgid uint64 // one past the last page in use
	txid     uint64
}

// readMeta reads the meta page at off, and reports whether it is one bbolt
// would accept: its magic, version and checksum.
func readMeta(f *os.File, off int64) (boltMeta, bool) {
	var buf [pageHeaderSize + metaSize]byte
	if _, err := f.ReadAt(buf[:], off); err != nil {
		return boltMeta{}, false
	}
	if binary.LittleEndian.Uint32(buf[offMagic:]) != boltMagic ||
		binary.LittleEndian.Uint32(buf[offVersion:]) != boltVersion {
		return boltMeta{}, false
	}
	h := fnv.New64a()
	_, _ = h.Write(buf[offMagic:offChecksum])
	if h.Sum64() != binary.LittleEndian.Uint64(buf[offChecksum:]) {
		return boltMeta{}, false
	}
	return boltMeta{
		pageSize: uint64(binary.LittleEndian.Uint32(buf[offPageSize:])),
		root:     binary.LittleEndian.Uint64(buf[offRoot:]),
		freelist: binary.LittleEndian.Uint64(buf[offFreelist:]),
		highPgid: binary.LittleEndian.Uint64(buf[offHighPgid:]),
		txid:     binary.LittleEndian.Uint64(buf[offTxid:]),
	}, true
}

// precheck reads a bbolt file's meta pages and freelist page header directly,
// before bbolt is given the file, and refuses values that cannot fit the file.
//
// bbolt believes them. A freelist page that claims 2^46 entries makes it
// allocate that many: the process dies of memory exhaustion, which is not a
// panic and cannot be recovered. A page size, a page id or a count is checked
// here against the one thing that cannot be forged, the file's length:
//
//   - the page size is a power of two between 1 KiB and 64 KiB;
//   - the pages in use end within the file;
//   - the root and freelist pages are among them;
//   - the freelist page says it is one, its entries fit in the pages it spans,
//     and those pages are in use too. Its count is therefore below the file's
//     length in bytes divided by 8.
//
// The meta page checked is the one bbolt will use: of those whose magic,
// version and checksum hold, the one with the higher transaction id. A file
// with no such page is left to bbolt, which refuses it with an error. An empty
// file is new, and is not checked.
func precheck(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := uint64(fi.Size())
	if size == 0 {
		return nil
	}
	corrupt := func(format string, args ...any) error {
		return fmt.Errorf("%w (%s)", ErrCorrupt, fmt.Sprintf(format, args...))
	}
	// Meta 0 is at the start. Meta 1 is one page in, and the page size is
	// written in the meta pages themselves: as bbolt does, find meta 1 by
	// trying each size when meta 0 does not hold.
	var metas []boltMeta
	if m, ok := readMeta(f, 0); ok {
		metas = append(metas, m)
		if m.pageSize >= minPageSize && m.pageSize <= maxPageSize {
			if m1, ok := readMeta(f, int64(m.pageSize)); ok {
				metas = append(metas, m1)
			}
		}
	} else {
		for ps := uint64(minPageSize); ps <= maxPageSize; ps <<= 1 {
			if m1, ok := readMeta(f, int64(ps)); ok && m1.pageSize == ps {
				metas = append(metas, m1)
				break
			}
		}
	}
	if len(metas) == 0 {
		return nil // not a database bbolt will open: it says so itself
	}
	m := metas[0]
	for _, other := range metas[1:] {
		if other.txid > m.txid {
			m = other
		}
	}
	ps := m.pageSize
	if ps < minPageSize || ps > maxPageSize || ps&(ps-1) != 0 {
		return corrupt("a page size of %d bytes", ps)
	}
	pages := size / ps
	if m.highPgid < 2 || m.highPgid > pages {
		return corrupt("the file is %d bytes, and its database records %d pages of %d bytes", size, m.highPgid, ps)
	}
	if m.root >= m.highPgid {
		return corrupt("a root page beyond the pages in use")
	}
	if m.freelist == noFreelist {
		return nil
	}
	if m.freelist < 2 || m.freelist >= m.highPgid {
		return corrupt("a freelist page beyond the pages in use")
	}
	var head [pageHeaderSize + 8]byte
	if _, err := f.ReadAt(head[:], int64(m.freelist*ps)); err != nil && err != io.EOF {
		return corrupt("the freelist page cannot be read: %v", err)
	}
	if binary.LittleEndian.Uint16(head[offFlags:])&freelistPageFlag == 0 {
		return corrupt("the freelist page is not a freelist page")
	}
	count := uint64(binary.LittleEndian.Uint16(head[offCount:]))
	overflow := uint64(binary.LittleEndian.Uint32(head[offOverflow:]))
	used := uint64(pageHeaderSize) // bytes of the page before its entries
	if count == bigCount {
		count = binary.LittleEndian.Uint64(head[pageHeaderSize:])
		used += 8
	}
	if m.freelist+overflow >= m.highPgid {
		return corrupt("a freelist that runs beyond the pages in use")
	}
	if room := ((overflow+1)*ps - used) / 8; count > room {
		return corrupt("a freelist of %d entries in pages that hold %d", count, room)
	}
	return nil
}
