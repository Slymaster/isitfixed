package httpx

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// BlockSize is the granularity of ranged reads and of their cache entries.
const BlockSize = 1 << 20

// RangedFile is an io.ReaderAt over a remote immutable file, fetched in
// cached blocks with HTTP Range requests. It lets isitfixed read a zip's
// central directory and a handful of entries without downloading a whole
// (possibly 50 MB) module zip. Servers that ignore Range get one full
// download.
type RangedFile struct {
	c    *Client
	ctx  context.Context
	url  string
	size int64

	mu     sync.Mutex
	blocks map[int64][]byte
	full   []byte
}

// OpenRanged opens a remote immutable file for random access.
func (c *Client) OpenRanged(ctx context.Context, u string) (*RangedFile, error) {
	f := &RangedFile{c: c, ctx: ctx, url: u, blocks: map[int64][]byte{}}
	if resp, ok := c.readCache(Request{URL: u + "#size", Immutable: true}); ok && resp.Status == 200 {
		if n, err := strconv.ParseInt(string(resp.Body), 10, 64); err == nil {
			f.size = n
			return f, nil
		}
	}
	if resp, ok := c.readCache(Request{URL: u + "#size", Immutable: true}); ok && resp.Status == 404 {
		return nil, ErrNotFound
	}
	b, total, err := f.fetch(0, true)
	if err != nil {
		if err == ErrNotFound {
			c.writeCache(Request{URL: u + "#size"}, &Response{Status: 404})
		}
		return nil, err
	}
	f.size = total
	if f.full == nil {
		f.blocks[0] = b
	}
	c.writeCache(Request{URL: u + "#size", Immutable: true}, &Response{Status: 200, Body: []byte(strconv.FormatInt(total, 10))})
	return f, nil
}

// Size returns the remote file size.
func (f *RangedFile) Size() int64 { return f.size }

// URL returns the remote URL.
func (f *RangedFile) URL() string { return f.url }

func (f *RangedFile) blockKey(i int64) Request {
	return Request{URL: fmt.Sprintf("%s#block%d", f.url, i), Immutable: true}
}

// fetch downloads block i, returning it and the total file size.
func (f *RangedFile) fetch(i int64, skipCache bool) ([]byte, int64, error) {
	if r, ok := f.c.readCache(f.blockKey(i)); !skipCache && ok && r.Status == 200 {
		return r.Body, f.size, nil
	}
	start := i * BlockSize
	end := start + BlockSize - 1
	if f.size > 0 && end >= f.size {
		end = f.size - 1
	}
	resp, err := f.c.do(f.ctx, "GET", f.url, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", start, end)})
	if err != nil {
		return nil, 0, err
	}
	switch resp.Status {
	case 206:
		total := f.size
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if j := strings.LastIndexByte(cr, '/'); j >= 0 {
				if n, err := strconv.ParseInt(cr[j+1:], 10, 64); err == nil {
					total = n
				}
			}
		}
		f.c.writeCache(f.blockKey(i), &Response{Status: 200, Body: resp.Body})
		return resp.Body, total, nil
	case 200:
		// Range ignored: keep the whole body and split it into cached blocks.
		f.mu.Lock()
		f.full = resp.Body
		f.mu.Unlock()
		for j := int64(0); j*BlockSize < int64(len(resp.Body)); j++ {
			e := min((j+1)*BlockSize, int64(len(resp.Body)))
			f.c.writeCache(f.blockKey(j), &Response{Status: 200, Body: resp.Body[j*BlockSize : e]})
		}
		e := min(int64(BlockSize), int64(len(resp.Body)))
		return resp.Body[:e], int64(len(resp.Body)), nil
	case 404, 410:
		return nil, 0, ErrNotFound
	default:
		return nil, 0, &StatusError{URL: f.url, Status: resp.Status}
	}
}

func (f *RangedFile) block(i int64) ([]byte, error) {
	f.mu.Lock()
	if f.full != nil {
		s := i * BlockSize
		e := min(s+BlockSize, int64(len(f.full)))
		f.mu.Unlock()
		if s >= e {
			return nil, io.EOF
		}
		return f.full[s:e], nil
	}
	if b, ok := f.blocks[i]; ok {
		f.mu.Unlock()
		return b, nil
	}
	f.mu.Unlock()
	b, _, err := f.fetch(i, false)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if len(f.blocks) > 64 {
		f.blocks = map[int64][]byte{}
	}
	f.blocks[i] = b
	f.mu.Unlock()
	return b, nil
}

// ReadAt implements io.ReaderAt.
func (f *RangedFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= f.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < f.size {
		bi := off / BlockSize
		b, err := f.block(bi)
		if err != nil {
			return n, err
		}
		inner := off - bi*BlockSize
		if inner >= int64(len(b)) {
			return n, io.ErrUnexpectedEOF
		}
		c := copy(p[n:], b[inner:])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
