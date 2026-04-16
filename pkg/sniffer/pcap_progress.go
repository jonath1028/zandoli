// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"bufio"
	"io"
	"os"
	"sync/atomic"
)

// CountingReader est un wrapper autour d'un io.Reader qui compte les octets lus.
type CountingReader struct {
	r io.Reader
	n int64
}

// NewCountingReader creates a new CountingReader.
func NewCountingReader(r io.Reader) *CountingReader {
	return &CountingReader{r: r}
}

// Read reads data and updates the counter atomically.
func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	atomic.AddInt64(&c.n, int64(n))
	return n, err
}

// N returns the number of bytes read in a thread-safe manner.
func (c *CountingReader) N() int64 {
	return atomic.LoadInt64(&c.n)
}

// WrapFile retourne un CountingReader buffered et la taille du fichier.
func WrapFile(path string) (cr *CountingReader, size int64, f *os.File, err error) {
	f, err = os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, nil, err
	}
	cr = NewCountingReader(bufio.NewReader(f))
	return cr, st.Size(), f, nil
}

