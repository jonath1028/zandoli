//go:build !windows
// +build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
)

// mmapFile maps the file at path into memory using mmap for fast sequential reads.
// Returns the mapped byte slice, the file size, and a cleanup function.
// On error, returns nil and the error.
func mmapFile(path string) ([]byte, int64, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("mmap: open: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, nil, fmt.Errorf("mmap: stat: %w", err)
	}

	size := fi.Size()
	if size == 0 {
		f.Close()
		return nil, 0, func() error { return nil }, nil
	}

	data, err := syscall.Mmap(
		int(f.Fd()),
		0,
		int(size),
		syscall.PROT_READ,
		syscall.MAP_PRIVATE,
	)
	if err != nil {
		f.Close()
		return nil, 0, nil, fmt.Errorf("mmap: mmap: %w", err)
	}

	cleanup := func() error {
		if err := syscall.Munmap(data); err != nil {
			return fmt.Errorf("mmap: munmap: %w", err)
		}
		return f.Close()
	}

	return data, size, cleanup, nil
}

// newMmapReader creates a bytes.Reader from an mmap'd file.
func newMmapReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

// mmapSupported returns true if mmap is supported on this platform.
func mmapSupported() bool {
	return true
}
