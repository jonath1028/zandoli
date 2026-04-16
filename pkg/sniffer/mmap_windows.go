//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import "bytes"

// mmapFile is a no-op on Windows — falls back to normal bufio.Reader in the sniffer.
func mmapFile(_ string) ([]byte, int64, func() error, error) {
	return nil, 0, nil, nil
}

// newMmapReader creates a bytes.Reader (unused on Windows).
func newMmapReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

// mmapSupported returns false on Windows — the sniffer will use the bufio fallback.
func mmapSupported() bool {
	return false
}
