// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PcapReaders encapsule un PacketSource et une fonction de fermeture.
type PcapReaders struct {
	PSrc      *gopacket.PacketSource
	CloseFunc func() error
}

// OpenPcapPacketSource automatically detects PCAP vs PCAP-NG format and creates a PacketSource.
func OpenPcapPacketSource(path string, r io.Reader) (*PcapReaders, error) {
	// Read the magic number from a separate handle (CountingReader stays at offset 0)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("cannot read magic: %w", err)
	}

	const (
		mPCAPBE    = 0xa1b2c3d4
		mPCAPLE    = 0xd4c3b2a1
		mPCAPBE_NS = 0xa1b23c4d
		mPCAPLE_NS = 0x4d3cb2a1
		mPCAPNG    = 0x0a0d0d0a
	)
	mv := binary.BigEndian.Uint32(magic[:])

	switch mv {
	case mPCAPBE, mPCAPLE, mPCAPBE_NS, mPCAPLE_NS:
		rd, err := pcapgo.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("pcap reader: %w", err)
		}
		ps := gopacket.NewPacketSource(rd, rd.LinkType())
		return &PcapReaders{PSrc: ps, CloseFunc: func() error { return nil }}, nil
	case mPCAPNG:
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapng reader: %w", err)
		}
		ps := gopacket.NewPacketSource(ng, ng.LinkType())
		return &PcapReaders{PSrc: ps, CloseFunc: func() error { return nil }}, nil
	default:
		return nil, fmt.Errorf("unknown pcap magic %x", mv)
	}
}

