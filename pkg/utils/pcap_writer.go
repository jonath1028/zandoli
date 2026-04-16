// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PCAPWriter defines methods for writing a packet to a .pcap file
type PCAPWriter interface {
	WritePacket(pkt gopacket.Packet) error
	Close() error
}

// pcapWriterImpl implements PCAPWriter with pcapgo.Writer
type pcapWriterImpl struct {
	file   *os.File
	writer *pcapgo.Writer
}

// NewPCAPWriter creates a writer ready to write to a PCAP file.
func NewPCAPWriter(path string, snaplen int) (PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &pcapWriterImpl{
		file:   f,
		writer: writer,
	}, nil
}

// WritePacket writes a captured packet with its timestamp
func (p *pcapWriterImpl) WritePacket(pkt gopacket.Packet) error {
	data := pkt.Data()
	ci := pkt.Metadata().CaptureInfo

	// Ensure CaptureLength and Length are consistent with data size
	if len(data) > 0 {
		// If CaptureLength is 0 or inconsistent, fix it
		if ci.CaptureLength == 0 || ci.CaptureLength != len(data) {
			ci.CaptureLength = len(data)
		}
		// Ensure Length is at least equal to CaptureLength
		if ci.Length < ci.CaptureLength {
			ci.Length = ci.CaptureLength
		}
	}

	return p.writer.WritePacket(ci, data)
}

// Close ferme le fichier .pcap
func (p *pcapWriterImpl) Close() error {
	return p.file.Close()
}
