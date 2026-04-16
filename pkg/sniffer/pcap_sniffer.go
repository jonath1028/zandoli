// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"context"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/ui"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// PcapSniffer reads an offline .pcap file and sends events to a channel.
type PcapSniffer struct {
	path       string
	packetChan chan model.PacketEvent
	log        *logger.Logger
	showUI     bool

	totalBytes int64
	bytesRead  func() int64
}

// NewPcapSniffer creates a new offline sniffer for PCAP files.
func NewPcapSniffer(path string, packetChan chan model.PacketEvent, log *logger.Logger, showUI bool) *PcapSniffer {
	return &PcapSniffer{
		path:       path,
		packetChan: packetChan,
		log:        log,
		showUI:     showUI,
	}
}

// Start lit le fichier .pcap ou .pcapng et injecte les paquets dans le channel.
// The channel is closed at the end to signal to the analyzer that reading is complete.
func (ps *PcapSniffer) Start(ctx context.Context) error {
	cr, size, f, err := WrapFile(ps.path)
	if err != nil {
		ps.log.Error().Err(err).Str("pcap", ps.path).Msg("Failed to open pcap file")
		return err
	}
	defer f.Close()
	ps.totalBytes = size
	ps.bytesRead = cr.N

	// Fast path for empty files
	if size == 0 {
		ps.log.Info().Str("pcap", ps.path).Msg("Empty PCAP file, nothing to read")
		// do NOT create a progress bar
		close(ps.packetChan)
		return nil
	}

	readers, err := OpenPcapPacketSource(ps.path, cr)
	if err != nil {
		ps.log.Error().Err(err).Str("pcap", ps.path).Msg("Failed to create packet source")
		return err
	}

	var progress func(int)
	var ticker *time.Ticker
	if ps.showUI && ps.totalBytes > 0 {
		progress = ui.PrintProgressBar("PCAP", 100, "count", "?", 100*time.Millisecond)
		ticker = time.NewTicker(200 * time.Millisecond)
		go func() {
			for range ticker.C {
				br := ps.bytesRead()
				pct := int((br * 100) / ps.totalBytes)
				if pct < 0 {
					pct = 0
				}
				if pct > 100 {
					pct = 100
				}
				progress(pct)
			}
		}()
	}

	ps.log.Info().Str("pcap", ps.path).Int64("size_bytes", size).Msg("PCAP reading started")

	src := readers.PSrc
	src.NoCopy = true

Loop:
	for {
		select {
		case <-ctx.Done():
			ps.log.Info().Msg("PCAP reading canceled")
			break Loop
		case pkt := <-src.Packets():
			if pkt == nil { // EOF
				break Loop
			}

			ethLayer := pkt.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)

			// Extract TTL from IPv4 layer
			var ttl uint8 = 0
			if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ipv4 := ipLayer.(*layers.IPv4)
				ttl = ipv4.TTL
			}

			// Extract VLAN ID from 802.1Q tag
			var vlanID int = -1
			if dot1qLayer := pkt.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
				dot1q := dot1qLayer.(*layers.Dot1Q)
				vlanID = int(dot1q.VLANIdentifier)
			}

			event := model.PacketEvent{
				Timestamp: pkt.Metadata().Timestamp,
				SrcMAC:    eth.SrcMAC,
				DstMAC:    eth.DstMAC,
				Payload:   pkt.Data(),
				PacketID:  uuid.New().String(),
				TTL:       ttl,
				VLANID:    vlanID,
			}

			select {
			case ps.packetChan <- event:
			case <-ctx.Done():
				break Loop
			}
		}
	}

	if ticker != nil {
		ticker.Stop()
		// Force 100% only at end of file (not on cancellation)
		progress(100)
	}
	close(ps.packetChan)
	ps.log.Info().Msg("PCAP sniffing completed")
	return nil
}
