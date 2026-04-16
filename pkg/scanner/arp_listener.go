// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package scanner provides active network reconnaissance logic.
package scanner

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARPResult holds a response from an ARP reply.
type ARPResult struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// StartARPListener listens for ARP replies and sends valid IP/MAC pairs to a channel.
// It stops when the context is cancelled or reaches its timeout.
func StartARPListener(ctx context.Context, handle *pcap.Handle, out chan<- ARPResult) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			close(out)
			return

		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arpResp := arpLayer.(*layers.ARP)
			if arpResp.Operation != layers.ARPReply {
				continue
			}

			ip := net.IP(arpResp.SourceProtAddress).To4()
			mac := net.HardwareAddr(arpResp.SourceHwAddress)

			if ip == nil || mac == nil {
				continue
			}

			out <- ARPResult{IP: ip, MAC: mac}
		}
	}
}

