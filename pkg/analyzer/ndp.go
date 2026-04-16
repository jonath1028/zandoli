// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides passive analysis functions for various protocols.
package analyzer

import (
	"fmt"
	"net"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseNDPPacket analyzes a packet for NDP (Neighbor Discovery Protocol) information.
// It handles ICMPv6 Neighbor Solicitation (type 135) and Neighbor Advertisement (type 136) messages.
// Returns a ParsedRecord with NDP protocol information if valid NDP packet is found.
func ParseNDPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.Payload) < 14 {
		return nil, nil
	}

	// Parse as complete Ethernet packet
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	// Check for IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		return nil, nil
	}
	ipv6 := ipv6Layer.(*layers.IPv6)

	// Check for ICMPv6 layer
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		return nil, nil
	}
	icmpv6 := icmpv6Layer.(*layers.ICMPv6)

	// Check for NDP types: Neighbor Solicitation (135) or Neighbor Advertisement (136)
	if icmpv6.TypeCode.Type() != 135 && icmpv6.TypeCode.Type() != 136 {
		return nil, nil
	}

	// Create ParsedRecord with NDP information
	record := NewParsedRecord(pkt)
	record.Protocols = []string{"NDP"}
	record.Source = "passive"

	// Determine role based on NDP message type
	if icmpv6.TypeCode.Type() == 135 {
		// Neighbor Solicitation - this is a request, so role is "client"
		record.Role = "client"
		record.Info = "Neighbor Solicitation"
	} else {
		// Neighbor Advertisement - this is a response, so role is "server"
		record.Role = "server"
		record.Info = "Neighbor Advertisement"
	}

	// Extract IPv6 addresses from the packet
	// For NDP, we're interested in the source IPv6 address
	if len(ipv6.SrcIP) > 0 {
		record.IP = ipv6.SrcIP
	}

	// Try to extract target address from NDP payload if available
	if len(icmpv6.Payload) >= 8 {
		// NDP payload structure: Flags (4 bytes) + Reserved (4 bytes) + Target Address (16 bytes)
		// Skip flags and reserved fields, extract target address
		if len(icmpv6.Payload) >= 24 {
			targetAddr := net.IP(icmpv6.Payload[8:24])
			if targetAddr.To16() != nil && !targetAddr.IsUnspecified() {
				// Store target address in Extra field for potential future use
				if record.Extra == nil {
					record.Extra = make(map[string]string)
				}
				record.Extra["target_address"] = targetAddr.String()
			}
		}
	}

	// Log NDP detection for debugging
	if record.IP != nil {
		// Additional info about the NDP message
		if record.Extra != nil && record.Extra["target_address"] != "" {
			record.Info = fmt.Sprintf("%s (target: %s)", record.Info, record.Extra["target_address"])
		}
	}

	return record, nil
}

// ParseNDPPacketFromIPv6 analyzes NDP packets from IPv6 payload directly.
// This is a helper function for cases where we already have IPv6 packet data.
func ParseNDPPacketFromIPv6(ipv6Payload []byte, srcMAC net.HardwareAddr, timestamp model.PacketEvent) (*ParsedRecord, error) {
	if len(ipv6Payload) < 40 { // Minimum IPv6 header size
		return nil, nil
	}

	// Parse IPv6 header
	// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits) = 4 bytes
	version := (ipv6Payload[0] >> 4) & 0x0F
	if version != 6 {
		return nil, nil
	}

	// Next Header (protocol) - should be 58 for ICMPv6
	nextHeader := ipv6Payload[6]
	if nextHeader != 58 {
		return nil, nil
	}

	// Extract source IPv6 address (bytes 8-23)
	srcIP := net.IP(ipv6Payload[8:24])

	// Extract ICMPv6 payload (after IPv6 header, minimum 40 bytes)
	if len(ipv6Payload) < 48 { // IPv6 header (40) + minimum ICMPv6 header (8)
		return nil, nil
	}

	icmpv6Payload := ipv6Payload[40:]
	icmpv6Type := icmpv6Payload[0]

	// Check for NDP types
	if icmpv6Type != 135 && icmpv6Type != 136 {
		return nil, nil
	}

	// Create ParsedRecord
	record := NewParsedRecord(timestamp)
	record.Protocols = []string{"NDP"}
	record.Source = "passive"
	record.IP = srcIP

	// Determine role and info
	if icmpv6Type == 135 {
		record.Role = "client"
		record.Info = "Neighbor Solicitation"
	} else {
		record.Role = "server"
		record.Info = "Neighbor Advertisement"
	}

	// Try to extract target address from NDP payload
	if len(icmpv6Payload) >= 24 { // ICMPv6 header (8) + NDP target address (16)
		targetAddr := net.IP(icmpv6Payload[8:24])
		if targetAddr.To16() != nil && !targetAddr.IsUnspecified() {
			if record.Extra == nil {
				record.Extra = make(map[string]string)
			}
			record.Extra["target_address"] = targetAddr.String()
			record.Info = fmt.Sprintf("%s (target: %s)", record.Info, targetAddr.String())
		}
	}

	return record, nil
}
