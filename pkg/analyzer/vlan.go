// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"errors"
	"net"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseVLANTag detects 802.1Q VLAN tags and returns a ParsedRecord.
func ParseVLANTag(pkt model.PacketEvent) (*ParsedRecord, error) {
	if pkt.Payload == nil {
		return nil, errors.New("empty payload")
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
	if dot1qLayer == nil {
		return nil, nil
	}

	dot1q := dot1qLayer.(*layers.Dot1Q)

	// For pure L2 frames without IP/CDP/LLDP, leave empty per specifications
	role := ""

	record := NewParsedRecord(pkt)
	record.Protocols = []string{"VLAN"}
	record.Role = role
	record.VLANID = int(dot1q.VLANIdentifier) // Override with the actual VLAN ID from the tag

	// Extract source and destination IPs if available
	var ipSource, ipDest net.IP
	var l3Proto string

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		ipSource = ipv4.SrcIP
		ipDest = ipv4.DstIP
		l3Proto = "IPv4"
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		ipSource = ipv6.SrcIP
		ipDest = ipv6.DstIP
		l3Proto = "IPv6"
	}

	// New fields
	record.IPSource = ipSource
	record.IPDest = ipDest
	record.L3Proto = l3Proto
	record.AppProto = "VLAN"
	record.Strength = "low" // VLAN tag seul = low strength

	// Log successful VLAN parsing with key fields
	// Note: This is a minimal log inside the parser - most logging is done at dispatcher level
	return record, nil
}
