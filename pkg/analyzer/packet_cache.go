// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GetPacket returns the pre-parsed gopacket.Packet from a PacketEvent.
// If the Packet field is already set (e.g., from PcapSniffer), it is reused.
// Otherwise, a new packet is parsed from the Payload bytes using the specified decode options.
// This eliminates redundant parsing: each packet is decoded only once.
func GetPacket(pkt model.PacketEvent, opts gopacket.DecodeOptions) gopacket.Packet {
	if pkt.Packet != nil {
		return pkt.Packet
	}
	return gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, opts)
}

// GetPacketNoCopy returns a pre-parsed packet with NoCopy decode options.
func GetPacketNoCopy(pkt model.PacketEvent) gopacket.Packet {
	return GetPacket(pkt, gopacket.NoCopy)
}

// GetPacketDefault returns a pre-parsed packet with Default decode options.
func GetPacketDefault(pkt model.PacketEvent) gopacket.Packet {
	return GetPacket(pkt, gopacket.Default)
}
