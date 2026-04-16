// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides passive analysis functions for various protocols.
package analyzer

import (
	"encoding/binary"
	"fmt"
	"zandoli/pkg/model"
)

// ParseSTPPacket parses STP BPDUs from raw Ethernet frames.
// Detects STP frames with multicast MAC 01:80:c2:00:00:00 and LLC DSAP/SSAP=0x42.
// Returns a ParsedRecord with STP information if valid BPDU is found.
func ParseSTPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	// Need at least Ethernet header (14) + LLC (3) + minimum STP BPDU (35) = 52 bytes
	if len(pkt.Payload) < 52 {
		return nil, nil
	}

	// Check if this is a STP multicast frame
	if len(pkt.DstMAC) != 6 {
		return nil, nil
	}

	// Check for STP multicast address (01:80:c2:00:00:00 or related group addresses)
	isSTPMulticast := pkt.DstMAC[0] == 0x01 && pkt.DstMAC[1] == 0x80 && pkt.DstMAC[2] == 0xc2
	if !isSTPMulticast {
		return nil, nil
	}

	// Check for LLC header (DSAP=0x42, SSAP=0x42, Control=0x03)
	// LLC starts at byte offset 14 (after Ethernet header)
	if len(pkt.Payload) < 17 {
		return nil, nil
	}

	if pkt.Payload[14] != 0x42 || pkt.Payload[15] != 0x42 || pkt.Payload[16] != 0x03 {
		return nil, nil
	}

	// STP BPDU starts after LLC header at offset 17
	stpOffset := 17
	if len(pkt.Payload) < stpOffset+35 {
		return nil, nil
	}

	// Parse STP BPDU header
	// Byte 0-1: Protocol ID (should be 0x0000)
	protocolID := binary.BigEndian.Uint16(pkt.Payload[stpOffset : stpOffset+2])
	if protocolID != 0x0000 {
		return nil, nil
	}

	// Byte 2: Version (0x00 for 802.1D)
	version := pkt.Payload[stpOffset+2]
	if version != 0x00 {
		return nil, nil
	}

	// Byte 3: Message Type (0x00 for Configuration BPDU)
	messageType := pkt.Payload[stpOffset+3]
	if messageType != 0x00 {
		// Skip TCN and RSTP frames for now, but don't error
		return nil, nil
	}

	// Parse STP BPDU fields
	// Byte 4: Flags (not used in current implementation)
	_ = pkt.Payload[stpOffset+4]

	// Byte 5-12: Root ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	rootID := pkt.Payload[stpOffset+5 : stpOffset+13]
	rootPriority := binary.BigEndian.Uint16(rootID[0:2])
	rootMAC := rootID[2:8]

	// Byte 13-16: Root Path Cost (4 bytes)
	rootPathCost := binary.BigEndian.Uint32(pkt.Payload[stpOffset+13 : stpOffset+17])

	// Byte 17-24: Bridge ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	bridgeID := pkt.Payload[stpOffset+17 : stpOffset+25]
	bridgePriority := binary.BigEndian.Uint16(bridgeID[0:2])
	bridgeMAC := bridgeID[2:8]

	// Byte 25-26: Port ID (2 bytes)
	portID := binary.BigEndian.Uint16(pkt.Payload[stpOffset+25 : stpOffset+27])

	// Byte 27-28: Message Age (2 bytes)
	messageAge := binary.BigEndian.Uint16(pkt.Payload[stpOffset+27 : stpOffset+29])

	// Byte 29-30: Max Age (2 bytes)
	maxAge := binary.BigEndian.Uint16(pkt.Payload[stpOffset+29 : stpOffset+31])

	// Byte 31-32: Hello Time (2 bytes)
	helloTime := binary.BigEndian.Uint16(pkt.Payload[stpOffset+31 : stpOffset+33])

	// Byte 33-34: Forward Delay (2 bytes)
	forwardDelay := binary.BigEndian.Uint16(pkt.Payload[stpOffset+33 : stpOffset+35])

	// Format MAC addresses as strings
	rootMACStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		rootMAC[0], rootMAC[1], rootMAC[2], rootMAC[3], rootMAC[4], rootMAC[5])
	bridgeMACStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		bridgeMAC[0], bridgeMAC[1], bridgeMAC[2], bridgeMAC[3], bridgeMAC[4], bridgeMAC[5])

	// Check if this bridge is claiming to be root (RootID == BridgeID)
	isRoot := rootMACStr == bridgeMACStr && rootPriority == bridgePriority

	// Format Bridge ID and Root ID as complete identifiers (priority + MAC)
	bridgeIDStr := fmt.Sprintf("%d:%s", bridgePriority, bridgeMACStr)
	rootIDStr := fmt.Sprintf("%d:%s", rootPriority, rootMACStr)

	// Create STP info structure
	stpInfo := &model.STPInfo{
		RootBridgeID: rootIDStr,
		RootPathCost: rootPathCost,
		BridgeID:     bridgeIDStr,
		PortID:       portID,
		HelloTime:    helloTime,
		MaxAge:       maxAge,
		ForwardDelay: forwardDelay,
		MessageAge:   messageAge,
		IsRoot:       isRoot,
	}

	// Build legacy info string for backward compatibility
	info := fmt.Sprintf("stpRoot=%t stpBridgeID=%s stpRootID=%s stpPathCost=%d stpPortID=%d",
		isRoot, bridgeIDStr, rootIDStr, rootPathCost, portID)

	return &ParsedRecord{
		MAC:       append([]byte(nil), pkt.SrcMAC...), // ensure safe copy
		Protocols: []string{"STP"},
		Role:      "network_device",
		Info:      info,
		Source:    "passive",
		FirstSeen: pkt.Timestamp.UTC(),
		LastSeen:  pkt.Timestamp.UTC(),
		STPInfo:   stpInfo, // Add STP-specific information
		L2: L2Info{
			STP: true,
		},
	}, nil
}
