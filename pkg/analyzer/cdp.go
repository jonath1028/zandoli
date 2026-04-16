// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides passive analysis functions for various protocols.
package analyzer

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseCDPPacket analyzes a packet for CDP (Cisco Discovery Protocol) information.
// It handles both direct EtherType 0x2000 and LLC/SNAP encapsulated CDP frames.
// Prefers gopacket's CiscoDiscovery layer when available, falls back to custom TLV parsing.
func ParseCDPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.Payload) == 0 {
		return nil, nil
	}

	// First try to parse as complete Ethernet packet with CDP
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	// Check for direct EtherType 0x2000 CDP
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		if eth.EthernetType == 0x2000 {
			// Direct CDP EtherType - extract CDP payload
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				return parseCDPFromPayload(appLayer.Payload(), pkt.SrcMAC, pkt.Timestamp)
			}
		}
	}

	// Check for LLC/SNAP encapsulated CDP
	if packet.Layer(layers.LayerTypeLLC) != nil && packet.Layer(layers.LayerTypeSNAP) != nil {
		snapLayer := packet.Layer(layers.LayerTypeSNAP)
		if snapLayer != nil {
			snap := snapLayer.(*layers.SNAP)
			// Cisco OUI (0x00000c) with CDP PID (0x2000)
			if snap.OrganizationalCode[0] == 0x00 && snap.OrganizationalCode[1] == 0x00 &&
				snap.OrganizationalCode[2] == 0x0c && snap.Type == 0x2000 {
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					return parseCDPFromPayload(appLayer.Payload(), pkt.SrcMAC, pkt.Timestamp)
				}
			}
		}
	}

	// If we receive raw CDP payload without Ethernet header (from dispatcher LLC/SNAP processing)
	// Try to parse it directly as CDP
	if len(pkt.Payload) >= 4 { // Minimum CDP header size
		return parseCDPFromPayload(pkt.Payload, pkt.SrcMAC, pkt.Timestamp)
	}

	return nil, nil
}

// parseCDPFromPayload parses CDP TLVs from raw CDP payload using gopacket first, then custom parser
func parseCDPFromPayload(payload []byte, srcMAC net.HardwareAddr, timestamp time.Time) (*ParsedRecord, error) {
	// Try gopacket CiscoDiscovery layer first
	packet := gopacket.NewPacket(payload, layers.LayerTypeCiscoDiscovery, gopacket.Default)

	if cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscovery); cdpLayer != nil {
		cdp := cdpLayer.(*layers.CiscoDiscovery)
		return parseWithGopacket(cdp, srcMAC, timestamp)
	}

	// Fallback to custom TLV parser
	return parseWithCustomTLV(payload, srcMAC, timestamp)
}

// parseWithGopacket extracts CDP information using gopacket's CiscoDiscovery layer
func parseWithGopacket(cdp *layers.CiscoDiscovery, srcMAC net.HardwareAddr, timestamp time.Time) (*ParsedRecord, error) {
	cdpInfo := &model.CDPInfo{}
	role := "network_device"
	var mgmtAddresses []string
	var deviceIP net.IP

	// Extract information from CDP TLVs
	for _, value := range cdp.Values {
		switch value.Type {
		case layers.CDPTLVDevID: // Device ID (0x01)
			if len(value.Value) > 0 {
				cdpInfo.DeviceID = string(value.Value)
			}

		case layers.CDPTLVAddress: // Address (0x02)
			if addr := parseAddressTLV(value.Value); addr != nil {
				addrStr := addr.String()
				mgmtAddresses = append(mgmtAddresses, addrStr)
				if deviceIP == nil && addr.To4() != nil {
					deviceIP = addr
				}
			}

		case layers.CDPTLVPortID: // Port ID (0x03)
			if len(value.Value) > 0 {
				cdpInfo.PortID = string(value.Value)
			}

		case layers.CDPTLVCapabilities: // Capabilities (0x04)
			if len(value.Value) >= 4 {
				capabilities := binary.BigEndian.Uint32(value.Value[:4])
				cdpInfo.Capabilities = capabilities
				cdpInfo.DecodedCaps = decodeCDPCapabilities(capabilities)
				cdpInfo.CapabilitiesDecoded = decodeCDPCapabilities(capabilities)
				role = determineRoleFromCapabilities(capabilities)
			}

		case layers.CDPTLVVersion: // Software Version (0x05)
			if len(value.Value) > 0 {
				cdpInfo.Version = strings.TrimSpace(string(value.Value))
			}

		case layers.CDPTLVPlatform: // Platform (0x06)
			if len(value.Value) > 0 {
				cdpInfo.Platform = string(value.Value)
			}

		case layers.CDPTLVNativeVLAN: // Native VLAN (0x0a)
			if len(value.Value) >= 2 {
				cdpInfo.NativeVLAN = int(binary.BigEndian.Uint16(value.Value[:2]))
			}

		default:
			// Unknown TLV type — skip silently
		}
	}

	cdpInfo.Addresses = mgmtAddresses

	// Build info string for backward compatibility
	var infoParts []string
	if cdpInfo.DeviceID != "" {
		infoParts = append(infoParts, "DeviceID:"+cdpInfo.DeviceID)
	}
	if cdpInfo.Platform != "" {
		infoParts = append(infoParts, "platform="+cdpInfo.Platform)
	}
	if cdpInfo.PortID != "" {
		infoParts = append(infoParts, "port="+cdpInfo.PortID)
	}
	if cdpInfo.Version != "" {
		// Truncate version for info string to keep it manageable
		version := cdpInfo.Version
		if len(version) > 50 {
			version = version[:47] + "..."
		}
		infoParts = append(infoParts, "os="+version)
	}

	record := &ParsedRecord{
		MAC:       srcMAC,
		IP:        deviceIP,
		Protocols: []string{"CDP"},
		Role:      role,
		Info:      strings.Join(infoParts, " "),
		Hostname:  cdpInfo.DeviceID, // Device ID often serves as hostname
		Source:    "passive",
		FirstSeen: timestamp,
		LastSeen:  timestamp,
		CDP:       cdpInfo,
		L2: L2Info{
			CDP: true,
		},
	}

	// Log successful CDP parsing with key fields
	// Note: This is a minimal log inside the parser - most logging is done at dispatcher level
	return record, nil
}

// parseWithCustomTLV parses CDP TLVs using a custom parser as fallback
// Handles malformed TLVs defensively by skipping invalid entries
func parseWithCustomTLV(payload []byte, srcMAC net.HardwareAddr, timestamp time.Time) (*ParsedRecord, error) {
	if len(payload) < 4 {
		return nil, nil
	}

	// Skip CDP header (Version+TTL, Checksum = 4 bytes)
	tlvData := payload[4:]

	cdpInfo := &model.CDPInfo{}
	role := "network_device"
	var mgmtAddresses []string
	var deviceIP net.IP

	offset := 0
	for offset < len(tlvData) {
		// Need at least 4 bytes for TLV header (type + length)
		if offset+4 > len(tlvData) {
			break
		}

		tlvType := binary.BigEndian.Uint16(tlvData[offset : offset+2])
		tlvLength := binary.BigEndian.Uint16(tlvData[offset+2 : offset+4])

		// Validate TLV length
		if tlvLength < 4 || offset+int(tlvLength) > len(tlvData) {
			break
		}

		// Extract TLV value (excluding type and length)
		valueLength := int(tlvLength) - 4
		if valueLength > 0 {
			value := tlvData[offset+4 : offset+4+valueLength]

			switch tlvType {
			case 0x01: // Device ID
				cdpInfo.DeviceID = string(value)
			case 0x02: // Address List
				if addr := parseAddressTLV(value); addr != nil {
					addrStr := addr.String()
					mgmtAddresses = append(mgmtAddresses, addrStr)
					if deviceIP == nil && addr.To4() != nil {
						deviceIP = addr
					}
				}
			case 0x03: // Port ID
				cdpInfo.PortID = string(value)
			case 0x04: // Capabilities
				if len(value) >= 4 {
					capabilities := binary.BigEndian.Uint32(value[:4])
					cdpInfo.Capabilities = capabilities
					cdpInfo.DecodedCaps = decodeCDPCapabilities(capabilities)
					cdpInfo.CapabilitiesDecoded = decodeCDPCapabilities(capabilities)
					role = determineRoleFromCapabilities(capabilities)
				}
			case 0x05: // Software Version
				cdpInfo.Version = strings.TrimSpace(string(value))
			case 0x06: // Platform
				cdpInfo.Platform = string(value)
			case 0x0a: // Native VLAN
				if len(value) >= 2 {
					cdpInfo.NativeVLAN = int(binary.BigEndian.Uint16(value[:2]))
				}
			default:
				// Unknown TLV — skip silently
			}
		}

		offset += int(tlvLength)
	}

	cdpInfo.Addresses = mgmtAddresses

	// Build info string
	var infoParts []string
	if cdpInfo.DeviceID != "" {
		infoParts = append(infoParts, "DeviceID:"+cdpInfo.DeviceID)
	}
	if cdpInfo.Platform != "" {
		infoParts = append(infoParts, "platform="+cdpInfo.Platform)
	}
	if cdpInfo.PortID != "" {
		infoParts = append(infoParts, "port="+cdpInfo.PortID)
	}
	if cdpInfo.Version != "" {
		version := cdpInfo.Version
		if len(version) > 50 {
			version = version[:47] + "..."
		}
		infoParts = append(infoParts, "os="+version)
	}

	record := &ParsedRecord{
		MAC:       srcMAC,
		IP:        deviceIP,
		Protocols: []string{"CDP"},
		Role:      role,
		Info:      strings.Join(infoParts, " "),
		Hostname:  cdpInfo.DeviceID,
		Source:    "passive",
		FirstSeen: timestamp,
		LastSeen:  timestamp,
		CDP:       cdpInfo,
		L2: L2Info{
			CDP: true,
		},
	}

	// Log successful CDP parsing with key fields (custom parser)
	// Note: This is a minimal log inside the parser - most logging is done at dispatcher level
	return record, nil
}

// parseAddressTLV extracts IP address from CDP Address TLV
// Supports IPv4 addresses (protocol type 1)
func parseAddressTLV(data []byte) net.IP {
	if len(data) < 8 { // Minimum: 4 bytes count + 1 byte protocol + 1 byte length + 2+ bytes address
		return nil
	}

	// Address TLV format:
	// 4 bytes: Number of addresses
	// For each address:
	//   1 byte: Protocol type (1 = IPv4)
	//   1 byte: Address length
	//   N bytes: Address

	count := binary.BigEndian.Uint32(data[:4])
	if count == 0 {
		return nil
	}

	offset := 4
	for i := uint32(0); i < count && offset < len(data); i++ {
		if offset+2 > len(data) {
			break
		}

		protocolType := data[offset]
		addressLength := data[offset+1]
		offset += 2

		if offset+int(addressLength) > len(data) {
			break
		}

		if protocolType == 1 && addressLength == 4 { // IPv4
			return net.IP(data[offset : offset+4])
		}

		offset += int(addressLength)
	}

	return nil
}

// determineRoleFromCapabilities determines device role based on CDP capabilities
func determineRoleFromCapabilities(capabilities uint32) string {
	// CDP Capability bits:
	// 0x01 - Router
	// 0x02 - Transparent Bridge
	// 0x04 - Source Route Bridge
	// 0x08 - Switch
	// 0x10 - Host
	// 0x20 - IGMP
	// 0x40 - Repeater
	// 0x80 - Phone/AP

	if capabilities&0x80 != 0 {
		return "reseau" // Access Point or Phone
	}
	if capabilities&0x01 != 0 {
		return "reseau"
	}
	if capabilities&0x08 != 0 || capabilities&0x02 != 0 {
		return "reseau"
	}
	if capabilities&0x10 != 0 {
		return "client"
	}

	return "reseau" // Default
}
