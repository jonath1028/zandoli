// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides passive analysis functions for various protocols.
package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseSMBPacket analyzes a packet and returns a ParsedRecord if it matches SMB over TCP (ports 445 or 139).
// Returns (nil, nil) if the packet is not an SMB packet.
func ParseSMBPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.Payload) < 1 {
		return nil, nil
	}

	// Use full decoding to extract TCP via IPv4 layer
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil, nil
	}

	// Support both SMB (port 445) and NetBIOS Session Service (port 139)
	if tcp.SrcPort != 445 && tcp.DstPort != 445 && tcp.SrcPort != 139 && tcp.DstPort != 139 {
		return nil, nil
	}

	role := "client"
	smbPort := 445
	if tcp.SrcPort == 445 || tcp.SrcPort == 139 {
		role = "server"
		smbPort = int(tcp.SrcPort)
	} else {
		smbPort = int(tcp.DstPort)
	}

	if len(pkt.SrcMAC) != 6 {
		return nil, nil
	}

	// Extract source and destination IPs
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

	record := &ParsedRecord{
		MAC:       append([]byte(nil), pkt.SrcMAC...), // safe copy
		Protocols: []string{"SMB"},
		Role:      role,
		Source:    "passive",
		FirstSeen: pkt.Timestamp.UTC(),
		LastSeen:  pkt.Timestamp.UTC(),
		// New fields
		IPSource:  ipSource,
		IPDest:    ipDest,
		L3Proto:   l3Proto,
		AppProto:  "SMB",
		Strength:  "medium", // SMB TCP = medium strength
		Transport: "tcp",
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
	}

	// Add port to record if role is server
	if role == "server" {
		record.Ports = []int{smbPort}
	}

	// Parse SMB payload for additional information
	parseSMBPayload(pkt.Payload, record)

	return record, nil
}

// parseSMBPayload analyzes SMB payload to extract OS information and other details
func parseSMBPayload(payload []byte, record *ParsedRecord) {
	if len(payload) < 4 {
		return
	}

	// Find SMB header in the payload
	// SMB packets start with 0xFF, 'S', 'M', 'B'
	smbStart := -1
	for i := 0; i < len(payload)-4; i++ {
		if payload[i] == 0xFF && payload[i+1] == 'S' && payload[i+2] == 'M' && payload[i+3] == 'B' {
			smbStart = i
			break
		}
	}

	if smbStart == -1 {
		return
	}

	smbData := payload[smbStart:]
	if len(smbData) < 32 {
		return
	}

	// Check for SMBv2/3 first (they have different header structure)
	if len(smbData) >= 68 {
		// Check for SMB2/3 header signature (4 zero bytes after SMB signature)
		if smbData[4] == 0x00 && smbData[5] == 0x00 && smbData[6] == 0x00 && smbData[7] == 0x00 {
			parseSMBv2v3Packet(smbData, record)
			return
		}
	}

	// Parse SMBv1 header
	// Byte 4: Command (0x72 = SMB_COM_SESSION_SETUP_ANDX for SMBv1)
	// Byte 5: Status (0x00 = success)
	command := smbData[4]
	status := smbData[5]

	// Check for SMBv1 Negotiate Protocol Response
	if command == 0x72 && status == 0x00 {
		// Check if this is a Negotiate Protocol Response by looking at the structure
		if len(smbData) >= 64 {
			parseSMBv1NegotiateResponse(smbData, record)
		}
		// Also check for Session Setup AndX Response
		parseSMBv1SessionSetupResponse(smbData, record)
	}
}

// parseSMBv1NegotiateResponse extracts dialect information from SMBv1 Negotiate Protocol Response
func parseSMBv1NegotiateResponse(smbData []byte, record *ParsedRecord) {
	if len(smbData) < 64 {
		return
	}

	// SMBv1 Negotiate Protocol Response structure:
	// Byte 32-33: Dialect index
	dialectIndex := binary.LittleEndian.Uint16(smbData[32:34])

	// Map dialect index to version (common SMBv1 dialects)
	var version string
	switch dialectIndex {
	case 0:
		version = "1.0"
	case 1:
		version = "2.002"
	case 2:
		version = "2.1"
	default:
		version = fmt.Sprintf("1.x (index %d)", dialectIndex)
	}

	record.Info = fmt.Sprintf("SMB dialect=%s", version)
}

// parseSMBv1SessionSetupResponse extracts NativeOS and NativeLanMan from SMBv1 Session Setup AndX Response
func parseSMBv1SessionSetupResponse(smbData []byte, record *ParsedRecord) {
	if len(smbData) < 32 {
		return
	}

	// SMBv1 Session Setup AndX Response structure:
	// Byte 32-33: AndX offset (if present)
	// Byte 34-35: Action
	// Byte 36-37: Security blob length
	// Byte 38+: Security blob
	// After security blob: NativeOS, NativeLanMan, PrimaryDomain, etc.

	// Skip to the security blob
	securityBlobLen := int(binary.LittleEndian.Uint16(smbData[36:38]))
	if securityBlobLen < 0 || len(smbData) < 38+securityBlobLen {
		return
	}

	// Start parsing after security blob
	offset := 38 + securityBlobLen
	if offset >= len(smbData) {
		return
	}

	// Parse strings (null-terminated)
	strings := parseNullTerminatedStrings(smbData[offset:])

	// Extract NativeOS and NativeLanMan
	var nativeOS, nativeLanMan string
	if len(strings) >= 1 && strings[0] != "" {
		nativeOS = strings[0]
	}
	if len(strings) >= 2 && strings[1] != "" {
		nativeLanMan = strings[1]
	}

	// Combine NativeOS and NativeLanMan for OSGuess
	if nativeOS != "" && nativeLanMan != "" {
		record.OSGuess = fmt.Sprintf("%s (%s)", nativeOS, nativeLanMan)
	} else if nativeOS != "" {
		record.OSGuess = nativeOS
	} else if nativeLanMan != "" {
		record.OSGuess = nativeLanMan
	}

	// Look for machine name in the strings (usually one of the first few)
	for _, str := range strings {
		if str != "" && len(str) > 0 {
			// Simple heuristic: if it looks like a hostname, use it
			if isLikelyHostname(str) {
				record.Hostname = str
				break
			}
		}
	}
}

// parseSMBv2v3Packet analyzes SMBv2/3 packets to extract dialect and OS information
func parseSMBv2v3Packet(smbData []byte, record *ParsedRecord) {
	if len(smbData) < 68 {
		return
	}

	// SMB2/3 header structure:
	// Byte 8-11: Header length (should be 64)
	// Byte 12-13: Credit charge
	// Byte 14-15: Status
	// Byte 16-17: Command
	// Byte 18-19: Credits
	// Byte 20-23: Flags
	// Byte 24-31: Next command
	// Byte 32-35: Message ID
	// Byte 36-39: Process ID
	// Byte 40-43: Tree ID
	// Byte 44-51: Session ID
	// Byte 52-67: Signature

	headerLen := binary.LittleEndian.Uint32(smbData[8:12])
	if headerLen != 64 {
		return
	}

	command := binary.LittleEndian.Uint16(smbData[16:18])
	status := binary.LittleEndian.Uint32(smbData[14:18])

	// Check for Negotiate Protocol Response (command 0x0000)
	if command == 0x0000 && status == 0x00000000 {
		parseSMBv2v3NegotiateResponse(smbData, record)
		return
	}

	// Check for Session Setup Response (command 0x0001)
	if command == 0x0001 && status == 0x00000000 {
		parseSMBv2v3SessionSetupResponse(smbData, record)
		return
	}
}

// parseSMBv2v3NegotiateResponse extracts dialect information from SMBv2/3 Negotiate Protocol Response
func parseSMBv2v3NegotiateResponse(smbData []byte, record *ParsedRecord) {
	if len(smbData) < 72 {
		return
	}

	// SMB2/3 Negotiate Response structure (after 64-byte header):
	// Byte 68-71: Dialect revision
	dialect := binary.LittleEndian.Uint16(smbData[68:70])

	// Map dialect to version
	var version string
	switch dialect {
	case 0x0202:
		version = "2.0.2"
	case 0x0210:
		version = "2.1.0"
	case 0x0300:
		version = "3.0"
	case 0x0302:
		version = "3.0.2"
	case 0x0311:
		version = "3.1.1"
	default:
		version = fmt.Sprintf("Unknown (0x%04X)", dialect)
	}

	record.Info = fmt.Sprintf("SMB dialect=%s", version)

	// Extract server capabilities for OS detection
	if len(smbData) >= 84 {
		serverCapabilities := binary.LittleEndian.Uint32(smbData[80:84])
		osGuess := getOSGuessFromSMBv2v3Capabilities(dialect, serverCapabilities)
		if osGuess != "" {
			record.OSGuess = osGuess
		}
	}
}

// parseSMBv2v3SessionSetupResponse extracts OS information from SMBv2/3 Session Setup Response
func parseSMBv2v3SessionSetupResponse(smbData []byte, record *ParsedRecord) {
	if len(smbData) < 80 {
		return
	}

	// Extract security buffer offset and length
	securityBufferOffset := binary.LittleEndian.Uint16(smbData[72:74])
	securityBufferLength := binary.LittleEndian.Uint16(smbData[74:76])

	if securityBufferLength == 0 || securityBufferOffset == 0 {
		return
	}

	// Calculate actual offset (SMB2/3 uses relative offsets from start of SMB header)
	actualOffset := int(securityBufferOffset)
	if actualOffset >= len(smbData) || actualOffset+int(securityBufferLength) > len(smbData) {
		return
	}

	// Parse security buffer for OS information
	securityBuffer := smbData[actualOffset : actualOffset+int(securityBufferLength)]
	parseSMBv2v3SecurityBuffer(securityBuffer, record)
}

// parseSMBv2v3SecurityBuffer extracts OS information from SMBv2/3 security buffer
func parseSMBv2v3SecurityBuffer(securityBuffer []byte, record *ParsedRecord) {
	// This is a simplified parser for NTLM authentication data
	// Look for NTLMSSP signature
	if len(securityBuffer) < 8 {
		return
	}

	// Check for NTLMSSP signature
	if string(securityBuffer[0:8]) == "NTLMSSP\x00" {
		// Parse NTLM Type 2 message for OS information
		if len(securityBuffer) >= 56 {
			// Extract OS version from NTLM Type 2 message
			osVersion := binary.LittleEndian.Uint32(securityBuffer[48:52])
			if osVersion != 0 {
				osGuess := getOSGuessFromNTLMOSVersion(osVersion)
				if osGuess != "" && record.OSGuess == "" {
					record.OSGuess = osGuess
				}
			}
		}
	}
}

// getOSGuessFromSMBv2v3Capabilities attempts to determine OS from SMBv2/3 capabilities
func getOSGuessFromSMBv2v3Capabilities(dialect uint16, capabilities uint32) string {
	// Windows-specific capability flags
	const (
		SMB2_GLOBAL_CAP_DFS                = 0x00000001
		SMB2_GLOBAL_CAP_LEASING            = 0x00000002
		SMB2_GLOBAL_CAP_LARGE_MTU          = 0x00000004
		SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
		SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
		SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
		SMB2_GLOBAL_CAP_ENCRYPTION         = 0x00000040
	)

	// Heuristics based on dialect and capabilities
	switch dialect {
	case 0x0202:
		if capabilities&SMB2_GLOBAL_CAP_DFS != 0 {
			return "Windows Vista/Server 2008 or later"
		}
		return "Windows Vista/Server 2008 or later"
	case 0x0210:
		if capabilities&SMB2_GLOBAL_CAP_LEASING != 0 {
			return "Windows 7/Server 2008 R2 or later"
		}
		return "Windows 7/Server 2008 R2 or later"
	case 0x0300:
		if capabilities&SMB2_GLOBAL_CAP_MULTI_CHANNEL != 0 {
			return "Windows 8/Server 2012 or later"
		}
		return "Windows 8/Server 2012 or later"
	case 0x0302:
		return "Windows 8.1/Server 2012 R2 or later"
	case 0x0311:
		if capabilities&SMB2_GLOBAL_CAP_ENCRYPTION != 0 {
			return "Windows 10/Server 2016 or later"
		}
		return "Windows 10/Server 2016 or later"
	}

	return ""
}

// getOSGuessFromNTLMOSVersion attempts to determine OS from NTLM OS version
func getOSGuessFromNTLMOSVersion(osVersion uint32) string {
	// Extract major and minor version
	major := uint8(osVersion & 0xFF)
	minor := uint8((osVersion >> 8) & 0xFF)
	build := uint16((osVersion >> 16) & 0xFFFF)

	// Windows version mapping based on build numbers
	switch {
	case major == 10:
		switch {
		case build >= 22000:
			return "Windows 11"
		case build >= 19041:
			return "Windows 10 (20H1 or later)"
		case build >= 18362:
			return "Windows 10 (19H1)"
		case build >= 17763:
			return "Windows 10 (1809)"
		case build >= 17134:
			return "Windows 10 (1803)"
		case build >= 16299:
			return "Windows 10 (1709)"
		case build >= 15063:
			return "Windows 10 (1703)"
		case build >= 14393:
			return "Windows 10 (1607)"
		case build >= 10586:
			return "Windows 10 (1511)"
		case build >= 10240:
			return "Windows 10"
		default:
			return "Windows 10 (unknown build)"
		}
	case major == 6:
		switch minor {
		case 3:
			return "Windows 8.1/Server 2012 R2"
		case 2:
			return "Windows 8/Server 2012"
		case 1:
			return "Windows 7/Server 2008 R2"
		case 0:
			return "Windows Vista/Server 2008"
		}
	case major == 5:
		switch minor {
		case 2:
			return "Windows Server 2003"
		case 1:
			return "Windows XP"
		case 0:
			return "Windows 2000"
		}
	}

	return fmt.Sprintf("Windows %d.%d (build %d)", major, minor, build)
}

// parseNullTerminatedStrings parses null-terminated strings from SMB data
func parseNullTerminatedStrings(data []byte) []string {
	var strings []string
	var current []byte

	for _, b := range data {
		if b == 0 {
			if len(current) > 0 {
				strings = append(strings, string(current))
				current = nil
			}
		} else {
			current = append(current, b)
		}
	}

	// Add last string if not null-terminated
	if len(current) > 0 {
		strings = append(strings, string(current))
	}

	return strings
}

// isLikelyHostname checks if a string looks like a hostname
func isLikelyHostname(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}

	// Check for valid hostname characters (alphanumeric, hyphen, dot)
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}

	// Must contain at least one alphanumeric character
	hasAlpha := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasAlpha = true
			break
		}
	}

	return hasAlpha
}
