// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides passive TCP OS fingerprinting capabilities.
// This module analyzes TCP SYN and SYN/ACK packets to extract OS-specific
// characteristics including Window Size, TCP options, and TTL patterns.
package analyzer

import (
	"errors"
	"fmt"
	"strings"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Global TCP consolidator instance
var tcpConsolidator = NewTCPConsolidator()

// ParseTCPPacket analyzes TCP SYN and SYN/ACK packets for OS fingerprinting.
// Extracts Window Size, TCP options, and TTL to compute an OS fingerprint score.
func ParseTCPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if pkt.Payload == nil {
		return nil, errors.New("empty payload")
	}

	// Parse the packet using gopacket
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	// Extract TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil // Not a TCP packet
	}

	tcp := tcpLayer.(*layers.TCP)

	// Only process SYN and SYN/ACK packets for OS fingerprinting
	if !tcp.SYN && !(tcp.SYN && tcp.ACK) {
		return nil, nil // Not a SYN or SYN/ACK packet
	}

	// Extract IP layer for TTL
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil // Not an IPv4 packet
	}

	ip := ipLayer.(*layers.IPv4)

	// Parse TCP options
	tcpOptions := parseTCPOptions(tcp.Options)

	// Add SYN packet to consolidator for grouping by 5-tuple
	if tcp.SYN && tcpOptions != nil {
		// Use the order from the parsed TCP options, not the raw extraction
		order := make([]string, len(tcpOptions.Order))
		copy(order, tcpOptions.Order)

		tcpConsolidator.AddSYN(
			ip.SrcIP,
			uint16(tcp.SrcPort),
			ip.DstIP,
			uint16(tcp.DstPort),
			6, // TCP protocol
			int(pkt.TTL),
			int(tcp.Window),
			tcpOptions,
			order,
		)
	}

	// Get consolidated TCP options for this host
	consolidatedOptions := tcpConsolidator.GetConsolidatedOptionsForHost(ip.SrcIP)

	// Use consolidated options if available, otherwise use current packet options
	finalOptions := tcpOptions
	if consolidatedOptions != nil {
		finalOptions = consolidatedOptions
	}

	// Compute OS fingerprinting score using consolidated options
	osGuess, osScore := computeOSFingerprint(
		int(tcp.Window),
		int(pkt.TTL),
		finalOptions,
	)

	// Determine role based on packet type
	role := "client"
	if tcp.SYN && tcp.ACK {
		role = "server"
	}

	// Create parsed record with OS fingerprinting data
	record := &ParsedRecord{
		MAC:        pkt.SrcMAC,
		IP:         ip.SrcIP,
		Protocols:  []string{"TCP"},
		Role:       role,
		WindowSize: int(tcp.Window),
		TTL:        int(pkt.TTL),
		OSGuess:    osGuess,
		OSScore:    int(osScore),
		TCPOpts:    formatTCPOptions(finalOptions),
		Source:     "passive",
		FirstSeen:  pkt.Timestamp,
		LastSeen:   pkt.Timestamp,
		// New fields
		IPSource: ip.SrcIP,
		IPDest:   ip.DstIP,
		L3Proto:  "IPv4",
		AppProto: "TCP",
		Strength: "medium", // TCP unicast = medium strength
	}

	// Add detailed TCP options if available
	if finalOptions != nil {
		record.TCPOptions = finalOptions
	}

	return record, nil
}

// parseTCPOptions extracts and parses TCP options from a TCP packet
func parseTCPOptions(options []layers.TCPOption) *model.TCPOptions {
	if len(options) == 0 {
		return nil
	}

	tcpOpts := &model.TCPOptions{
		Order: make([]string, 0, len(options)),
	}

	for _, option := range options {
		switch option.OptionType {
		case layers.TCPOptionKindMSS:
			if len(option.OptionData) >= 2 {
				// MSS is stored as big-endian 16-bit value
				tcpOpts.MSS = int(option.OptionData[0])<<8 | int(option.OptionData[1])
			}
			tcpOpts.Order = append(tcpOpts.Order, "MSS")

		case layers.TCPOptionKindWindowScale:
			if len(option.OptionData) >= 1 {
				tcpOpts.WSCALE = int(option.OptionData[0])
			}
			tcpOpts.Order = append(tcpOpts.Order, "WSCALE")

		case layers.TCPOptionKindSACKPermitted:
			tcpOpts.SACKPermitted = true
			tcpOpts.Order = append(tcpOpts.Order, "SACK_PERMITTED")

		case layers.TCPOptionKindTimestamps:
			tcpOpts.Timestamp = true
			tcpOpts.Order = append(tcpOpts.Order, "TIMESTAMP")

		case 1: // NOP option (kind 1)
			tcpOpts.NOPCount++
			tcpOpts.Order = append(tcpOpts.Order, "NOP")

		default:
			// Handle other options generically
			optionName := fmt.Sprintf("UNKNOWN_%d", option.OptionType)
			tcpOpts.Order = append(tcpOpts.Order, optionName)
		}
	}

	return tcpOpts
}

// extractOrderFromOptions extracts the order of TCP options as strings
func extractOrderFromOptions(options []layers.TCPOption) []string {
	var order []string

	for _, option := range options {
		switch option.OptionType {
		case layers.TCPOptionKindMSS:
			order = append(order, "MSS")
		case layers.TCPOptionKindWindowScale:
			order = append(order, "WSCALE")
		case layers.TCPOptionKindSACKPermitted:
			order = append(order, "SACK_PERMITTED")
		case layers.TCPOptionKindTimestamps:
			order = append(order, "TIMESTAMP")
		case 1: // NOP option
			order = append(order, "NOP")
		case 0: // End of Option List
			order = append(order, "EOL")
		default:
			order = append(order, fmt.Sprintf("UNKNOWN_%d", option.OptionType))
		}
	}

	return order
}

// formatTCPOptions converts TCP options to string format for legacy compatibility
func formatTCPOptions(tcpOpts *model.TCPOptions) []string {
	if tcpOpts == nil {
		return nil
	}

	var options []string

	if tcpOpts.MSS > 0 {
		options = append(options, fmt.Sprintf("MSS:%d", tcpOpts.MSS))
	}
	if tcpOpts.WSCALE > 0 {
		options = append(options, fmt.Sprintf("WSCALE:%d", tcpOpts.WSCALE))
	}
	if tcpOpts.SACKPermitted {
		options = append(options, "SACK_PERMITTED")
	}
	if tcpOpts.Timestamp {
		options = append(options, "TIMESTAMP")
	}
	if tcpOpts.NOPCount > 0 {
		options = append(options, fmt.Sprintf("NOP:%d", tcpOpts.NOPCount))
	}

	return options
}

// computeOSFingerprint analyzes TCP characteristics to determine OS and confidence score
func computeOSFingerprint(windowSize, ttl int, tcpOpts *model.TCPOptions) (string, uint8) {
	// OS fingerprinting patterns based on known characteristics
	osPatterns := map[string]int{
		"Windows": 0,
		"Linux":   0,
		"Cisco":   0,
		"FreeBSD": 0,
		"macOS":   0,
		"Unknown": 0,
	}

	// TTL-based scoring (common TTL values by OS)
	switch {
	case ttl >= 120 && ttl <= 135: // Windows typically uses 128
		osPatterns["Windows"] += 25
	case ttl >= 60 && ttl <= 70: // Linux/Unix typically uses 64
		osPatterns["Linux"] += 25
		osPatterns["FreeBSD"] += 20
	case ttl >= 250 && ttl <= 255: // Some BSD systems use 255
		osPatterns["FreeBSD"] += 25
	case ttl >= 55 && ttl <= 65: // macOS typically uses 64
		osPatterns["macOS"] += 20
	case ttl >= 200 && ttl <= 220: // Cisco devices often use 255
		osPatterns["Cisco"] += 25
	default:
		// TTL doesn't match common patterns
		osPatterns["Unknown"] += 10
	}

	// Window Size-based scoring
	switch {
	case windowSize == 65535 || windowSize == 64240: // Windows typical values
		osPatterns["Windows"] += 20
	case windowSize == 5840 || windowSize == 29200: // Linux typical values
		osPatterns["Linux"] += 20
	case windowSize == 4128 || windowSize == 16384: // BSD typical values
		osPatterns["FreeBSD"] += 20
	case windowSize == 65535 && tcpOpts != nil && tcpOpts.WSCALE > 0: // macOS with window scaling
		osPatterns["macOS"] += 20
	case windowSize >= 8192 && windowSize <= 32768: // Common range for various systems
		osPatterns["Windows"] += 10
		osPatterns["Linux"] += 10
		osPatterns["FreeBSD"] += 10
	default:
		// Unusual window size
		osPatterns["Unknown"] += 5
	}

	// TCP Options-based scoring
	if tcpOpts != nil {
		// MSS-based scoring
		if tcpOpts.MSS > 0 {
			switch {
			case tcpOpts.MSS == 1460: // Common Ethernet MSS
				osPatterns["Linux"] += 15
				osPatterns["Windows"] += 10
				osPatterns["macOS"] += 10
			case tcpOpts.MSS >= 1300 && tcpOpts.MSS <= 1500:
				osPatterns["Windows"] += 10
				osPatterns["Linux"] += 10
				osPatterns["macOS"] += 10
			case tcpOpts.MSS == 1380: // Common for VPN/MTU reduced
				osPatterns["Cisco"] += 15
			default:
				osPatterns["Unknown"] += 5
			}
		}

		// Window Scale Factor
		if tcpOpts.WSCALE > 0 {
			switch tcpOpts.WSCALE {
			case 7, 8: // Windows and Linux common values
				osPatterns["Windows"] += 10
				osPatterns["Linux"] += 10
			case 6: // macOS common value
				osPatterns["macOS"] += 15
			case 3, 4, 5: // Cisco common values
				osPatterns["Cisco"] += 15
			default:
				osPatterns["Unknown"] += 5
			}
		}

		// SACK Permitted
		if tcpOpts.SACKPermitted {
			osPatterns["Linux"] += 10
			osPatterns["Windows"] += 10
			osPatterns["macOS"] += 10
			osPatterns["FreeBSD"] += 10
		}

		// Timestamp option
		if tcpOpts.Timestamp {
			osPatterns["Linux"] += 10
			osPatterns["Windows"] += 10
			osPatterns["FreeBSD"] += 10
		}

		// NOP count patterns
		switch tcpOpts.NOPCount {
		case 0, 1: // Minimal NOPs
			osPatterns["Linux"] += 5
		case 2, 3: // Moderate NOPs
			osPatterns["Windows"] += 5
			osPatterns["macOS"] += 5
		case 4, 5: // Many NOPs
			osPatterns["Cisco"] += 10
		default:
			osPatterns["Unknown"] += 5
		}

		// Option order patterns
		if len(tcpOpts.Order) > 0 {
			orderStr := strings.Join(tcpOpts.Order, ",")

			// Windows typically: MSS,WSCALE,NOP,SACK_PERMITTED,TIMESTAMP,NOP,NOP
			if strings.Contains(orderStr, "MSS,WSCALE") && strings.Contains(orderStr, "SACK_PERMITTED") {
				osPatterns["Windows"] += 10
			}

			// Linux typically: MSS,SACK_PERMITTED,TIMESTAMP,NOP,WSCALE
			if strings.Contains(orderStr, "MSS,SACK_PERMITTED") && strings.Contains(orderStr, "TIMESTAMP") {
				osPatterns["Linux"] += 10
			}

			// macOS typically: MSS,NOP,WSCALE,NOP,TIMESTAMP,NOP,SACK_PERMITTED
			if strings.Contains(orderStr, "MSS,NOP,WSCALE") && strings.Contains(orderStr, "SACK_PERMITTED") {
				osPatterns["macOS"] += 10
			}

			// Cisco typically: MSS,NOP,NOP,NOP,TIMESTAMP,NOP,WSCALE
			if strings.Contains(orderStr, "MSS,NOP,NOP,NOP") && strings.Contains(orderStr, "WSCALE") {
				osPatterns["Cisco"] += 15
			}
		}
	}

	// Find the OS with highest score
	maxScore := 0
	bestOS := "Unknown"
	for os, score := range osPatterns {
		if score > maxScore {
			maxScore = score
			bestOS = os
		}
	}

	// Convert score to percentage (0-100)
	confidence := uint8(maxScore)
	if confidence > 100 {
		confidence = 100
	}

	// If confidence is too low, mark as Unknown
	if confidence < 30 {
		bestOS = "Unknown"
		confidence = 0
	}

	return bestOS, confidence
}

// mergeTCPFingerprint merges TCP fingerprinting data into an existing host record
func mergeTCPFingerprint(host *model.Host, tcpRecord *ParsedRecord) {
	if tcpRecord == nil || host == nil {
		return
	}

	// Get consolidated TCP options for this host
	consolidatedOptions := tcpConsolidator.GetConsolidatedOptionsForHost(tcpRecord.IP)

	// Use consolidated options if available, otherwise use record options
	finalOptions := tcpRecord.TCPOptions
	if consolidatedOptions != nil {
		finalOptions = consolidatedOptions
	}

	// Update OS information if we have better data or consolidated options
	shouldUpdate := false
	if uint8(tcpRecord.OSScore) > host.OSScore {
		shouldUpdate = true
	} else if consolidatedOptions != nil && consolidatedOptions.TCPFPConfidence > 0 {
		// Use consolidated options if they have confidence
		shouldUpdate = true
	}

	if shouldUpdate {
		host.OSGuess = tcpRecord.OSGuess
		host.OSScore = uint8(tcpRecord.OSScore)
		host.WindowSize = tcpRecord.WindowSize
		host.TCPOptions = finalOptions

		// Merge TCP options strings
		if len(tcpRecord.TCPOpts) > 0 {
			host.TCPOpts = append(host.TCPOpts, tcpRecord.TCPOpts...)
		}
	}

	// Update TTL average
	if tcpRecord.TTL > 0 {
		if host.TTLAvg == 0 {
			host.TTLAvg = uint8(tcpRecord.TTL)
		} else {
			// Simple average calculation
			host.TTLAvg = (host.TTLAvg + uint8(tcpRecord.TTL)) / 2
		}
	}
}
