// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides OS fingerprinting capabilities based on SYN/ACK responses.
package analyzer

import (
	"strings"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// GuessOS performs heuristic OS detection based on TTL, Window Size, and TCP options.
// Returns the most likely OS family and a confidence score (0-10).
// DEPRECATED: Use GuessOSWeighted instead for better accuracy.
func GuessOS(ttl int, win int, opts []string) (string, int) {
	scores := map[string]int{
		"Windows": 0,
		"Linux":   0,
		"BSD":     0,
		"Other":   0,
	}

	// Dynamic TTL weight: when TTL is our only signal, give it more weight
	ttlWeight := 3
	if win == 0 && len(opts) == 0 {
		ttlWeight = 6 // TTL is our only signal, give it more weight
	}

	// TTL-based scoring
	switch {
	case ttl >= 120 && ttl <= 135: // Windows typically uses 128
		scores["Windows"] += ttlWeight
	case ttl >= 60 && ttl <= 70: // Linux/Unix typically uses 64
		scores["Linux"] += ttlWeight
		scores["BSD"] += ttlWeight - 1
	case ttl >= 250 && ttl <= 255: // Some BSD systems use 255
		scores["BSD"] += ttlWeight
		scores["Other"] += 1
	default:
		// TTL doesn't match common patterns
		scores["Other"] += 1
	}

	// Window Size-based scoring
	switch {
	case win == 65535 || win == 64240: // Windows typical values
		scores["Windows"] += 3
	case win == 5840 || win == 29200: // Linux typical values
		scores["Linux"] += 3
	case win == 4128 || win == 16384: // BSD typical values
		scores["BSD"] += 3
	case win >= 8192 && win <= 32768: // Common range for various systems
		scores["Windows"] += 1
		scores["Linux"] += 1
		scores["BSD"] += 1
	default:
		// Unusual window size
		scores["Other"] += 1
	}

	// TCP Options-based scoring
	hasMSS := false
	hasWScale := false
	hasSACK := false
	mssValue := 0

	for _, opt := range opts {
		opt = strings.TrimSpace(opt)
		if strings.HasPrefix(opt, "MSS:") {
			hasMSS = true
			// Extract MSS value for additional scoring
			if len(opt) > 4 {
				// Simple MSS value extraction (could be improved)
				if mss := extractMSS(opt); mss > 0 {
					mssValue = mss
				}
			}
		} else if strings.HasPrefix(opt, "WSCALE:") {
			hasWScale = true
		} else if opt == "SACK_PERMITTED" {
			hasSACK = true
		}
	}

	// MSS-based scoring
	if hasMSS {
		if mssValue == 1460 { // Common Ethernet MSS
			scores["Linux"] += 2
			scores["Windows"] += 1
		} else if mssValue >= 1300 && mssValue <= 1500 {
			scores["Windows"] += 1
			scores["Linux"] += 1
		}
	}

	// WSCALE-based scoring
	if hasWScale {
		scores["Linux"] += 1
		scores["Windows"] += 1
	}

	// SACK-based scoring (neutral, common to both)
	if hasSACK {
		scores["Linux"] += 1
		scores["Windows"] += 1
	}

	// Find the OS with highest score
	maxScore := 0
	bestOS := "Unknown"
	for os, score := range scores {
		if score > maxScore {
			maxScore = score
			bestOS = os
		}
	}

	// Cap the score at 10
	if maxScore > 10 {
		maxScore = 10
	}

	return bestOS, maxScore
}

// extractMSS attempts to extract MSS value from option string
func extractMSS(opt string) int {
	// Simple extraction - could be improved with proper parsing
	// Format is typically "MSS:1460"
	parts := strings.Split(opt, ":")
	if len(parts) != 2 {
		return 0
	}

	// Try to parse the MSS value
	if mss, err := parseInt(parts[1]); err == nil {
		return mss
	}
	return 0
}

// parseInt is a simple integer parser
func parseInt(s string) (int, error) {
	// Simple implementation for MSS parsing
	result := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			break
		}
	}
	return result, nil
}

// OSDetectionResult represents the result of weighted OS detection
type OSDetectionResult struct {
	Family  string   // OS family (e.g., "FortiOS", "iOS/macOS", "Cisco IOS", "Windows")
	Score   int      // Confidence score (0-100)
	Signals []string // Sources used for detection: vendor, cdp, mdns, tcp
}

// GuessOSWeighted performs weighted OS detection combining multiple signals:
// - Vendor information (strongest signal)
// - CDP information (very strong for Cisco devices)
// - mDNS services (strong for Apple devices)
// - TCP fingerprinting (weaker, used as fallback)
func GuessOSWeighted(host *model.Host) OSDetectionResult {
	scores := make(map[string]int)
	signals := make([]string, 0)

	// Initialize scores
	scores["Unknown"] = 0

	// 1. VENDOR-BASED DETECTION (Strongest signal, +40 points)
	if host.Vendor != "" {
		vendorOS := detectOSFromVendor(host.Vendor)
		if vendorOS != "Unknown" {
			scores[vendorOS] += 40
			signals = append(signals, "vendor")
		}
	}

	// 2. CDP-BASED DETECTION (Very strong for Cisco, +50 points)
	if host.CDP != nil {
		cdpOS := detectOSFromCDP(host.CDP)
		if cdpOS != "Unknown" {
			scores[cdpOS] += 50
			signals = append(signals, "cdp")
		}
	}

	// 3. mDNS-BASED DETECTION (Strong for Apple devices, +30 points)
	if utils.ContainsString(host.Protocols, "mDNS") && host.Info != "" {
		mdnsOS := detectOSFromMDNS(host.Info)
		if mdnsOS != "Unknown" {
			scores[mdnsOS] += 30
			signals = append(signals, "mdns")
		}
	}

	// 4. TCP FINGERPRINTING (Weaker signal, +10 points, only if no strong signals)
	hasStrongSignal := false
	for _, signal := range signals {
		if signal == "vendor" || signal == "cdp" || signal == "mdns" {
			hasStrongSignal = true
			break
		}
	}

	// Only use TCP fingerprinting if no strong signals are available
	ttlToUse := int(host.TTLAvg)
	if ttlToUse == 0 {
		ttlToUse = host.TTL
	}
	if !hasStrongSignal && ttlToUse > 0 {
		tcpOS, tcpScore := detectOSFromTCP(ttlToUse, host.WindowSize, host.TCPOpts)
		if tcpOS != "Unknown" && tcpScore > 0 {
			scores[tcpOS] += 10
			signals = append(signals, "tcp")
		}
	}

	// Find the OS with highest score
	maxScore := 0
	bestOS := "Unknown"
	for os, score := range scores {
		if score > maxScore {
			maxScore = score
			bestOS = os
		}
	}

	// Cap the score at 100
	if maxScore > 100 {
		maxScore = 100
	}

	return OSDetectionResult{
		Family:  bestOS,
		Score:   maxScore,
		Signals: signals,
	}
}

// detectOSFromVendor detects OS based on vendor information
func detectOSFromVendor(vendor string) string {
	vendor = strings.ToLower(vendor)

	// Fortinet devices
	if strings.Contains(vendor, "fortinet") {
		return "FortiOS"
	}

	// Apple devices
	if strings.Contains(vendor, "apple") {
		return "iOS/macOS"
	}

	// Cisco devices (generic)
	if strings.Contains(vendor, "cisco") {
		return "Cisco"
	}

	// Microsoft devices
	if strings.Contains(vendor, "microsoft") {
		return "Windows"
	}

	// Linux-based devices
	if strings.Contains(vendor, "raspberry") || strings.Contains(vendor, "linux") {
		return "Linux"
	}

	// VirtualBox / VMs
	if strings.Contains(vendor, "pcs systemtechnik") || strings.Contains(vendor, "virtualbox") {
		return "Linux/VM"
	}

	// VMware
	if strings.Contains(vendor, "vmware") {
		return "VM"
	}

	// Embedded devices (TP-Link routers/switches)
	if strings.Contains(vendor, "tp-link") || strings.Contains(vendor, "tp:link") {
		return "Embedded"
	}

	// Windows ODM laptops (Compal)
	if strings.Contains(vendor, "compal") {
		return "Windows"
	}

	// Lenovo laptops (typically Windows)
	if strings.Contains(vendor, "lcfc") || strings.Contains(vendor, "lenovo") {
		return "Windows"
	}

	// Intel NICs (typically Windows PCs)
	if strings.Contains(vendor, "intel") {
		return "Windows"
	}

	// Realtek NICs (typically Windows PCs)
	if strings.Contains(vendor, "realtek") {
		return "Windows"
	}

	return "Unknown"
}

// detectOSFromCDP detects OS based on CDP information
func detectOSFromCDP(cdp *model.CDPInfo) string {
	if cdp.Version != "" {
		version := strings.ToLower(cdp.Version)

		// Cisco IOS
		if strings.Contains(version, "ios") {
			return "Cisco IOS"
		}

		// Cisco NX-OS
		if strings.Contains(version, "nx-os") {
			return "Cisco NX-OS"
		}

		// Cisco ASA
		if strings.Contains(version, "asa") {
			return "Cisco ASA"
		}
	}

	if cdp.Platform != "" {
		platform := strings.ToLower(cdp.Platform)

		// Cisco platforms
		if strings.Contains(platform, "cisco") {
			return "Cisco"
		}
	}

	return "Unknown"
}

// detectOSFromMDNS detects OS based on mDNS services
func detectOSFromMDNS(info string) string {
	info = strings.ToLower(info)

	// Apple services
	appleServices := []string{"_airplay._tcp", "_raop._tcp", "_homekit._tcp", "_airport._tcp"}
	for _, service := range appleServices {
		if strings.Contains(info, service) {
			return "iOS/macOS"
		}
	}

	// Windows services
	if strings.Contains(info, "_workstation._tcp") {
		return "Windows"
	}

	return "Unknown"
}

// detectOSFromTCP performs TCP-based OS detection (fallback method)
func detectOSFromTCP(ttl int, win int, opts []string) (string, int) {
	// Use the existing TCP-based detection logic
	os, score := GuessOS(ttl, win, opts)

	// Convert score from 0-10 to 0-100 scale for consistency
	score = score * 10

	return os, score
}
