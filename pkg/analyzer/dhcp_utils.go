// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// normalizeString cleans a string by removing non-printable characters
// and ensuring it is valid UTF-8
func normalizeString(s string) string {
	if s == "" {
		return ""
	}

	// Check if the string is valid UTF-8
	if !utf8.ValidString(s) {
		// If not valid UTF-8, convert to hex
		return "0x" + hex.EncodeToString([]byte(s))
	}

	// Clean non-printable characters
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 { // Printable characters except DEL
			result.WriteRune(r)
		} else if r == 0 {
			// Replace null bytes with an indicator
			result.WriteString("\\0")
		} else {
			// Replace other non-printable characters with their hex code
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}

	return result.String()
}

// normalizeBytes converts bytes to a readable hex representation
func normalizeBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// If all bytes are printable, try to treat them as a string
	if isPrintable(data) {
		str := string(data)
		if utf8.ValidString(str) {
			return normalizeString(str)
		}
	}

	// Otherwise, convert to hex with format "01:xx:xx:..."
	var parts []string
	for i, b := range data {
		if i == 0 {
			parts = append(parts, fmt.Sprintf("%02x", b))
		} else {
			parts = append(parts, fmt.Sprintf("%02x", b))
		}
	}
	return strings.Join(parts, ":")
}

// isPrintable checks if all bytes are printable
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}

// parseIPList parses a list of IPs from DHCP data
func parseIPList(data []byte) []string {
	var ips []string

	// IPs are stored in blocks of 4 bytes
	for i := 0; i < len(data); i += 4 {
		if i+4 <= len(data) {
			ip := net.IP(data[i : i+4])
			if !ip.IsUnspecified() {
				ips = append(ips, ip.String())
			}
		}
	}

	return ips
}

// parseDHCPRoutes parses static routes from options 121 and 249
func parseDHCPRoutes(data []byte) []DHCPRoute {
	var routes []DHCPRoute

	i := 0
	for i < len(data) {
		if i+1 >= len(data) {
			break
		}

		prefixLen := int(data[i])
		i++

		if prefixLen == 0 {
			// Default route
			if i+4 <= len(data) {
				nextHop := net.IP(data[i : i+4])
				routes = append(routes, DHCPRoute{
					Prefix:  "0.0.0.0/0",
					NextHop: nextHop.String(),
				})
				i += 4
			}
		} else if prefixLen <= 32 {
			// Route with prefix
			octets := (prefixLen + 7) / 8 // Number of bytes for the prefix
			if i+octets+4 <= len(data) {
				// Extract the prefix
				prefixBytes := make([]byte, 4)
				copy(prefixBytes, data[i:i+octets])
				prefix := net.IP(prefixBytes)

				// Extract the next hop
				nextHop := net.IP(data[i+octets : i+octets+4])

				// Build the CIDR
				cidr := fmt.Sprintf("%s/%d", prefix.String(), prefixLen)

				routes = append(routes, DHCPRoute{
					Prefix:  cidr,
					NextHop: nextHop.String(),
				})

				i += octets + 4
			} else {
				break
			}
		} else {
			// Invalid prefix length
			break
		}
	}

	return routes
}

// parseDHCPRelayInfo parses DHCP relay information (option 82)
func parseDHCPRelayInfo(data []byte) DHCPRelayInfo {
	var relay DHCPRelayInfo

	i := 0
	for i < len(data) {
		if i+2 >= len(data) {
			break
		}

		subOptType := data[i]
		subOptLen := int(data[i+1])
		i += 2

		if i+subOptLen > len(data) {
			break
		}

		subOptData := data[i : i+subOptLen]

		switch subOptType {
		case 1: // Circuit ID
			relay.CircuitID = normalizeBytes(subOptData)
		case 2: // Remote ID
			relay.RemoteID = normalizeBytes(subOptData)
		}

		i += subOptLen
	}

	return relay
}

// truncateString truncates a string if it exceeds the maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// truncateList truncates a list if it exceeds the maximum size
func truncateList(items []string, maxItems int) []string {
	if len(items) <= maxItems {
		return items
	}

	truncated := make([]string, maxItems)
	copy(truncated, items[:maxItems])
	truncated[maxItems-1] = fmt.Sprintf("+%d more", len(items)-maxItems+1)
	return truncated
}

