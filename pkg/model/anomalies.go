// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

// "net" // Not used in current implementation

// DetectAnomalies analyzes a host for potential network anomalies
func DetectAnomalies(host *Host) []Anomaly {
	var anomalies []Anomaly

	// Check for dual stack (IPv4 + IPv6) - this is NOT an anomaly
	// This is normal behavior for modern networks

	// Check for multiple DHCP servers
	if hasMultipleDHCPServers(host) {
		anomalies = append(anomalies, Anomaly{
			Type:        string(AnomMultipleDHCPServers),
			Description: string(AnomMultipleDHCPServers),
			Severity:    "high",
		})
	}

	// Check for suspicious TTL values
	if hasSuspiciousTTL(host) {
		anomalies = append(anomalies, Anomaly{
			Type:        string(AnomSuspiciousTTL),
			Description: string(AnomSuspiciousTTL),
			Severity:    "medium",
		})
	}

	// Check for unusual port combinations
	if hasUnusualPorts(host) {
		anomalies = append(anomalies, Anomaly{
			Type:        string(AnomUnusualPorts),
			Description: string(AnomUnusualPorts),
			Severity:    "medium",
		})
	}

	// Check for MAC address anomalies
	if hasMACAnomalies(host) {
		anomalies = append(anomalies, Anomaly{
			Type:        string(AnomMACAnomalies),
			Description: string(AnomMACAnomalies),
			Severity:    "low",
		})
	}

	return anomalies
}

// hasMultipleDHCPServers checks if the host has multiple DHCP servers
func hasMultipleDHCPServers(host *Host) bool {
	// This would need to be implemented based on how DHCP server information
	// is stored in the host record. For now, return false as a placeholder.
	// In a real implementation, this would check for multiple DHCP server
	// IPs in the host's info or other relevant fields.
	return false
}

// hasSuspiciousTTL checks for suspicious TTL values
func hasSuspiciousTTL(host *Host) bool {
	// TTL values that might indicate tunneling or unusual routing
	// Very low TTLs (0-15) or very high TTLs (200+) are suspicious
	if host.TTL >= 0 && host.TTL <= 15 {
		return true
	}
	if host.TTL >= 200 {
		return true
	}
	return false
}

// hasUnusualPorts checks for unusual port combinations
func hasUnusualPorts(host *Host) bool {
	// Check for common suspicious port combinations
	// This is a simplified implementation
	if len(host.Ports) == 0 {
		return false
	}

	// Check for common suspicious ports
	suspiciousPorts := []int{22, 23, 135, 139, 445, 1433, 3389, 5900, 8080}
	for _, port := range host.Ports {
		for _, suspiciousPort := range suspiciousPorts {
			if port == suspiciousPort {
				return true
			}
		}
	}
	return false
}

// hasMACAnomalies checks for MAC address anomalies
func hasMACAnomalies(host *Host) bool {
	if host.MAC == nil || len(host.MAC) != 6 {
		return false
	}

	// Check for broadcast MAC
	if host.MAC[0] == 0xFF && host.MAC[1] == 0xFF && host.MAC[2] == 0xFF &&
		host.MAC[3] == 0xFF && host.MAC[4] == 0xFF && host.MAC[5] == 0xFF {
		return true
	}

	// Check for multicast MAC
	if host.MAC[0]&0x01 == 1 {
		return true
	}

	// Check for locally administered MAC
	if host.MAC[0]&0x02 == 1 {
		return true
	}

	return false
}

// SetAnomalies sets the anomalies for a host
func (h *Host) SetAnomalies() {
	h.Anomalies = DetectAnomalies(h)
}
