package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

var (
	ExcludedIPs     []net.IP
	ExcludedSubnets []net.IPNet
)

// LoadExclusions reads IPs and CIDRs from a file and fills ExcludedIPs and ExcludedSubnets.
func LoadExclusions(path string) error {
	ExcludedIPs = nil
	ExcludedSubnets = nil

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open exclusion file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try parsing as CIDR
		if _, subnet, err := net.ParseCIDR(line); err == nil {
			ExcludedSubnets = append(ExcludedSubnets, *subnet)
			continue
		}

		// Try parsing as single IP
		if ip := net.ParseIP(line); ip != nil {
			ExcludedIPs = append(ExcludedIPs, ip)
			continue
		}

		return fmt.Errorf("invalid entry in exclusion file: %s", line)
	}

	return scanner.Err()
}

// IsExcludedIP returns true if the IP matches an excluded IP or subnet.
func IsExcludedIP(ip net.IP) bool {
	for _, excl := range ExcludedIPs {
		if ip.Equal(excl) {
			return true
		}
	}
	for _, subnet := range ExcludedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

