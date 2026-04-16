// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package validation

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateFlags validates CLI configuration flags.
func ValidateFlags(interfaceName string, synPorts []int, blacklist []string, passiveDuration int) []error {
	var errors []error

	// Network interface validation
	if interfaceName != "" {
		if !isValidInterface(interfaceName) {
			errors = append(errors, fmt.Errorf("invalid interface: %s", interfaceName))
		}
	}

	// SYN port validation
	for _, port := range synPorts {
		if port < 1 || port > 65535 {
			errors = append(errors, fmt.Errorf("invalid SYN port: %d (must be between 1 and 65535)", port))
		}
	}

	// Blacklist validation
	for _, ip := range blacklist {
		if !isValidIPOrCIDR(ip) {
			errors = append(errors, fmt.Errorf("invalid IP/CIDR in blacklist: %s", ip))
		}
	}

	// Passive duration validation
	if passiveDuration < 0 {
		errors = append(errors, fmt.Errorf("invalid passive duration: %d (must be positive)", passiveDuration))
	}

	return errors
}

// isValidInterface checks if the network interface exists
func isValidInterface(iface string) bool {
	// Allowed special interfaces
	specialInterfaces := []string{"lo", "any", "all"}
	for _, special := range specialInterfaces {
		if iface == special {
			return true
		}
	}

	// Check if the interface exists
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, i := range interfaces {
		if i.Name == iface {
			return true
		}
	}
	return false
}

// isValidIPOrCIDR checks if a string is a valid IP or CIDR
func isValidIPOrCIDR(ip string) bool {
	// Clean the IP
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}

	// Check if it is a simple IP
	if net.ParseIP(ip) != nil {
		return true
	}

	// Check if it is a CIDR
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return true
	}

	return false
}

// ValidatePorts validates a comma-separated list of ports.
func ValidatePorts(portsStr string) ([]int, error) {
	if portsStr == "" {
		return nil, nil
	}

	var ports []int
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		portStr := strings.TrimSpace(part)
		if portStr == "" {
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}

		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %d (must be between 1 and 65535)", port)
		}

		ports = append(ports, port)
	}

	return ports, nil
}

// ValidateFormats validates output format names.
func ValidateFormats(formats []string) error {
	validFormats := map[string]bool{
		"json":     true,
		"csv":      true,
		"html":     true,
		"markdown": true,
		"xml":      true,
	}

	for _, format := range formats {
		if !validFormats[format] {
			return fmt.Errorf("invalid format: %s (supported: json, csv, html, markdown, xml)", format)
		}
	}

	return nil
}
