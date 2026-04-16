// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"net"
	"strings"
)

// IsExcludedIPv4 checks if an IPv4 should be excluded (net.IP version)
func IsExcludedIPv4(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	// 127.0.0.0/8 (loopback)
	if isInRange(ip, net.IPv4(127, 0, 0, 0), net.IPv4(127, 255, 255, 255)) {
		return true
	}

	// 224.0.0.0/4 (multicast)
	if isInRange(ip, net.IPv4(224, 0, 0, 0), net.IPv4(239, 255, 255, 255)) {
		return true
	}

	// 0.0.0.0/8 (reserved)
	if isInRange(ip, net.IPv4(0, 0, 0, 0), net.IPv4(0, 255, 255, 255)) {
		return true
	}

	// 255.255.255.255 (broadcast)
	if ip.Equal(net.IPv4(255, 255, 255, 255)) {
		return true
	}

	return false
}

// IsExcludedIPv6 checks if an IPv6 should be excluded (net.IP version)
func IsExcludedIPv6(ip net.IP) bool {
	if ip.To16() == nil || ip.To4() != nil {
		return false
	}

	// fe80::/10 (link-local)
	// Check if the IP starts with fe80::/10
	if len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}

	return false
}

// IsExcludedIPv4Str checks if an IPv4 should be excluded (string version)
func IsExcludedIPv4Str(ip string) bool {
	// Exclure loopback, multicast, 0/8, broadcast
	if strings.HasPrefix(ip, "127.") || // loopback
		strings.HasPrefix(ip, "224.") || // multicast
		strings.HasPrefix(ip, "225.") ||
		strings.HasPrefix(ip, "226.") ||
		strings.HasPrefix(ip, "227.") ||
		strings.HasPrefix(ip, "228.") ||
		strings.HasPrefix(ip, "229.") ||
		strings.HasPrefix(ip, "230.") ||
		strings.HasPrefix(ip, "231.") ||
		strings.HasPrefix(ip, "232.") ||
		strings.HasPrefix(ip, "233.") ||
		strings.HasPrefix(ip, "234.") ||
		strings.HasPrefix(ip, "235.") ||
		strings.HasPrefix(ip, "236.") ||
		strings.HasPrefix(ip, "237.") ||
		strings.HasPrefix(ip, "238.") ||
		strings.HasPrefix(ip, "239.") ||
		strings.HasPrefix(ip, "0.") || // 0/8
		ip == "255.255.255.255" { // broadcast
		return true
	}
	return false
}

// IsExcludedIPv6Str checks if an IPv6 should be excluded (string version)
func IsExcludedIPv6Str(ip string) bool {
	// Exclure link-local fe80::/10
	return strings.HasPrefix(ip, "fe80:")
}

// IsPrivateIPv4 checks if an IPv4 is in RFC1918 private space
func IsPrivateIPv4(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	// 10.0.0.0/8
	if isInRange(ip, net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255)) {
		return true
	}

	// 172.16.0.0/12
	if isInRange(ip, net.IPv4(172, 16, 0, 0), net.IPv4(172, 31, 255, 255)) {
		return true
	}

	// 192.168.0.0/16
	if isInRange(ip, net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 255, 255)) {
		return true
	}

	return false
}

// isInRange checks if an IP is in a given range
func isInRange(ip, start, end net.IP) bool {
	ipBytes := ip.To4()
	startBytes := start.To4()
	endBytes := end.To4()

	if ipBytes == nil || startBytes == nil || endBytes == nil {
		return false
	}

	for i := 0; i < 4; i++ {
		if ipBytes[i] < startBytes[i] || ipBytes[i] > endBytes[i] {
			return false
		}
	}
	return true
}
