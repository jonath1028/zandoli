// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import "net"

func IsBlacklisted(ip net.IP, blacklist []string) bool {
	if ip == nil {
		return false
	}
	ipStr := ip.String()
	for _, b := range blacklist {
		if ipStr == b {
			return true
		}
		if _, subnet, err := net.ParseCIDR(b); err == nil {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

