// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"net"
	"testing"
)

func TestIsPrivateIPv4(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// RFC1918 - Classe A (10.0.0.0/8)
		{"Class A - 10.0.0.1", "10.0.0.1", true},
		{"Class A - 10.255.255.254", "10.255.255.254", true},
		{"Class A - 10.128.64.32", "10.128.64.32", true},

		// RFC1918 - Classe B (172.16.0.0/12)
		{"Class B - 172.16.0.1", "172.16.0.1", true},
		{"Class B - 172.31.255.254", "172.31.255.254", true},
		{"Class B - 172.20.128.64", "172.20.128.64", true},

		// RFC1918 - Classe C (192.168.0.0/16)
		{"Class C - 192.168.0.1", "192.168.0.1", true},
		{"Class C - 192.168.255.254", "192.168.255.254", true},
		{"Class C - 192.168.128.64", "192.168.128.64", true},

		// IPs publiques
		{"Public - 8.8.8.8", "8.8.8.8", false},
		{"Public - 1.1.1.1", "1.1.1.1", false},
		{"Public - 208.67.222.222", "208.67.222.222", false},

		// IPs spéciales
		{"Loopback - 127.0.0.1", "127.0.0.1", false},
		{"Multicast - 224.0.0.1", "224.0.0.1", false},
		{"Broadcast - 255.255.255.255", "255.255.255.255", false},

		// IPs en dehors des plages RFC1918
		{"172.15.255.255", "172.15.255.255", false},   // Juste avant 172.16.0.0/12
		{"172.32.0.1", "172.32.0.1", false},           // Juste après 172.31.255.255
		{"192.167.255.255", "192.167.255.255", false}, // Juste avant 192.168.0.0/16
		{"192.169.0.1", "192.169.0.1", false},         // Juste après 192.168.255.255
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := IsPrivateIPv4(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIPv4(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIPv4_InvalidInput(t *testing.T) {
	// Test avec une IP nulle
	result := IsPrivateIPv4(nil)
	if result != false {
		t.Errorf("IsPrivateIPv4(nil) = %v, expected false", result)
	}

	// Test avec une IPv6 (doit retourner false)
	ipv6 := net.ParseIP("2001:db8::1")
	result = IsPrivateIPv4(ipv6)
	if result != false {
		t.Errorf("IsPrivateIPv4(IPv6) = %v, expected false", result)
	}
}
