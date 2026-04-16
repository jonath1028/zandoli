// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"net"
	"testing"

	"zandoli/pkg/model"
)

func TestFilterSubnets24(t *testing.T) {
	tests := []struct {
		name     string
		subnets  []model.Subnet
		expected int
	}{
		{
			name: "Filtrer les sous-réseaux /24",
			subnets: []model.Subnet{
				{CIDR: "192.168.1.0/24", Source: "ARP", Hosts: []string{"192.168.1.1", "192.168.1.2"}},
				{CIDR: "192.168.2.0/24", Source: "DHCP", Hosts: []string{"192.168.2.1"}},
				{CIDR: "10.0.0.0/16", Source: "ARP", Hosts: []string{"10.0.0.1", "10.0.1.1"}},
				{CIDR: "172.16.0.0/12", Source: "CDP", Hosts: []string{"172.16.0.1"}},
				{CIDR: "192.168.3.0/24", Source: "LLDP", Hosts: []string{"192.168.3.1"}},
			},
			expected: 3, // Seuls les /24 doivent être conservés
		},
		{
			name: "Aucun sous-réseau /24",
			subnets: []model.Subnet{
				{CIDR: "10.0.0.0/16", Source: "ARP", Hosts: []string{"10.0.0.1"}},
				{CIDR: "172.16.0.0/12", Source: "CDP", Hosts: []string{"172.16.0.1"}},
			},
			expected: 0,
		},
		{
			name:     "Liste vide",
			subnets:  []model.Subnet{},
			expected: 0,
		},
		{
			name: "Tous les sous-réseaux sont /24",
			subnets: []model.Subnet{
				{CIDR: "192.168.1.0/24", Source: "ARP", Hosts: []string{"192.168.1.1"}},
				{CIDR: "192.168.2.0/24", Source: "DHCP", Hosts: []string{"192.168.2.1"}},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterSubnets24(tt.subnets)
			if len(result) != tt.expected {
				t.Errorf("FilterSubnets24() retourné %d sous-réseaux, attendu %d", len(result), tt.expected)
			}

			// Vérifier que tous les sous-réseaux retournés sont bien /24
			for _, subnet := range result {
				if !isSubnet24(subnet.CIDR) {
					t.Errorf("Le sous-réseau %s n'est pas un /24", subnet.CIDR)
				}
			}
		})
	}
}

// isSubnet24 vérifie si un CIDR est un sous-réseau /24
func isSubnet24(cidr string) bool {
	// Vérification simple pour les tests
	return len(cidr) >= 3 && cidr[len(cidr)-3:] == "/24"
}

func TestRecomputeSubnetsFromHosts(t *testing.T) {
	tests := []struct {
		name                string
		hosts               []*model.Host
		allowPublicSubnets  bool
		expectedSubnetCount int
		expectedHostCount   int
	}{
		{
			name: "Hôtes privés uniquement",
			hosts: []*model.Host{
				{IP: net.ParseIP("192.168.1.1"), MACStr: "aa:bb:cc:dd:ee:01"},
				{IP: net.ParseIP("192.168.1.2"), MACStr: "aa:bb:cc:dd:ee:02"},
				{IP: net.ParseIP("192.168.2.1"), MACStr: "aa:bb:cc:dd:ee:03"},
				{IP: net.ParseIP("10.0.0.1"), MACStr: "aa:bb:cc:dd:ee:04"},
			},
			allowPublicSubnets:  false,
			expectedSubnetCount: 3, // 192.168.1.0/24, 192.168.2.0/24, 10.0.0.0/24
			expectedHostCount:   4,
		},
		{
			name: "Hôtes privés et publics",
			hosts: []*model.Host{
				{IP: net.ParseIP("192.168.1.1"), MACStr: "aa:bb:cc:dd:ee:01"},
				{IP: net.ParseIP("8.8.8.8"), MACStr: "aa:bb:cc:dd:ee:02"},
				{IP: net.ParseIP("1.1.1.1"), MACStr: "aa:bb:cc:dd:ee:03"},
			},
			allowPublicSubnets:  false,
			expectedSubnetCount: 1, // Seulement 192.168.1.0/24
			expectedHostCount:   1,
		},
		{
			name: "Hôtes privés et publics avec allowPublicSubnets=true",
			hosts: []*model.Host{
				{IP: net.ParseIP("192.168.1.1"), MACStr: "aa:bb:cc:dd:ee:01"},
				{IP: net.ParseIP("8.8.8.8"), MACStr: "aa:bb:cc:dd:ee:02"},
				{IP: net.ParseIP("1.1.1.1"), MACStr: "aa:bb:cc:dd:ee:03"},
			},
			allowPublicSubnets:  true,
			expectedSubnetCount: 3, // 192.168.1.0/24, 8.8.8.0/24, 1.1.1.0/24
			expectedHostCount:   3,
		},
		{
			name: "Hôtes sans IP",
			hosts: []*model.Host{
				{MACStr: "aa:bb:cc:dd:ee:01"}, // Pas d'IP
				{IP: net.ParseIP("192.168.1.1"), MACStr: "aa:bb:cc:dd:ee:02"},
			},
			allowPublicSubnets:  false,
			expectedSubnetCount: 1,
			expectedHostCount:   1,
		},
		{
			name: "Hôtes IPv6",
			hosts: []*model.Host{
				{IP: net.ParseIP("2001:db8::1"), MACStr: "aa:bb:cc:dd:ee:01"},
				{IP: net.ParseIP("192.168.1.1"), MACStr: "aa:bb:cc:dd:ee:02"},
			},
			allowPublicSubnets:  false,
			expectedSubnetCount: 1, // Seulement l'IPv4
			expectedHostCount:   1,
		},
		{
			name:                "Liste vide",
			hosts:               []*model.Host{},
			allowPublicSubnets:  false,
			expectedSubnetCount: 0,
			expectedHostCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RecomputeSubnetsFromHosts(tt.hosts, tt.allowPublicSubnets)

			if len(result) != tt.expectedSubnetCount {
				t.Errorf("RecomputeSubnetsFromHosts() retourné %d sous-réseaux, attendu %d", len(result), tt.expectedSubnetCount)
			}

			// Compter le nombre total d'hôtes dans tous les sous-réseaux
			totalHosts := 0
			for _, subnet := range result {
				totalHosts += len(subnet.Hosts)
			}

			if totalHosts != tt.expectedHostCount {
				t.Errorf("Nombre total d'hôtes dans les sous-réseaux: %d, attendu %d", totalHosts, tt.expectedHostCount)
			}

			// Vérifier que tous les sous-réseaux sont /24
			for _, subnet := range result {
				if !isSubnet24(subnet.CIDR) {
					t.Errorf("Le sous-réseau %s n'est pas un /24", subnet.CIDR)
				}
			}

			// Vérifier que la source est "computed"
			for _, subnet := range result {
				if subnet.Source != "computed" {
					t.Errorf("La source du sous-réseau %s est %s, attendu 'computed'", subnet.CIDR, subnet.Source)
				}
			}
		})
	}
}

func TestIsPublicSubnet(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IP privée 192.168.1.1", "192.168.1.1", false},
		{"IP privée 10.0.0.1", "10.0.0.1", false},
		{"IP privée 172.16.0.1", "172.16.0.1", false},
		{"IP publique 8.8.8.8", "8.8.8.8", true},
		{"IP publique 1.1.1.1", "1.1.1.1", true},
		{"IP publique 100.25.225.1", "100.25.225.1", true},
		{"IP loopback 127.0.0.1", "127.0.0.1", true}, // Loopback est considéré comme public
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("IP invalide: %s", tt.ip)
			}
			result := isPublicSubnet(ip)
			if result != tt.expected {
				t.Errorf("isPublicSubnet(%s) = %v, attendu %v", tt.ip, result, tt.expected)
			}
		})
	}
}
