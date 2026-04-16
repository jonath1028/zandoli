// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"

	"zandoli/pkg/model"
)

func TestComputeActiveSubnets(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []*model.Host
		expected []model.Subnet
	}{
		{
			name: "ARP subnets detection",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.0.10"),
					Protocols: []string{"ARP"},
					Source:    "passive",
				},
				{
					IP:        net.ParseIP("192.168.0.11"),
					Protocols: []string{"ARP"},
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.0.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.0.10", "192.168.0.11"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.0.10", "192.168.0.11"},
				},
			},
		},
		{
			name: "DHCP subnets detection",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.1.100"),
					Protocols: []string{"DHCP"},
					Info:      "Router:10.10.10.1 DNS:8.8.8.8",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.1.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.1.100"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.1.100"},
				},
				{
					CIDR:   "10.10.10.0/24",
					Source: "DHCP",
					Hosts:  []string{},
				},
				{
					CIDR:   "10.10.0.0/16",
					Source: "DHCP",
					Hosts:  []string{},
				},
				{
					CIDR:   "8.8.8.0/24",
					Source: "DHCP",
					Hosts:  []string{},
				},
				{
					CIDR:   "8.8.0.0/16",
					Source: "DHCP",
					Hosts:  []string{},
				},
			},
		},
		{
			name: "CDP subnets detection",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.2.50"),
					Protocols: []string{"CDP"},
					Info:      "DeviceID:Switch1 MgmtIP:172.16.5.1",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.2.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.2.50"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.2.50"},
				},
				{
					CIDR:   "172.16.5.0/24",
					Source: "CDP",
					Hosts:  []string{},
				},
				{
					CIDR:   "172.16.0.0/16",
					Source: "CDP",
					Hosts:  []string{},
				},
			},
		},
		{
			name: "LLDP subnets detection",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.3.60"),
					Protocols: []string{"LLDP"},
					Info:      "MgmtIP:10.0.0.1",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.3.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.3.60"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.3.60"},
				},
				{
					CIDR:   "10.0.0.0/24",
					Source: "LLDP",
					Hosts:  []string{},
				},
				{
					CIDR:   "10.0.0.0/16",
					Source: "LLDP",
					Hosts:  []string{},
				},
			},
		},
		{
			name: "VLAN detection",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.4.70"),
					Protocols: []string{"VLAN"},
					Info:      "VLANID:100",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.4.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.4.70"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.4.70"},
				},
				{
					CIDR:   "VLAN-100",
					Source: "VLAN",
					Hosts:  []string{},
				},
			},
		},
		{
			name: "Mixed protocols",
			hosts: []*model.Host{
				{
					IP:        net.ParseIP("192.168.5.10"),
					Protocols: []string{"ARP", "DHCP"},
					Info:      "Router:192.168.5.1",
					Source:    "passive",
				},
				{
					IP:        net.ParseIP("192.168.5.20"),
					Protocols: []string{"ARP", "CDP"},
					Info:      "MgmtIP:10.1.1.1",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{
				{
					CIDR:   "192.168.5.0/24",
					Source: "ARP",
					Hosts:  []string{"192.168.5.10", "192.168.5.20"},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "ARP",
					Hosts:  []string{"192.168.5.10", "192.168.5.20"},
				},
				{
					CIDR:   "192.168.5.0/24",
					Source: "DHCP",
					Hosts:  []string{},
				},
				{
					CIDR:   "192.168.0.0/16",
					Source: "DHCP",
					Hosts:  []string{},
				},
				{
					CIDR:   "10.1.1.0/24",
					Source: "CDP",
					Hosts:  []string{},
				},
				{
					CIDR:   "10.1.0.0/16",
					Source: "CDP",
					Hosts:  []string{},
				},
			},
		},
		{
			name:     "Empty hosts",
			hosts:    []*model.Host{},
			expected: []model.Subnet{},
		},
		{
			name: "Hosts without IP",
			hosts: []*model.Host{
				{
					Protocols: []string{"CDP"},
					Info:      "DeviceID:Switch1",
					Source:    "passive",
				},
			},
			expected: []model.Subnet{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeActiveSubnets(tt.hosts)

			// Vérifier le nombre de subnets
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d subnets, got %d", len(tt.expected), len(result))
				t.Logf("Expected: %+v", tt.expected)
				t.Logf("Got: %+v", result)
				return
			}

			// Créer une map pour faciliter la comparaison
			resultMap := make(map[string]model.Subnet)
			for _, subnet := range result {
				key := subnet.CIDR + "-" + subnet.Source
				resultMap[key] = subnet
			}

			for _, expected := range tt.expected {
				key := expected.CIDR + "-" + expected.Source
				actual, exists := resultMap[key]
				if !exists {
					t.Errorf("Expected subnet %s not found", key)
					continue
				}

				if actual.CIDR != expected.CIDR {
					t.Errorf("Expected CIDR %s, got %s", expected.CIDR, actual.CIDR)
				}

				if actual.Source != expected.Source {
					t.Errorf("Expected Source %s, got %s", expected.Source, actual.Source)
				}

				// Vérifier les hosts (ordre peut différer)
				if len(actual.Hosts) != len(expected.Hosts) {
					t.Errorf("Expected %d hosts, got %d for subnet %s", len(expected.Hosts), len(actual.Hosts), expected.CIDR)
				}

				// Créer des sets pour comparer les hosts
				expectedHosts := make(map[string]bool)
				for _, host := range expected.Hosts {
					expectedHosts[host] = true
				}

				actualHosts := make(map[string]bool)
				for _, host := range actual.Hosts {
					actualHosts[host] = true
				}

				for host := range expectedHosts {
					if !actualHosts[host] {
						t.Errorf("Expected host %s not found in subnet %s", host, expected.CIDR)
					}
				}

				for host := range actualHosts {
					if !expectedHosts[host] {
						t.Errorf("Unexpected host %s found in subnet %s", host, expected.CIDR)
					}
				}
			}
		})
	}
}

func TestExtractDHCPSubnets(t *testing.T) {
	subnetMap := make(map[string]model.Subnet)

	// Test avec Router et DNS
	extractDHCPSubnets("Router:192.168.1.1 DNS:8.8.8.8", subnetMap)

	expectedKeys := []string{
		"192.168.1.0/24-DHCP",
		"192.168.0.0/16-DHCP",
		"8.8.8.0/24-DHCP",
		"8.8.0.0/16-DHCP",
	}

	for _, key := range expectedKeys {
		if _, exists := subnetMap[key]; !exists {
			t.Errorf("Expected subnet key %s not found", key)
		}
	}
}

func TestExtractCDPSubnets(t *testing.T) {
	subnetMap := make(map[string]model.Subnet)

	// Test avec Management IP
	extractCDPSubnets("DeviceID:Switch1 MgmtIP:172.16.1.1", subnetMap)

	expectedKeys := []string{
		"172.16.1.0/24-CDP",
		"172.16.0.0/16-CDP",
	}

	for _, key := range expectedKeys {
		if _, exists := subnetMap[key]; !exists {
			t.Errorf("Expected subnet key %s not found", key)
		}
	}
}

func TestExtractLLDPSubnets(t *testing.T) {
	subnetMap := make(map[string]model.Subnet)

	// Test avec Management IP
	extractLLDPSubnets("MgmtIP:10.0.1.1", subnetMap)

	expectedKeys := []string{
		"10.0.1.0/24-LLDP",
		"10.0.0.0/16-LLDP",
	}

	for _, key := range expectedKeys {
		if _, exists := subnetMap[key]; !exists {
			t.Errorf("Expected subnet key %s not found", key)
		}
	}
}

func TestExtractVLANSubnets(t *testing.T) {
	subnetMap := make(map[string]model.Subnet)

	// Test avec VLAN ID
	extractVLANSubnets("VLANID:200", subnetMap)

	expectedKey := "VLAN-200-VLAN"
	if _, exists := subnetMap[expectedKey]; !exists {
		t.Errorf("Expected VLAN key %s not found", expectedKey)
	}

	// Vérifier le contenu
	vlan := subnetMap[expectedKey]
	if vlan.CIDR != "VLAN-200" {
		t.Errorf("Expected CIDR VLAN-200, got %s", vlan.CIDR)
	}
	if vlan.Source != "VLAN" {
		t.Errorf("Expected Source VLAN, got %s", vlan.Source)
	}
}

func TestAddSubnetsForIP(t *testing.T) {
	subnetMap := make(map[string]model.Subnet)

	// Test avec une IP
	ip := net.ParseIP("192.168.10.5")
	addSubnetsForIP(ip, "TEST", subnetMap)

	expectedKeys := []string{
		"192.168.10.0/24-TEST",
		"192.168.0.0/16-TEST",
	}

	for _, key := range expectedKeys {
		if _, exists := subnetMap[key]; !exists {
			t.Errorf("Expected subnet key %s not found", key)
		}
	}

	// Vérifier le contenu
	subnet24 := subnetMap["192.168.10.0/24-TEST"]
	if subnet24.CIDR != "192.168.10.0/24" {
		t.Errorf("Expected CIDR 192.168.10.0/24, got %s", subnet24.CIDR)
	}
	if subnet24.Source != "TEST" {
		t.Errorf("Expected Source TEST, got %s", subnet24.Source)
	}
}
