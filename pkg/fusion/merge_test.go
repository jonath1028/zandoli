// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package fusion

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"
)

func TestMergeHosts_FusionByKey(t *testing.T) {
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	ip := net.IPv4(192, 168, 0, 10)
	now := time.Now()

	passive := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"dhcp"},
			Ports:     []int{67},
			Anomalies: []model.Anomaly{{Description: "mac-mismatch", Severity: "medium"}},
			Role:      "client",
			TTL:       64,
			Source:    "passive",
			FirstSeen: now.Add(-2 * time.Minute),
			LastSeen:  now.Add(-1 * time.Minute),
		},
	}

	active := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"smb"},
			Ports:     []int{445},
			Anomalies: []model.Anomaly{{Description: "os-desync", Severity: "high"}},
			Role:      "server",
			TTL:       128,
			OSGuess:   "Windows",
			OnlyARP:   true,
			Source:    "active",
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	result := MergeHosts(passive, active)

	if len(result) != 1 {
		t.Fatalf("Expected 1 merged host, got %d", len(result))
	}

	h := result[0]

	if h.Source != "combined" {
		t.Errorf("Expected Source 'combined', got %s", h.Source)
	}

	if h.Role != "server" {
		t.Errorf("Expected Role 'server', got %s", h.Role)
	}

	if h.TTL != 128 {
		t.Errorf("Expected TTL from active (128), got %d", h.TTL)
	}

	if h.OSGuess != "Windows" {
		t.Errorf("Expected OSGuess 'Windows', got %s", h.OSGuess)
	}

	if !h.OnlyARP {
		t.Error("Expected OnlyARP to be true from active host")
	}

	if len(h.Ports) != 2 || !(contains(h.Ports, 67) && contains(h.Ports, 445)) {
		t.Errorf("Expected merged ports [67, 445], got %v", h.Ports)
	}

	if len(h.Protocols) != 2 || !(containsStr(h.Protocols, "dhcp") && containsStr(h.Protocols, "smb")) {
		t.Errorf("Expected merged protocols [dhcp, smb], got %v", h.Protocols)
	}

	if len(h.Anomalies) != 2 {
		t.Errorf("Expected 2 anomalies, got %v", h.Anomalies)
	}
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsStr(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func TestMergeRole(t *testing.T) {
	tests := []struct {
		name     string
		oldRole  string
		newRole  string
		expected string
	}{
		{
			name:     "Empty to client",
			oldRole:  "",
			newRole:  "client",
			expected: "client",
		},
		{
			name:     "Client to server",
			oldRole:  "client",
			newRole:  "server",
			expected: "server",
		},
		{
			name:     "Server to reseau",
			oldRole:  "server",
			newRole:  "reseau",
			expected: "reseau",
		},
		{
			name:     "Switch to router (both become reseau)",
			oldRole:  "switch",
			newRole:  "router",
			expected: "reseau",
		},
		{
			name:     "Router to client (should keep reseau)",
			oldRole:  "router",
			newRole:  "client",
			expected: "reseau",
		},
		{
			name:     "Router to server (should keep reseau)",
			oldRole:  "router",
			newRole:  "server",
			expected: "reseau",
		},
		{
			name:     "Router to switch (should keep reseau)",
			oldRole:  "router",
			newRole:  "switch",
			expected: "reseau",
		},
		{
			name:     "Client to router",
			oldRole:  "client",
			newRole:  "router",
			expected: "reseau",
		},
		{
			name:     "Server to router",
			oldRole:  "server",
			newRole:  "router",
			expected: "reseau",
		},
		{
			name:     "Same role",
			oldRole:  "switch",
			newRole:  "switch",
			expected: "reseau",
		},
		{
			name:     "Empty to empty",
			oldRole:  "",
			newRole:  "",
			expected: "",
		},
		{
			name:     "Server to client (should keep server)",
			oldRole:  "server",
			newRole:  "client",
			expected: "server",
		},
		{
			name:     "Empty to server",
			oldRole:  "",
			newRole:  "server",
			expected: "server",
		},
		{
			name:     "Empty to router",
			oldRole:  "",
			newRole:  "router",
			expected: "reseau",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeRole(tt.oldRole, tt.newRole)
			if result != tt.expected {
				t.Errorf("mergeRole(%q, %q) = %q, expected %q", tt.oldRole, tt.newRole, result, tt.expected)
			}
		})
	}
}

func TestMergeHosts_RouterRolePreservation(t *testing.T) {
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	ip := net.IPv4(192, 168, 0, 1)
	now := time.Now()

	// Hôte passif identifié comme router
	passive := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"CDP"},
			Role:      "reseau",
			Info:      "DeviceID:Router1",
			Source:    "passive",
			FirstSeen: now.Add(-2 * time.Minute),
			LastSeen:  now.Add(-1 * time.Minute),
		},
	}

	// Hôte actif identifié comme switch
	active := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"SMB"},
			Ports:     []int{445},
			Role:      "reseau",
			Source:    "active",
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	result := MergeHosts(passive, active)

	if len(result) != 1 {
		t.Fatalf("Expected 1 merged host, got %d", len(result))
	}

	h := result[0]

	// Le rôle "reseau" doit être préservé car il a une priorité plus élevée
	if h.Role != "reseau" {
		t.Errorf("Expected Role 'reseau' (priority 3), got %s", h.Role)
	}

	// Vérifier que les protocoles sont fusionnés
	expectedProtocols := []string{"CDP", "SMB"}
	if len(h.Protocols) != 2 {
		t.Errorf("Expected 2 protocols, got %d: %v", len(h.Protocols), h.Protocols)
	}

	protocolMap := make(map[string]bool)
	for _, protocol := range h.Protocols {
		protocolMap[protocol] = true
	}

	for _, expectedProtocol := range expectedProtocols {
		if !protocolMap[expectedProtocol] {
			t.Errorf("Expected protocol %s not found in %v", expectedProtocol, h.Protocols)
		}
	}

	// Vérifier que les ports sont fusionnés
	if len(h.Ports) != 1 || h.Ports[0] != 445 {
		t.Errorf("Expected ports [445], got %v", h.Ports)
	}
}

func TestMergeHosts_OnlyARPPriority(t *testing.T) {
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
	ip := net.IPv4(192, 168, 0, 20)
	now := time.Now()

	// Hôte passif avec protocoles TCP et mDNS
	passive := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"TCP", "mDNS"},
			Ports:     []int{80, 443, 5353},
			Role:      "client",
			Source:    "passive",
			FirstSeen: now.Add(-2 * time.Minute),
			LastSeen:  now.Add(-1 * time.Minute),
		},
	}

	// Hôte actif avec OnlyARP=true
	active := []*model.Host{
		{
			MAC:       mac,
			MACStr:    mac.String(),
			IP:        ip,
			Protocols: []string{"ARP"},
			OnlyARP:   true,
			Role:      "client",
			Source:    "active",
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	result := MergeHosts(passive, active)

	if len(result) != 1 {
		t.Fatalf("Expected 1 merged host, got %d", len(result))
	}

	h := result[0]

	// OnlyARP doit être true car le scan actif l'a défini, même si le passif a d'autres protocoles
	if !h.OnlyARP {
		t.Error("Expected OnlyARP to be true (prioritized from active scan)")
	}

	// Les protocoles doivent être fusionnés (TCP, mDNS, ARP)
	expectedProtocols := []string{"TCP", "mDNS", "ARP"}
	if len(h.Protocols) != 3 {
		t.Errorf("Expected 3 protocols, got %d: %v", len(h.Protocols), h.Protocols)
	}

	protocolMap := make(map[string]bool)
	for _, protocol := range h.Protocols {
		protocolMap[protocol] = true
	}

	for _, expectedProtocol := range expectedProtocols {
		if !protocolMap[expectedProtocol] {
			t.Errorf("Expected protocol %s not found in %v", expectedProtocol, h.Protocols)
		}
	}

	// Les ports doivent être fusionnés
	expectedPorts := []int{80, 443, 5353}
	if len(h.Ports) != 3 {
		t.Errorf("Expected 3 ports, got %d: %v", len(h.Ports), h.Ports)
	}

	portMap := make(map[int]bool)
	for _, port := range h.Ports {
		portMap[port] = true
	}

	for _, expectedPort := range expectedPorts {
		if !portMap[expectedPort] {
			t.Errorf("Expected port %d not found in %v", expectedPort, h.Ports)
		}
	}
}
