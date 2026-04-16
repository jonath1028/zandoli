// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"strings"
	"testing"
	"time"

	"zandoli/pkg/model"
)

// DISABLED: MergeRole logic changed in simplified aggregator
/*
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
			name:     "Client to router",
			oldRole:  "client",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeRole(tt.oldRole, tt.newRole)
			if result != tt.expected {
				t.Errorf("mergeRole(%q, %q) = %q, expected %q", tt.oldRole, tt.newRole, result, tt.expected)
			}
		})
	}
}
*/

// TestAggregatorL2Hosts teste que l'aggregator peut gérer les hôtes L2 sans IP
func TestAggregatorL2Hosts(t *testing.T) {
	aggregator := NewAggregator()

	// Créer 3 ParsedRecord CDP avec seulement MAC et Protocols
	mac1 := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	mac2 := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
	mac3 := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77}

	records := []*ParsedRecord{
		{
			MAC:       mac1,
			Protocols: []string{"CDP"},
			Role:      "switch",
			Info:      "DeviceID:Switch1",
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac2,
			Protocols: []string{"LLDP"},
			Role:      "router",
			Info:      "DeviceID:Router1",
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac3,
			Protocols: []string{"STP"},
			Role:      "switch",
			Info:      "",
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
	}

	// Injecter les records dans l'aggregator
	for _, record := range records {
		aggregator.Merge(record)
	}

	// Vérifier que GetResults() retourne 3 Hosts avec ces MAC
	hosts := aggregator.GetAll()
	if len(hosts) != 3 {
		t.Errorf("Expected 3 hosts, got %d", len(hosts))
	}

	// Vérifier que chaque MAC est présente
	macStrings := make(map[string]bool)
	for _, host := range hosts {
		macStrings[host.MACStr] = true
	}

	expectedMACs := []string{
		mac1.String(),
		mac2.String(),
		mac3.String(),
	}

	for _, expectedMAC := range expectedMACs {
		if !macStrings[expectedMAC] {
			t.Errorf("Expected MAC %s not found in results", expectedMAC)
		}
	}

	// Vérifier que les protocoles sont corrects
	for _, host := range hosts {
		if len(host.Protocols) == 0 {
			t.Errorf("Host %s has no protocols", host.MACStr)
		}
	}
}

// TestAggregatorL2WithIPFusion teste la fusion d'un hôte L2 avec une IP plus tard
func TestAggregatorL2WithIPFusion(t *testing.T) {
	aggregator := NewAggregator()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("192.168.1.100")

	// D'abord, créer un hôte L2 sans IP
	l2Record := &ParsedRecord{
		MAC:       mac,
		Protocols: []string{"CDP"},
		Role:      "switch",
		Info:      "DeviceID:Switch1",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Puis, créer un record avec la même MAC mais avec IP
	ipRecord := &ParsedRecord{
		MAC:       mac,
		IP:        ip,
		Protocols: []string{"DHCP"},
		Role:      "switch",
		Info:      "Router:192.168.1.1",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Injecter les deux records
	aggregator.Merge(l2Record)
	aggregator.Merge(ipRecord)

	// Vérifier qu'il n'y a qu'un seul host
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Errorf("Expected 1 host after fusion, got %d", len(hosts))
	}

	host := hosts[0]

	// Vérifier que le host a à la fois l'IP et les protocoles L2
	if host.IP == nil || !host.IP.Equal(ip) {
		t.Errorf("Expected IP %s, got %v", ip.String(), host.IP)
	}

	if host.MACStr != mac.String() {
		t.Errorf("Expected MAC %s, got %s", mac.String(), host.MACStr)
	}

	// Vérifier que les protocoles sont fusionnés
	expectedProtocols := []string{"CDP", "DHCP"}
	if len(host.Protocols) != 2 {
		t.Errorf("Expected 2 protocols, got %d: %v", len(host.Protocols), host.Protocols)
	}

	protocolMap := make(map[string]bool)
	for _, protocol := range host.Protocols {
		protocolMap[protocol] = true
	}

	for _, expectedProtocol := range expectedProtocols {
		if !protocolMap[expectedProtocol] {
			t.Errorf("Expected protocol %s not found in %v", expectedProtocol, host.Protocols)
		}
	}
}

func TestMergeHostname(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Test 1: Définir un hostname quand il est vide
	record1 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "host1.example.com",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record1)
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(hosts))
	}

	host := hosts[0]
	if host.Hostname != "host1.example.com" {
		t.Errorf("Expected hostname 'host1.example.com', got '%s'", host.Hostname)
	}

	// Test 2: Ne pas écraser un hostname existant avec une valeur différente
	record2 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "host2.example.com", // Différent du premier
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record2)
	hosts = aggregator.GetAll()
	host = hosts[0]
	if host.Hostname != "host1.example.com" {
		t.Errorf("Expected hostname to remain 'host1.example.com', got '%s'", host.Hostname)
	}

	// Test 3: Définir un hostname si l'ancien était vide
	aggregator2 := NewAggregator()
	record3 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "", // Vide
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	record4 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "newhost.example.com",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator2.Merge(record3)
	aggregator2.Merge(record4)
	hosts = aggregator2.GetAll()
	host = hosts[0]
	if host.Hostname != "newhost.example.com" {
		t.Errorf("Expected hostname 'newhost.example.com', got '%s'", host.Hostname)
	}
}

func TestMergeVLANs(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Test 1: Ajouter un VLAN
	record1 := &ParsedRecord{
		MAC:       mac,
		VLANID:    100,
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record1)
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(hosts))
	}

	host := hosts[0]
	if len(host.VLANs) != 1 || host.VLANs[0] != 100 {
		t.Errorf("Expected VLAN [100], got %v", host.VLANs)
	}

	// Test 2: Ajouter un VLAN différent
	record2 := &ParsedRecord{
		MAC:       mac,
		VLANID:    200,
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record2)
	hosts = aggregator.GetAll()
	host = hosts[0]
	if len(host.VLANs) != 2 {
		t.Errorf("Expected 2 VLANs, got %d: %v", len(host.VLANs), host.VLANs)
	}

	// Vérifier que les deux VLANs sont présents
	vlanMap := make(map[int]bool)
	for _, vlan := range host.VLANs {
		vlanMap[vlan] = true
	}
	if !vlanMap[100] || !vlanMap[200] {
		t.Errorf("Expected VLANs [100, 200], got %v", host.VLANs)
	}

	// Test 3: Ne pas ajouter un VLAN dupliqué
	record3 := &ParsedRecord{
		MAC:       mac,
		VLANID:    100, // Même VLAN que le premier
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record3)
	hosts = aggregator.GetAll()
	host = hosts[0]
	if len(host.VLANs) != 2 {
		t.Errorf("Expected 2 VLANs after duplicate, got %d: %v", len(host.VLANs), host.VLANs)
	}
}

func TestMergeInfoVLANFiltering(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Test 1: Info normale (non-VLAN) doit être acceptée
	record1 := &ParsedRecord{
		MAC:       mac,
		Info:      "Router:192.168.1.1 DNS:8.8.8.8",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record1)
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(hosts))
	}

	host := hosts[0]
	if host.Info != "Router:192.168.1.1 DNS:8.8.8.8" {
		t.Errorf("Expected normal info to be set, got '%s'", host.Info)
	}

	// Test 2: Info avec VLAN doit être filtrée
	record2 := &ParsedRecord{
		MAC:       mac,
		Info:      "VLANID:100", // Info VLAN qui doit être filtrée
		VLANID:    100,          // VLAN ID qui doit être ajouté via AddVLAN
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record2)
	hosts = aggregator.GetAll()
	host = hosts[0]

	// L'info ne doit pas être écrasée par l'info VLAN
	if host.Info != "Router:192.168.1.1 DNS:8.8.8.8" {
		t.Errorf("Expected info to remain unchanged, got '%s'", host.Info)
	}

	// Mais le VLAN doit être ajouté
	if len(host.VLANs) != 1 || host.VLANs[0] != 100 {
		t.Errorf("Expected VLAN [100], got %v", host.VLANs)
	}
}

func TestMergeMultipleVLANs(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Test: Fusion de multiples VLANs
	records := []*ParsedRecord{
		{
			MAC:       mac,
			VLANID:    100,
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac,
			VLANID:    200,
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac,
			VLANID:    300,
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
	}

	// Injecter tous les records
	for _, record := range records {
		aggregator.Merge(record)
	}

	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host after merging VLANs, got %d", len(hosts))
	}

	host := hosts[0]
	if len(host.VLANs) != 3 {
		t.Errorf("Expected 3 VLANs, got %d: %v", len(host.VLANs), host.VLANs)
	}

	// Vérifier que tous les VLANs sont présents
	expectedVLANs := []int{100, 200, 300}
	vlanMap := make(map[int]bool)
	for _, vlan := range host.VLANs {
		vlanMap[vlan] = true
	}

	for _, expectedVLAN := range expectedVLANs {
		if !vlanMap[expectedVLAN] {
			t.Errorf("Expected VLAN %d not found in %v", expectedVLAN, host.VLANs)
		}
	}
}

func TestMergeHostnameNotOverwrittenByEmpty(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Test 1: Définir un hostname
	record1 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "original-hostname",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record1)
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(hosts))
	}

	host := hosts[0]
	if host.Hostname != "original-hostname" {
		t.Errorf("Expected hostname 'original-hostname', got '%s'", host.Hostname)
	}

	// Test 2: Essayer d'écraser avec une valeur vide (ne doit pas fonctionner)
	record2 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "", // Valeur vide
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record2)
	hosts = aggregator.GetAll()
	host = hosts[0]

	// Le hostname ne doit pas être écrasé par la valeur vide
	if host.Hostname != "original-hostname" {
		t.Errorf("Expected hostname to remain 'original-hostname', got '%s'", host.Hostname)
	}

	// Test 3: Essayer d'écraser avec une valeur différente (ne doit pas fonctionner)
	record3 := &ParsedRecord{
		MAC:       mac,
		Hostname:  "different-hostname",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	aggregator.Merge(record3)
	hosts = aggregator.GetAll()
	host = hosts[0]

	// Le hostname ne doit pas être écrasé par la nouvelle valeur
	if host.Hostname != "original-hostname" {
		t.Errorf("Expected hostname to remain 'original-hostname', got '%s'", host.Hostname)
	}
}

// TestMultiVLANAnomalyDetection teste la détection d'anomalies avec des VLANs
// DISABLED: Simplified aggregator no longer tracks VLAN in IP mappings
/*
func TestMultiVLANAnomalyDetection(t *testing.T) {
	aggregator := NewAggregator()

	// Créer deux hôtes avec la même IP mais sur des VLANs différents
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	ip := net.ParseIP("192.168.1.100")

	// Hôte 1 sur VLAN 10
	record1 := &ParsedRecord{
		MAC:       mac1,
		IP:        ip,
		VLANID:    10,
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Hôte 2 sur VLAN 20 (même IP, VLAN différent)
	record2 := &ParsedRecord{
		MAC:       mac2,
		IP:        ip,
		VLANID:    20,
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Injecter les records
	aggregator.Merge(record1)
	aggregator.Merge(record2)

	// Détecter les anomalies
	aggregator.DetectAnomalies()

	// Vérifier qu'il n'y a PAS d'anomalie ip_duplicate
	// car les IPs sont sur des VLANs différents
	hosts := aggregator.GetAll()
	if len(hosts) != 2 {
		t.Fatalf("Expected 2 hosts, got %d", len(hosts))
	}

	for _, host := range hosts {
		for _, anomaly := range host.Anomalies {
			if anomaly.Type == "ip_duplicate" {
				t.Errorf("Expected no ip_duplicate anomaly for same IP on different VLANs, but found: %v", anomaly)
			}
		}
	}

	// Maintenant testons le cas où la même IP est utilisée sur le même VLAN
	aggregator2 := NewAggregator()
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")

	// Hôte 1 sur VLAN 10
	record3 := &ParsedRecord{
		MAC:       mac1,
		IP:        ip,
		VLANID:    10,
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Hôte 3 sur VLAN 10 (même IP, même VLAN - anomalie attendue)
	record4 := &ParsedRecord{
		MAC:       mac3,
		IP:        ip,
		VLANID:    10,
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Injecter les records
	aggregator2.Merge(record3)
	aggregator2.Merge(record4)

	// Détecter les anomalies
	aggregator2.DetectAnomalies()

	// Vérifier qu'il y a une anomalie ip_duplicate_v4
	hosts2 := aggregator2.GetAll()
	hasIPDuplicate := false
	for _, host := range hosts2 {
		for _, anomaly := range host.Anomalies {
			if anomaly.Type == "ip_duplicate_v4" {
				hasIPDuplicate = true
				// Vérifier que les paramètres contiennent les MACs
				if macs, ok := anomaly.Parameters["macs"].([]string); ok {
					if len(macs) < 2 {
						t.Errorf("Expected at least 2 MACs in duplicate, got: %d", len(macs))
					}
				}
			}
		}
	}

	if !hasIPDuplicate {
		t.Error("Expected ip_duplicate_v4 anomaly for same IP on same VLAN, but none found")
	}
}
*/

// TestMultiVLANHost teste un hôte présent sur plusieurs VLANs
func TestMultiVLANHost(t *testing.T) {
	aggregator := NewAggregator()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.100")

	// Créer des records pour le même hôte sur différents VLANs
	records := []*ParsedRecord{
		{
			MAC:       mac,
			IP:        ip,
			VLANID:    10,
			Protocols: []string{"ARP"},
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac,
			IP:        ip,
			VLANID:    20,
			Protocols: []string{"ARP"},
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		{
			MAC:       mac,
			IP:        ip,
			VLANID:    10, // Dupliqué
			Protocols: []string{"ARP"},
			Source:    "passive",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
	}

	// Injecter tous les records
	for _, record := range records {
		aggregator.Merge(record)
	}

	// Vérifier qu'il n'y a qu'un seul hôte
	hosts := aggregator.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(hosts))
	}

	host := hosts[0]

	// Vérifier que l'hôte a les deux VLANs
	if len(host.VLANs) != 2 {
		t.Errorf("Expected 2 VLANs, got %d: %v", len(host.VLANs), host.VLANs)
	}

	// Vérifier que les VLANs sont 10 et 20
	vlanMap := make(map[int]bool)
	for _, vlan := range host.VLANs {
		vlanMap[vlan] = true
	}
	if !vlanMap[10] || !vlanMap[20] {
		t.Errorf("Expected VLANs [10, 20], got %v", host.VLANs)
	}

	// Vérifier les statistiques VLAN
	if len(host.VLANStats) != 2 {
		t.Errorf("Expected 2 VLAN stats, got %d: %v", len(host.VLANStats), host.VLANStats)
	}

	// VLAN 10 devrait avoir 2 occurrences (dupliqué)
	if host.VLANStats[10] != 2 {
		t.Errorf("Expected VLAN 10 to have 2 occurrences, got %d", host.VLANStats[10])
	}

	// VLAN 20 devrait avoir 1 occurrence
	if host.VLANStats[20] != 1 {
		t.Errorf("Expected VLAN 20 to have 1 occurrence, got %d", host.VLANStats[20])
	}

	// Le VLAN principal devrait être 10 (le plus fréquent)
	if host.PrimaryVLAN != 10 {
		t.Errorf("Expected primary VLAN to be 10, got %d", host.PrimaryVLAN)
	}
}

// DISABLED: Method inferRoleWithPriorityMatrix removed from simplified aggregator
/*
func TestRoleInference_NetworkBeatsServerOnL2Signals(t *testing.T) {
	a := NewAggregator()

	// Test 1: CDP + TCP → reseau (CDP=97 > TCP=70)
	h1 := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MACStr:      "00:11:22:33:44:55",
		IP:          net.ParseIP("10.200.200.101"),
		IPs:         []net.IP{net.ParseIP("10.200.200.101")},
		Vendor:      "Cisco Systems",
		Protocols:   []string{"ARP", "CDP", "TCP"},
		RoleSignals: []string{"CDP", "TCP"},
	}
	roleInfo1 := a.inferRoleWithPriorityMatrix(h1)
	if roleInfo1.Role != "reseau" {
		t.Fatalf("Test 1: expected role reseau, got %s (signals=%v, confidence=%d)", roleInfo1.Role, roleInfo1.Signals, roleInfo1.Confidence)
	}

	// Test 2: LLDP + DHCP → reseau (LLDP=96 > DHCP=95)
	h2 := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		MACStr:      "00:11:22:33:44:66",
		IP:          net.ParseIP("192.168.1.1"),
		IPs:         []net.IP{net.ParseIP("192.168.1.1")},
		Vendor:      "HP",
		Protocols:   []string{"LLDP", "DHCP"},
		RoleSignals: []string{"LLDP", "DHCP"},
	}
	roleInfo2 := a.inferRoleWithPriorityMatrix(h2)
	if roleInfo2.Role != "reseau" {
		t.Fatalf("Test 2: expected role reseau, got %s (signals=%v, confidence=%d)", roleInfo2.Role, roleInfo2.Signals, roleInfo2.Confidence)
	}

	// Test 3: STP + DNS → reseau (STP=98 > DNS=90)
	h3 := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77},
		MACStr:      "00:11:22:33:44:77",
		IP:          net.ParseIP("10.0.0.1"),
		IPs:         []net.IP{net.ParseIP("10.0.0.1")},
		Vendor:      "Dell",
		Protocols:   []string{"STP", "DNS"},
		RoleSignals: []string{"STP", "DNS"},
	}
	roleInfo3 := a.inferRoleWithPriorityMatrix(h3)
	if roleInfo3.Role != "reseau" {
		t.Fatalf("Test 3: expected role reseau, got %s (signals=%v, confidence=%d)", roleInfo3.Role, roleInfo3.Signals, roleInfo3.Confidence)
	}

	// Test 4: TCP seul → server (pas de L2 discovery)
	h4 := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x88},
		MACStr:      "00:11:22:33:44:88",
		IP:          net.ParseIP("192.168.1.100"),
		IPs:         []net.IP{net.ParseIP("192.168.1.100")},
		Vendor:      "Microsoft",
		Protocols:   []string{"TCP"},
		RoleSignals: []string{"TCP"},
	}
	roleInfo4 := a.inferRoleWithPriorityMatrix(h4)
	if roleInfo4.Role != "server" {
		t.Fatalf("Test 4: expected role server, got %s (signals=%v, confidence=%d)", roleInfo4.Role, roleInfo4.Signals, roleInfo4.Confidence)
	}
}

func TestRoleInference_TieBreakerDeterministic(t *testing.T) {
	a := NewAggregator()

	// Test tie-breaker: même priorité → reseau > server > client > unknown
	// Créer un hôte avec des signaux de même priorité pour tester le tie-breaker
	h := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x99},
		MACStr:      "00:11:22:33:44:99",
		IP:          net.ParseIP("192.168.1.50"),
		IPs:         []net.IP{net.ParseIP("192.168.1.50")},
		Vendor:      "Test Vendor",
		Protocols:   []string{"CDP", "DHCP"}, // CDP=97, DHCP=95 → CDP gagne
		RoleSignals: []string{"CDP", "DHCP"},
	}

	roleInfo := a.inferRoleWithPriorityMatrix(h)
	if roleInfo.Role != "reseau" {
		t.Fatalf("Tie-breaker test: expected role reseau (CDP beats DHCP), got %s (signals=%v, confidence=%d)", roleInfo.Role, roleInfo.Signals, roleInfo.Confidence)
	}
}
*/

func TestNormalizeRole_AccentsAndSynonyms(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"réseau", "reseau"},
		{"réseaux", "reseau"},
		{"reseaux", "reseau"},
		{"router", "reseau"},
		{"switch", "reseau"},
		{"network_device", "reseau"},
		{"repeater", "reseau"},
		{"access_point", "reseau"},
		{"server", "server"},
		{"client", "client"},
		{"unknown", "unknown"},
		{"", ""},
		{"RÉSEAU", "reseau"}, // Test case insensitive
		{"SWITCH", "reseau"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeRole(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeRole(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestOUITriggersNetworkRole vérifie que l'OUI d'un équipement réseau déclenche le rôle "reseau"
// même sans signaux L2 authentiques (CDP, LLDP, STP, 802.1X)
func TestOUITriggersNetworkRole(t *testing.T) {
	// Test 1: Host avec uniquement MAC/Vendor Cisco → doit être "reseau"
	t.Run("Vendor_Cisco_Without_L2_Signals", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0x00, 0x1E, 0x14, 0xAA, 0xBB, 0xCC}, // OUI Cisco
			MACStr:    "00:1e:14:aa:bb:cc",
			Vendor:    "Cisco Systems",
			Protocols: []string{}, // Aucun protocole détecté
		}

		roleInfo := InferRole(h)
		if roleInfo.Role != "reseau" {
			t.Errorf("OUI Cisco doit déclencher le rôle 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
		if roleInfo.Confidence != 90 {
			t.Errorf("Confiance OUI_INFRA doit être 90. Got %d", roleInfo.Confidence)
		}
		// Vérifier que le signal OUI_INFRA est présent
		hasOUISignal := false
		for _, sig := range roleInfo.Signals {
			if sig == "OUI_INFRA" || strings.HasPrefix(sig, "OUI:") {
				hasOUISignal = true
				break
			}
		}
		if !hasOUISignal {
			t.Errorf("Signal OUI_INFRA manquant. Got signals=%v", roleInfo.Signals)
		}
	})

	// Test 2: Host avec OUI non-réseau (VMware) → pas "reseau"
	t.Run("VMware_Vendor_Without_L2", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0xAA, 0xBB, 0xCC}, // OUI VMware
			MACStr:    "00:0c:29:aa:bb:cc",
			Vendor:    "VMware",
			IP:        net.ParseIP("192.168.1.10"),
			IPs:       []net.IP{net.ParseIP("192.168.1.10")},
			Protocols: []string{"ARP"},
		}

		roleInfo := InferRole(h)
		if roleInfo.Role == "reseau" {
			t.Errorf("OUI VMware (non-réseau) ne doit PAS déclencher 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
	})

	// Test 3: Host avec CDP → doit être "reseau"
	t.Run("CDP_Triggers_Reseau", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0x00, 0x1E, 0x14, 0xAA, 0xBB, 0xCC},
			MACStr:    "00:1e:14:aa:bb:cc",
			Vendor:    "Cisco Systems",
			Protocols: []string{"CDP"},
			L2Signals: model.L2SignalsInfo{
				CDP: true,
			},
			CDP: &model.CDPInfo{
				DeviceID:     "switch-1",
				Capabilities: CDPCapSwitch, // Capabilities non-zéro pour trigger CDP analysis
			},
		}

		roleInfo := InferRole(h)
		if roleInfo.Role != "reseau" {
			t.Errorf("CDP doit déclencher le rôle 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
		// Vérifier que le signal L2_PRESENT est présent (nouveau comportement)
		hasL2 := false
		for _, sig := range roleInfo.Signals {
			if sig == "L2_PRESENT" {
				hasL2 = true
				break
			}
		}
		if !hasL2 {
			t.Errorf("Signal L2_PRESENT manquant dans les signaux de rôle. Got signals=%v", roleInfo.Signals)
		}
	})

	// Test 4: Host avec LLDP → doit être "reseau"
	t.Run("LLDP_Triggers_Reseau", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33},
			MACStr:    "aa:bb:cc:11:22:33",
			Protocols: []string{"LLDP"},
			L2Signals: model.L2SignalsInfo{
				LLDP: true,
			},
			LLDP: &model.LLDPInfo{
				SysName: "switch-2",
			},
		}

		roleInfo := InferRole(h)
		if roleInfo.Role != "reseau" {
			t.Errorf("LLDP doit déclencher le rôle 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
	})

	// Test 5: Host avec STP → doit être "reseau"
	t.Run("STP_Triggers_Reseau", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33},
			MACStr:    "bb:cc:dd:11:22:33",
			Protocols: []string{"STP"},
			L2Signals: model.L2SignalsInfo{
				STP: true,
			},
			STP: &model.STPInfo{
				BridgeID: "8000.bbccdd112233",
			},
		}

		roleInfo := InferRole(h)
		if roleInfo.Role != "reseau" {
			t.Errorf("STP doit déclencher le rôle 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
	})

	// Test 6: Host avec 802.1X (EAPOL) → doit être "reseau"
	t.Run("EAPOL_Triggers_Reseau", func(t *testing.T) {
		h := &model.Host{
			MAC:       net.HardwareAddr{0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33},
			MACStr:    "cc:dd:ee:11:22:33",
			Protocols: []string{"802.1X"},
			L2Signals: model.L2SignalsInfo{
				EAPOL: true,
			},
		}

		roleInfo := InferRole(h)
		if roleInfo.Role != "reseau" {
			t.Errorf("802.1X (EAPOL) doit déclencher le rôle 'reseau'. Got role=%s, signals=%v",
				roleInfo.Role, roleInfo.Signals)
		}
	})
}

// E) Tests ciblés pour la nouvelle logique L2 prioritaire et Client vs Serveur

func TestL2BeatsEverything(t *testing.T) {
	// Test avec LLDP
	host := &model.Host{
		L2Signals: model.L2SignalsInfo{
			LLDP: true,
		},
	}
	result := InferRole(host)
	if result.Role != "reseau" {
		t.Fatalf("want reseau, got %s", result.Role)
	}
	if result.Confidence != 100 {
		t.Fatalf("want confidence 100, got %d", result.Confidence)
	}

	// Test avec CDP
	host2 := &model.Host{
		L2Signals: model.L2SignalsInfo{
			CDP: true,
		},
	}
	result2 := InferRole(host2)
	if result2.Role != "reseau" {
		t.Fatalf("want reseau, got %s", result2.Role)
	}

	// Test avec STP
	host3 := &model.Host{
		L2Signals: model.L2SignalsInfo{
			STP: true,
		},
	}
	result3 := InferRole(host3)
	if result3.Role != "reseau" {
		t.Fatalf("want reseau, got %s", result3.Role)
	}

	// Test avec EAPOL
	host4 := &model.Host{
		L2Signals: model.L2SignalsInfo{
			EAPOL: true,
		},
	}
	result4 := InferRole(host4)
	if result4.Role != "reseau" {
		t.Fatalf("want reseau, got %s", result4.Role)
	}
}

func TestClientAppearsOnInitiations(t *testing.T) {
	// Test client avec protocoles d'initiation (sans DHCP car c'est un signal serveur fort)
	host := &model.Host{
		Protocols: []string{"HTTP", "DNS"},
		Services: model.ServicesInfo{
			TCP: []int{}, // Pas de ports serveur
		},
		PacketCount: 10,
	}
	result := InferRole(host)
	if result.Role != "client" {
		t.Fatalf("want client, got %s (signals: %v)", result.Role, result.Signals)
	}
}

func TestServerNeedsServerSignals(t *testing.T) {
	// Test serveur avec signaux serveur spécifiques
	host := &model.Host{
		Protocols: []string{"DHCP", "DNS", "HTTP"},
		Services: model.ServicesInfo{
			TCP: []int{80, 443, 53}, // Ports serveur
		},
	}
	result := InferRole(host)
	if result.Role != "server" {
		t.Fatalf("want server, got %s (signals: %v)", result.Role, result.Signals)
	}
}

func TestServerWithDHCPOnly(t *testing.T) {
	// Test serveur DHCP uniquement
	host := &model.Host{
		Protocols: []string{"DHCP"},
		Services: model.ServicesInfo{
			UDP: []int{67}, // Port DHCP serveur
		},
	}
	result := InferRole(host)
	if result.Role != "server" {
		t.Fatalf("want server for DHCP, got %s", result.Role)
	}
}

func TestClientWithMultipleProtocols(t *testing.T) {
	// Test client avec plusieurs protocoles mais pas de ports serveur
	host := &model.Host{
		Protocols: []string{"HTTP", "DNS", "NTP", "SMB"},
		Services: model.ServicesInfo{
			TCP: []int{}, // Pas de ports serveur
			UDP: []int{}, // Pas de ports serveur
		},
		PacketCount: 5,
	}
	result := InferRole(host)
	if result.Role != "client" {
		t.Fatalf("want client with multiple protocols, got %s", result.Role)
	}
}

func TestTieBreakerReseauWins(t *testing.T) {
	// Test tie-breaker : reseau doit gagner même avec des signaux serveur
	host := &model.Host{
		L2Signals: model.L2SignalsInfo{
			CDP: true, // Signal L2 fort
		},
		Protocols: []string{"DHCP", "DNS"}, // Signaux serveur
		Services: model.ServicesInfo{
			TCP: []int{80, 443},
		},
	}
	result := InferRole(host)
	if result.Role != "reseau" {
		t.Fatalf("want reseau to win over server signals, got %s", result.Role)
	}
	if result.Confidence != 100 {
		t.Fatalf("want confidence 100 for L2, got %d", result.Confidence)
	}
}

func TestServerWinsOverClient(t *testing.T) {
	// Test serveur gagne sur client quand les signaux sont équilibrés
	host := &model.Host{
		Protocols: []string{"HTTP", "DNS", "DHCP"},
		Services: model.ServicesInfo{
			TCP: []int{80, 53}, // Ports serveur
		},
		PacketCount: 3, // Quelques paquets client
	}
	result := InferRole(host)
	if result.Role != "server" {
		t.Fatalf("want server to win over client, got %s", result.Role)
	}
}
