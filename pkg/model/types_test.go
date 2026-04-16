// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestHost_AddPort(t *testing.T) {
	host := &Host{
		IP:    net.ParseIP("192.168.1.1"),
		MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Ports: []int{80, 443},
	}

	// Test ajout d'un port existant (ne doit pas dupliquer)
	host.AddPort(80)
	if len(host.Ports) != 2 {
		t.Errorf("Expected 2 ports after adding existing port, got %d", len(host.Ports))
	}

	// Test ajout d'un nouveau port
	host.AddPort(22)
	if len(host.Ports) != 3 {
		t.Errorf("Expected 3 ports after adding new port, got %d", len(host.Ports))
	}

	// Vérifier que le port 22 a été ajouté
	found := false
	for _, port := range host.Ports {
		if port == 22 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected port 22 to be added")
	}

	// Test ajout de plusieurs ports
	host.AddPort(8080)
	host.AddPort(9090)
	if len(host.Ports) != 5 {
		t.Errorf("Expected 5 ports after adding more ports, got %d", len(host.Ports))
	}
}

func TestHost_JSONSerialization(t *testing.T) {
	now := time.Now()
	host := &Host{
		IP:         net.ParseIP("192.168.1.100"),
		MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MACStr:     "00:11:22:33:44:55",
		Vendor:     "TestVendor",
		Role:       "reseau",
		Protocols:  []string{"CDP", "LLDP"},
		Info:       "DeviceID:Switch1 PortID:Gi0/1",
		TTL:        64,
		OSGuess:    "Cisco IOS",
		OSScore:    85,
		WindowSize: 8192,
		TCPOpts:    []string{"MSS", "SACK", "Timestamp"},
		FirstSeen:  now,
		LastSeen:   now.Add(5 * time.Minute),
		Anomalies: []Anomaly{
			{Type: string(AnomSuspiciousTTL), Description: string(AnomSuspiciousTTL)},
			{Type: "odd_timing", Description: "odd_timing"},
		},
		Ports:    []int{22, 80, 443, 8080},
		Source:   "combined",
		OnlyARP:  false,
		TTLAvg:   64,
		Category: "network_device",
	}

	// Test sérialisation JSON
	jsonData, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("Failed to marshal host to JSON: %v", err)
	}

	// Test désérialisation JSON
	var host2 Host
	err = json.Unmarshal(jsonData, &host2)
	if err != nil {
		t.Fatalf("Failed to unmarshal host from JSON: %v", err)
	}

	// Vérifier que les champs sont correctement sérialisés/désérialisés
	if !host2.IP.Equal(host.IP) {
		t.Errorf("Expected IP %v, got %v", host.IP, host2.IP)
	}
	if host2.MACStr != host.MACStr {
		t.Errorf("Expected MACStr %s, got %s", host.MACStr, host2.MACStr)
	}
	if host2.Vendor != host.Vendor {
		t.Errorf("Expected Vendor %s, got %s", host.Vendor, host2.Vendor)
	}
	if host2.Role != host.Role {
		t.Errorf("Expected Role %s, got %s", host.Role, host2.Role)
	}
	if len(host2.Protocols) != len(host.Protocols) {
		t.Errorf("Expected %d protocols, got %d", len(host.Protocols), len(host2.Protocols))
	}
	if host2.Info != host.Info {
		t.Errorf("Expected Info %s, got %s", host.Info, host2.Info)
	}
	if host2.TTL != host.TTL {
		t.Errorf("Expected TTL %d, got %d", host.TTL, host2.TTL)
	}
	if host2.OSGuess != host.OSGuess {
		t.Errorf("Expected OSGuess %s, got %s", host.OSGuess, host2.OSGuess)
	}
	if host2.WindowSize != host.WindowSize {
		t.Errorf("Expected WindowSize %d, got %d", host.WindowSize, host2.WindowSize)
	}
	if len(host2.TCPOpts) != len(host.TCPOpts) {
		t.Errorf("Expected %d TCPOpts, got %d", len(host.TCPOpts), len(host2.TCPOpts))
	}
	if !host2.FirstSeen.Equal(host.FirstSeen) {
		t.Errorf("Expected FirstSeen %v, got %v", host.FirstSeen, host2.FirstSeen)
	}
	if !host2.LastSeen.Equal(host.LastSeen) {
		t.Errorf("Expected LastSeen %v, got %v", host.LastSeen, host2.LastSeen)
	}
	if len(host2.Anomalies) != len(host.Anomalies) {
		t.Errorf("Expected %d Anomalies, got %d", len(host.Anomalies), len(host2.Anomalies))
	}
	if len(host2.Ports) != len(host.Ports) {
		t.Errorf("Expected %d Ports, got %d", len(host.Ports), len(host2.Ports))
	}
	if host2.Source != host.Source {
		t.Errorf("Expected Source %s, got %s", host.Source, host2.Source)
	}
	if host2.OnlyARP != host.OnlyARP {
		t.Errorf("Expected OnlyARP %v, got %v", host.OnlyARP, host2.OnlyARP)
	}
	if host2.TTLAvg != host.TTLAvg {
		t.Errorf("Expected TTLAvg %d, got %d", host.TTLAvg, host2.TTLAvg)
	}
	if host2.Category != host.Category {
		t.Errorf("Expected Category %s, got %s", host.Category, host2.Category)
	}
}

func TestPacketEvent_Creation(t *testing.T) {
	now := time.Now()
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	pe := PacketEvent{
		Timestamp: now,
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		Payload:   payload,
		PacketID:  "test-packet-001",
		TTL:       64,
	}

	// Vérifier les champs
	if !pe.Timestamp.Equal(now) {
		t.Errorf("Expected timestamp %v, got %v", now, pe.Timestamp)
	}
	if pe.SrcMAC.String() != srcMAC.String() {
		t.Errorf("Expected SrcMAC %v, got %v", srcMAC, pe.SrcMAC)
	}
	if pe.DstMAC.String() != dstMAC.String() {
		t.Errorf("Expected DstMAC %v, got %v", dstMAC, pe.DstMAC)
	}
	if len(pe.Payload) != len(payload) {
		t.Errorf("Expected payload length %d, got %d", len(payload), len(pe.Payload))
	}
	if pe.PacketID != "test-packet-001" {
		t.Errorf("Expected PacketID 'test-packet-001', got '%s'", pe.PacketID)
	}
	if pe.TTL != 64 {
		t.Errorf("Expected TTL 64, got %d", pe.TTL)
	}
}

func TestSubnet_Creation(t *testing.T) {
	subnet := Subnet{
		CIDR:   "192.168.1.0/24",
		Source: "ARP",
		Hosts:  []string{"192.168.1.1", "192.168.1.100", "192.168.1.200"},
	}

	// Vérifier les champs
	if subnet.CIDR != "192.168.1.0/24" {
		t.Errorf("Expected CIDR '192.168.1.0/24', got '%s'", subnet.CIDR)
	}
	if subnet.Source != "ARP" {
		t.Errorf("Expected Source 'ARP', got '%s'", subnet.Source)
	}
	if len(subnet.Hosts) != 3 {
		t.Errorf("Expected 3 hosts, got %d", len(subnet.Hosts))
	}

	// Vérifier les hôtes
	expectedHosts := []string{"192.168.1.1", "192.168.1.100", "192.168.1.200"}
	for i, expected := range expectedHosts {
		if subnet.Hosts[i] != expected {
			t.Errorf("Expected host %d '%s', got '%s'", i, expected, subnet.Hosts[i])
		}
	}
}

func TestSubnet_JSONSerialization(t *testing.T) {
	subnet := Subnet{
		CIDR:   "10.0.0.0/8",
		Source: "DHCP",
		Hosts:  []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
	}

	// Test sérialisation JSON
	jsonData, err := json.Marshal(subnet)
	if err != nil {
		t.Fatalf("Failed to marshal subnet to JSON: %v", err)
	}

	// Test désérialisation JSON
	var subnet2 Subnet
	err = json.Unmarshal(jsonData, &subnet2)
	if err != nil {
		t.Fatalf("Failed to unmarshal subnet from JSON: %v", err)
	}

	// Vérifier que les champs sont correctement sérialisés/désérialisés
	if subnet2.CIDR != subnet.CIDR {
		t.Errorf("Expected CIDR %s, got %s", subnet.CIDR, subnet2.CIDR)
	}
	if subnet2.Source != subnet.Source {
		t.Errorf("Expected Source %s, got %s", subnet.Source, subnet2.Source)
	}
	if len(subnet2.Hosts) != len(subnet.Hosts) {
		t.Errorf("Expected %d hosts, got %d", len(subnet.Hosts), len(subnet2.Hosts))
	}
}

func TestHost_EmptyFields(t *testing.T) {
	// Test avec des champs vides
	host := &Host{}

	// Test AddPort avec un host sans ports
	host.AddPort(80)
	if len(host.Ports) != 1 {
		t.Errorf("Expected 1 port after adding to empty host, got %d", len(host.Ports))
	}
	if host.Ports[0] != 80 {
		t.Errorf("Expected port 80, got %d", host.Ports[0])
	}

	// Test JSON avec des champs vides
	jsonData, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("Failed to marshal empty host to JSON: %v", err)
	}

	var host2 Host
	err = json.Unmarshal(jsonData, &host2)
	if err != nil {
		t.Fatalf("Failed to unmarshal empty host from JSON: %v", err)
	}

	if len(host2.Ports) != 1 {
		t.Errorf("Expected 1 port after JSON roundtrip, got %d", len(host2.Ports))
	}
}

func TestHost_ComplexData(t *testing.T) {
	// Test avec des données complexes
	host := &Host{
		IP:         net.ParseIP("fe80::1"),
		MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MACStr:     "00:11:22:33:44:55",
		Vendor:     "Cisco Systems",
		Role:       "reseau",
		Protocols:  []string{"CDP", "LLDP", "STP", "VTP"},
		Info:       "DeviceID:Switch-01 PortID:GigabitEthernet0/1 Platform:WS-C2960-24TC-L",
		TTL:        255,
		OSGuess:    "Cisco IOS 15.1",
		OSScore:    90,
		WindowSize: 65535,
		TCPOpts:    []string{"MSS", "SACK", "Timestamp", "Window Scale", "NOP"},
		FirstSeen:  time.Now().Add(-1 * time.Hour),
		LastSeen:   time.Now(),
		Anomalies: []Anomaly{
			{Type: string(AnomSuspiciousTTL), Description: string(AnomSuspiciousTTL)},
			{Type: "odd_timing", Description: "odd_timing"},
			{Type: string(AnomUnusualPorts), Description: string(AnomUnusualPorts)},
		},
		Ports:    []int{22, 23, 80, 443, 161, 162, 514, 8080, 8443},
		Source:   "combined",
		OnlyARP:  false,
		TTLAvg:   64,
		Category: "network_device",
	}

	// Test sérialisation JSON avec des données complexes
	jsonData, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("Failed to marshal complex host to JSON: %v", err)
	}

	// Vérifier que le JSON contient les données attendues
	jsonStr := string(jsonData)
	if !contains(jsonStr, "Cisco Systems") {
		t.Error("Expected JSON to contain vendor name")
	}
	if !contains(jsonStr, "reseau") {
		t.Error("Expected JSON to contain role")
	}
	if !contains(jsonStr, "CDP") {
		t.Error("Expected JSON to contain protocols")
	}
	if !contains(jsonStr, "Switch-01") {
		t.Error("Expected JSON to contain device info")
	}
}

// Fonction utilitaire pour vérifier si une chaîne contient une sous-chaîne
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHost_CategorizePorts(t *testing.T) {
	host := &Host{
		Ports: []int{80, 443, 53, 1900, 22, 67, 123},
	}

	host.CategorizePorts()

	// Validation UDP
	expectedUDP := []int{53, 67, 123, 1900}
	if len(host.Services.UDP) != len(expectedUDP) {
		t.Errorf("Expected %d UDP ports, got %d", len(expectedUDP), len(host.Services.UDP))
	}
	for i, expected := range expectedUDP {
		if i < len(host.Services.UDP) && host.Services.UDP[i] != expected {
			t.Errorf("Expected UDP port %d at index %d, got %d", expected, i, host.Services.UDP[i])
		}
	}

	// Validation TCP (everything else)
	expectedTCP := []int{22, 80, 443}
	if len(host.Services.TCP) != len(expectedTCP) {
		t.Errorf("Expected %d TCP ports, got %d", len(expectedTCP), len(host.Services.TCP))
	}
	for i, expected := range expectedTCP {
		if i < len(host.Services.TCP) && host.Services.TCP[i] != expected {
			t.Errorf("Expected TCP port %d at index %d, got %d", expected, i, host.Services.TCP[i])
		}
	}
}
