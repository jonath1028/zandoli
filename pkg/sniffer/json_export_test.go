// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

func TestJSONExportWithTrafficStats(t *testing.T) {
	log, err := logger.New("test", &config.Config{})
	stats := NewTrafficStats(log)

	// Créer un hôte avec des statistiques de trafic
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.100")

	// Enregistrer du trafic
	stats.RecordPacket(mac, ip, 1500)
	stats.RecordPacket(mac, ip, 1024)
	stats.RecordPacket(mac, ip, 512)

	// Créer l'hôte et mettre à jour ses statistiques
	host := &model.Host{
		MAC:       mac,
		IP:        ip,
		MACStr:    mac.String(),
		Vendor:    "Test Vendor",
		Protocols: []string{"DHCP", "ARP"},
	}

	stats.UpdateHostWithStats(host)

	// Sérialiser en JSON
	jsonData, err := json.MarshalIndent(host, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal host to JSON: %v", err)
	}

	// Vérifier que les champs de statistiques sont présents
	jsonStr := string(jsonData)
	if !strings.Contains(jsonStr, "packetCount") {
		t.Error("JSON output missing packetCount field")
	}
	if !strings.Contains(jsonStr, "byteCount") {
		t.Error("JSON output missing byteCount field")
	}
	if !strings.Contains(jsonStr, "\"packetCount\": 3") {
		t.Error("JSON output has incorrect packetCount value")
	}
	if !strings.Contains(jsonStr, "\"byteCount\": 3036") {
		t.Error("JSON output has incorrect byteCount value")
	}

	t.Logf("JSON output: %s", jsonStr)
}

func TestMultipleHostsJSONExport(t *testing.T) {
	log, err := logger.New("test", &config.Config{})
	stats := NewTrafficStats(log)

	// Créer plusieurs hôtes avec des statistiques différentes
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	hosts := []*model.Host{
		{
			MAC:       mac1,
			IP:        net.ParseIP("192.168.1.100"),
			MACStr:    "00:11:22:33:44:55",
			Vendor:    "Vendor A",
			Protocols: []string{"DHCP"},
		},
		{
			MAC:       mac2,
			IP:        net.ParseIP("192.168.1.101"),
			MACStr:    "00:11:22:33:44:66",
			Vendor:    "Vendor B",
			Protocols: []string{"ARP", "DHCP"},
		},
	}

	// Enregistrer du trafic différent pour chaque hôte
	stats.RecordPacket(hosts[0].MAC, hosts[0].IP, 1000)
	stats.RecordPacket(hosts[0].MAC, hosts[0].IP, 500)

	stats.RecordPacket(hosts[1].MAC, hosts[1].IP, 2000)
	stats.RecordPacket(hosts[1].MAC, hosts[1].IP, 1500)
	stats.RecordPacket(hosts[1].MAC, hosts[1].IP, 750)

	// Mettre à jour tous les hôtes avec leurs statistiques
	for _, host := range hosts {
		stats.UpdateHostWithStats(host)
	}

	// Sérialiser tous les hôtes en JSON
	jsonData, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal hosts to JSON: %v", err)
	}

	jsonStr := string(jsonData)

	// Vérifier que chaque hôte a ses statistiques
	if !strings.Contains(jsonStr, "\"packetCount\": 2") || !strings.Contains(jsonStr, "\"byteCount\": 1500") {
		t.Error("First host statistics not found in JSON")
	}
	if !strings.Contains(jsonStr, "\"packetCount\": 3") || !strings.Contains(jsonStr, "\"byteCount\": 4250") {
		t.Error("Second host statistics not found in JSON")
	}

	t.Logf("Multiple hosts JSON output: %s", jsonStr)
}
