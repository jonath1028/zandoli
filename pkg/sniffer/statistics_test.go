// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"net"
	"testing"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

func TestTrafficStats(t *testing.T) {
	log, err := logger.New("test", &config.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	stats := NewTrafficStats(log)

	// Test avec adresse MAC
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	ip1 := net.ParseIP("192.168.1.100")

	// Test avec adresse IP seulement
	ip2 := net.ParseIP("192.168.1.101")

	// Enregistrer des paquets
	stats.RecordPacket(mac1, ip1, 1500)
	stats.RecordPacket(mac1, ip1, 1024)
	stats.RecordPacket(nil, ip2, 512)

	// Vérifier les statistiques
	packets1, bytes1 := stats.GetStats(mac1, ip1)
	if packets1 != 2 {
		t.Errorf("Expected 2 packets for host 1, got %d", packets1)
	}
	if bytes1 != 2524 {
		t.Errorf("Expected 2524 bytes for host 1, got %d", bytes1)
	}

	packets2, bytes2 := stats.GetStats(nil, ip2)
	if packets2 != 1 {
		t.Errorf("Expected 1 packet for host 2, got %d", packets2)
	}
	if bytes2 != 512 {
		t.Errorf("Expected 512 bytes for host 2, got %d", bytes2)
	}

	// Test des statistiques totales
	totalPackets, totalBytes, hostCount := stats.GetTotalStats()
	if totalPackets != 3 {
		t.Errorf("Expected 3 total packets, got %d", totalPackets)
	}
	if totalBytes != 3036 {
		t.Errorf("Expected 3036 total bytes, got %d", totalBytes)
	}
	if hostCount != 2 {
		t.Errorf("Expected 2 tracked hosts, got %d", hostCount)
	}
}

func TestUpdateHostWithStats(t *testing.T) {
	log, err := logger.New("test", &config.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	stats := NewTrafficStats(log)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.100")

	// Enregistrer du trafic
	stats.RecordPacket(mac, ip, 1000)
	stats.RecordPacket(mac, ip, 500)

	// Créer un hôte et mettre à jour ses statistiques
	host := &model.Host{
		MAC: mac,
		IP:  ip,
	}

	stats.UpdateHostWithStats(host)

	if host.PacketCount != 2 {
		t.Errorf("Expected 2 packets, got %d", host.PacketCount)
	}
	if host.ByteCount != 1500 {
		t.Errorf("Expected 1500 bytes, got %d", host.ByteCount)
	}
}

func TestGetHostKey(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.100")

	// Test avec MAC
	key1 := GetHostKey(mac, ip)
	if key1 != "00:11:22:33:44:55" {
		t.Errorf("Expected MAC key, got %s", key1)
	}

	// Test avec IP seulement
	key2 := GetHostKey(nil, ip)
	if key2 != "192.168.1.100" {
		t.Errorf("Expected IP key, got %s", key2)
	}

	// Test avec aucune adresse
	key3 := GetHostKey(nil, nil)
	if key3 != "" {
		t.Errorf("Expected empty key, got %s", key3)
	}
}

func TestConcurrentAccess(t *testing.T) {
	log, err := logger.New("test", &config.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	stats := NewTrafficStats(log)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.100")

	// Test d'accès concurrent
	done := make(chan bool, 10)

	// Lancer 10 goroutines qui écrivent simultanément
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				stats.RecordPacket(mac, ip, 100)
			}
			done <- true
		}()
	}

	// Attendre que toutes les goroutines se terminent
	for i := 0; i < 10; i++ {
		<-done
	}

	// Vérifier le résultat final
	packets, bytes := stats.GetStats(mac, ip)
	expectedPackets := uint64(1000)
	expectedBytes := uint64(100000)

	if packets != expectedPackets {
		t.Errorf("Expected %d packets, got %d", expectedPackets, packets)
	}
	if bytes != expectedBytes {
		t.Errorf("Expected %d bytes, got %d", expectedBytes, bytes)
	}
}
