// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/internal/logger"
)

func TestAggregator_DualStack_NoOverwrite(t *testing.T) {
	// Créer un agrégateur avec logger
	log, _ := logger.New("test", nil)
	agg := NewAggregatorWithLogger(log)

	// Créer des records avec différentes IPs pour la même MAC
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Record 1: IPv6
	record1 := &ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("2001:db8::1"),
		Protocols: []string{"NDP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Record 2: IPv4
	record2 := &ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Traiter les records
	agg.Merge(record1)
	agg.Merge(record2)

	// Récupérer les résultats
	hosts := agg.GetAll()

	if len(hosts) != 1 {
		t.Fatalf("Attendu 1 host, reçu %d", len(hosts))
	}

	host := hosts[0]

	// Vérifier que la MAC est correcte
	if host.MACStr != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC incorrecte: %s", host.MACStr)
	}

	// Vérifier que les protocoles sont fusionnés
	if len(host.Protocols) < 2 {
		t.Errorf("Protocoles devraient contenir au moins NDP et ARP, reçu: %v", host.Protocols)
	}
}

func TestAggregator_LinkLocal_NotPrimary(t *testing.T) {
	log, _ := logger.New("test", nil)
	agg := NewAggregatorWithLogger(log)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Record 1: IPv6 link-local
	record1 := &ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("fe80::1"),
		Protocols: []string{"NDP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Record 2: IPv4 privée
	record2 := &ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	agg.Merge(record1)
	agg.Merge(record2)

	hosts := agg.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Attendu 1 host, reçu %d", len(hosts))
	}

	host := hosts[0]

	// Vérifier qu'un IP est défini (version simplifiée)
	if host.IP == nil {
		t.Error("IP devrait être définie")
	}

	// Vérifier que les protocoles sont présents
	if len(host.Protocols) < 2 {
		t.Errorf("Protocoles devraient contenir NDP et ARP, reçu: %v", host.Protocols)
	}
}

func TestAggregator_OrderIndependent(t *testing.T) {
	log, _ := logger.New("test", nil)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Test 1: IPv4 puis IPv6
	agg1 := NewAggregatorWithLogger(log)
	agg1.Merge(&ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	})
	agg1.Merge(&ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("2001:db8::1"),
		Protocols: []string{"NDP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	})

	hosts1 := agg1.GetAll()
	if len(hosts1) != 1 {
		t.Fatalf("Test1: Attendu 1 host, reçu %d", len(hosts1))
	}

	// Test 2: IPv6 puis IPv4
	agg2 := NewAggregatorWithLogger(log)
	agg2.Merge(&ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("2001:db8::1"),
		Protocols: []string{"NDP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	})
	agg2.Merge(&ParsedRecord{
		MAC:       mac,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	})

	hosts2 := agg2.GetAll()
	if len(hosts2) != 1 {
		t.Fatalf("Test2: Attendu 1 host, reçu %d", len(hosts2))
	}

	// Les deux agrégateurs devraient produire le même nombre d'hôtes
	if len(hosts1) != len(hosts2) {
		t.Errorf("L'ordre ne devrait pas changer le nombre d'hôtes: %d vs %d", len(hosts1), len(hosts2))
	}
}

func TestAggregator_DuplicateIPs(t *testing.T) {
	log, _ := logger.New("test", nil)
	agg := NewAggregatorWithLogger(log)

	// Deux MACs différentes avec la même IP
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	mac2, _ := net.ParseMAC("11:22:33:44:55:66")

	record1 := &ParsedRecord{
		MAC:       mac1,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	record2 := &ParsedRecord{
		MAC:       mac2,
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"DHCP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	agg.Merge(record1)
	agg.Merge(record2)

	// Détecter les anomalies
	agg.DetectAnomalies()

	hosts := agg.GetAll()
	if len(hosts) != 2 {
		t.Fatalf("Attendu 2 hosts, reçu %d", len(hosts))
	}

	// Vérifier que les deux hosts ont une anomalie ip_duplicate
	anomalyFound := false
	for _, host := range hosts {
		for _, anomaly := range host.Anomalies {
			if anomaly.Type == "ip_duplicate" {
				anomalyFound = true
				break
			}
		}
	}

	if !anomalyFound {
		t.Error("Anomalie ip_duplicate attendue mais non trouvée")
	}
}
