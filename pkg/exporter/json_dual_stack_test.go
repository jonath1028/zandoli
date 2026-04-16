// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"
)

func TestJSONExport_DualStack(t *testing.T) {
	// Créer un host dual-stack
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Vendor:    "Test Vendor",
		Role:      "client",
		Protocols: []string{"ARP", "DHCP"},
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	// Ajouter des IPs multiples
	host.AddIP(net.ParseIP("192.168.1.100"))
	host.AddIP(net.ParseIP("2001:db8::1"))
	host.AddIP(net.ParseIP("10.0.0.1"))
	host.AddIP(net.ParseIP("fe80::1")) // Link-local (ne devrait pas être primaire)

	// Convertir en JSONHost
	jsonHost := convertToJSONHost(host)

	// Vérifier les champs principaux
	if jsonHost.IP != "10.0.0.1" { // Dernière IPv4 ajoutée
		t.Errorf("JSONHost.IP = %s, attendu 10.0.0.1", jsonHost.IP)
	}

	if jsonHost.IPv6 != "2001:db8::1" { // IPv6 principale (pas link-local)
		t.Errorf("JSONHost.IPv6 = %s, attendu 2001:db8::1", jsonHost.IPv6)
	}

	// Vérifier que toutes les IPs sont présentes dans la liste
	if len(jsonHost.IPs) != 4 {
		t.Errorf("JSONHost.IPs contient %d éléments, attendu 4", len(jsonHost.IPs))
	}

	// Vérifier que les IPs sont présentes
	ipsMap := make(map[string]bool)
	for _, ip := range jsonHost.IPs {
		ipsMap[ip] = true
	}

	expectedIPs := []string{"192.168.1.100", "2001:db8::1", "10.0.0.1", "fe80::1"}
	for _, expectedIP := range expectedIPs {
		if !ipsMap[expectedIP] {
			t.Errorf("IP %s manquante dans JSONHost.IPs", expectedIP)
		}
	}

	// Tester la sérialisation JSON
	jsonData, err := json.Marshal(jsonHost)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation JSON: %v", err)
	}

	// Vérifier que le JSON contient les bons champs
	jsonStr := string(jsonData)
	if !contains(jsonStr, `"ip":"10.0.0.1"`) {
		t.Error("JSON ne contient pas le champ 'ip' avec la bonne valeur")
	}
	if !contains(jsonStr, `"ipv6":"2001:db8::1"`) {
		t.Error("JSON ne contient pas le champ 'ipv6' avec la bonne valeur")
	}
	if !contains(jsonStr, `"ips":`) {
		t.Error("JSON ne contient pas le champ 'ips'")
	}
}

func TestJSONExport_IPv4Only(t *testing.T) {
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	host.AddIP(net.ParseIP("192.168.1.100"))

	jsonHost := convertToJSONHost(host)

	// Vérifier que seul le champ IPv4 est rempli
	if jsonHost.IP != "192.168.1.100" {
		t.Errorf("JSONHost.IP = %s, attendu 192.168.1.100", jsonHost.IP)
	}

	if jsonHost.IPv6 != "" {
		t.Errorf("JSONHost.IPv6 devrait être vide pour un host IPv4-only, reçu: %s", jsonHost.IPv6)
	}

	if len(jsonHost.IPs) != 1 {
		t.Errorf("JSONHost.IPs contient %d éléments, attendu 1", len(jsonHost.IPs))
	}
}

func TestJSONExport_IPv6Only(t *testing.T) {
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	host.AddIP(net.ParseIP("2001:db8::1"))

	jsonHost := convertToJSONHost(host)

	// Vérifier que seul le champ IPv6 est rempli
	if jsonHost.IP != "" {
		t.Errorf("JSONHost.IP devrait être vide pour un host IPv6-only, reçu: %s", jsonHost.IP)
	}

	if jsonHost.IPv6 != "2001:db8::1" {
		t.Errorf("JSONHost.IPv6 = %s, attendu 2001:db8::1", jsonHost.IPv6)
	}

	if len(jsonHost.IPs) != 1 {
		t.Errorf("JSONHost.IPs contient %d éléments, attendu 1", len(jsonHost.IPs))
	}
}

func TestJSONExport_LinkLocalExcludedFromPrimary(t *testing.T) {
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	// Ajouter seulement une IPv6 link-local
	host.AddIP(net.ParseIP("fe80::1"))

	jsonHost := convertToJSONHost(host)

	// Vérifier que l'IPv6 link-local n'est pas sélectionnée comme primaire
	if jsonHost.IPv6 != "" {
		t.Errorf("JSONHost.IPv6 devrait être vide pour une IPv6 link-local, reçu: %s", jsonHost.IPv6)
	}

	// Mais elle devrait être dans la liste des IPs
	if len(jsonHost.IPs) != 1 {
		t.Errorf("JSONHost.IPs contient %d éléments, attendu 1", len(jsonHost.IPs))
	}

	if jsonHost.IPs[0] != "fe80::1" {
		t.Errorf("JSONHost.IPs[0] = %s, attendu fe80::1", jsonHost.IPs[0])
	}
}

// Fonction utilitaire pour vérifier si une chaîne contient une sous-chaîne
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
