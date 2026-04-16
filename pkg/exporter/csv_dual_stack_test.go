// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"bytes"
	"encoding/csv"
	"net"
	"strings"
	"testing"
	"time"

	"zandoli/pkg/model"
)

func TestCSVExport_DualStack(t *testing.T) {
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

	// Créer un buffer pour capturer la sortie CSV
	var buf bytes.Buffer

	// Créer un writer CSV temporaire pour tester (délimiteur ';' comme dans ExportCSV)
	writer := csv.NewWriter(&buf)
	writer.Comma = ';' // Utiliser le même délimiteur que l'exporteur
	defer writer.Flush()

	// Écrire les en-têtes
	headers := []string{"IP", "IPv6", "MAC", "Vendor", "Role", "RoleConfidence", "RoleSignals", "Category", "Hostname", "TTLAvg", "OS", "Ports", "VLANs", "Protocols", "FirstSeen", "LastSeen", "Source", "OnlyARP", "Anomalies", "Info", "HasCDP", "HasSTP", "AnomalyCount", "DetectionSource", "IPs"}
	if err := writer.Write(headers); err != nil {
		t.Fatalf("Erreur lors de l'écriture des en-têtes: %v", err)
	}

	// Écrire les données du host
	h := host
	ipStr := ""
	if h.IP != nil {
		ipStr = h.IP.String()
	}

	ipv6Str := ""
	if h.IPv6Primary != nil {
		ipv6Str = h.IPv6Primary.String()
	}

	macStr := ""
	if h.MAC != nil {
		macStr = h.MAC.String()
	}

	// Convertir toutes les IPs en string
	allIPsStr := ""
	if len(h.IPs) > 0 {
		ipStrs := make([]string, len(h.IPs))
		for i, ip := range h.IPs {
			ipStrs[i] = ip.String()
		}
		allIPsStr = strings.Join(ipStrs, ",")
	}

	row := []string{
		ipStr,
		ipv6Str,
		macStr,
		h.Vendor,
		h.Role,
		"0", // RoleConfidence
		"",  // RoleSignals
		h.Category,
		h.Hostname,
		"", // TTLAvg
		h.OSGuess,
		"", // Ports
		"", // VLANs
		strings.Join(h.Protocols, ","),
		h.FirstSeen.Format("2006-01-02 15:04:05"),
		h.LastSeen.Format("2006-01-02 15:04:05"),
		h.Source,
		"false", // OnlyARP
		"",      // Anomalies
		h.Info,
		"no", // HasCDP
		"no", // HasSTP
		"0",  // AnomalyCount
		h.Source,
		allIPsStr,
	}

	if err := writer.Write(row); err != nil {
		t.Fatalf("Erreur lors de l'écriture de la ligne: %v", err)
	}

	writer.Flush()

	// Vérifier le contenu CSV
	csvContent := buf.String()
	lines := strings.Split(strings.TrimSpace(csvContent), "\n")

	if len(lines) != 2 { // En-têtes + 1 ligne de données
		t.Fatalf("CSV contient %d lignes, attendu 2", len(lines))
	}

	// Vérifier les en-têtes (délimiteur ';')
	headerLine := lines[0]
	if !strings.Contains(headerLine, "IP;IPv6") {
		t.Error("Les en-têtes CSV ne contiennent pas 'IP;IPv6' dans le bon ordre")
	}

	// Vérifier les données (délimiteur ';')
	dataLine := lines[1]
	fields := strings.Split(dataLine, ";")

	// Vérifier que les champs IP et IPv6 sont présents et corrects
	if len(fields) < 2 {
		t.Fatalf("Pas assez de champs dans la ligne CSV: %d", len(fields))
	}

	// Le champ IP (premier champ) devrait contenir l'IPv4 principale
	if fields[0] != "10.0.0.1" {
		t.Errorf("Champ IP = %s, attendu 10.0.0.1", fields[0])
	}

	// Le champ IPv6 (deuxième champ) devrait contenir l'IPv6 principale
	if fields[1] != "2001:db8::1" {
		t.Errorf("Champ IPv6 = %s, attendu 2001:db8::1", fields[1])
	}

	// Vérifier que toutes les IPs sont dans le dernier champ
	lastField := fields[len(fields)-1]
	expectedIPs := []string{"192.168.1.100", "10.0.0.1", "2001:db8::1"}
	for _, expectedIP := range expectedIPs {
		if !strings.Contains(lastField, expectedIP) {
			t.Errorf("IP %s manquante dans le champ IPs: %s", expectedIP, lastField)
		}
	}
}

func TestCSVExport_IPv4Only(t *testing.T) {
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	host.AddIP(net.ParseIP("192.168.1.100"))

	// Tester la logique de conversion
	ipStr := ""
	if host.IP != nil {
		ipStr = host.IP.String()
	}

	ipv6Str := ""
	if host.IPv6Primary != nil {
		ipv6Str = host.IPv6Primary.String()
	}

	// Vérifier les valeurs
	if ipStr != "192.168.1.100" {
		t.Errorf("ipStr = %s, attendu 192.168.1.100", ipStr)
	}

	if ipv6Str != "" {
		t.Errorf("ipv6Str devrait être vide pour un host IPv4-only, reçu: %s", ipv6Str)
	}
}

func TestCSVExport_IPv6Only(t *testing.T) {
	host := &model.Host{
		MACStr:    "aa:bb:cc:dd:ee:ff",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		IPs:       []net.IP{},
	}

	host.AddIP(net.ParseIP("2001:db8::1"))

	// Tester la logique de conversion
	ipStr := ""
	if host.IP != nil {
		ipStr = host.IP.String()
	}

	ipv6Str := ""
	if host.IPv6Primary != nil {
		ipv6Str = host.IPv6Primary.String()
	}

	// Vérifier les valeurs
	if ipStr != "" {
		t.Errorf("ipStr devrait être vide pour un host IPv6-only, reçu: %s", ipStr)
	}

	if ipv6Str != "2001:db8::1" {
		t.Errorf("ipv6Str = %s, attendu 2001:db8::1", ipv6Str)
	}
}
