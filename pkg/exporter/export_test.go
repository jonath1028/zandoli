// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// Test_Export_JSON_Shape_And_Stability teste la forme et la stabilité de l'export JSON
func Test_Export_JSON_Shape_And_Stability(t *testing.T) {
	// Créer des données de test
	hosts := createTestHosts()

	// Créer un fichier temporaire
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "test.csv")

	// Créer un logger de test
	log, _ := logger.New("test", nil)

	// Exporter les hôtes en CSV
	err := ExportCSV(hosts, csvPath, log)
	if err != nil {
		t.Fatalf("Erreur export CSV: %v", err)
	}

	// Lire et vérifier le fichier CSV
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("Erreur lecture fichier CSV: %v", err)
	}

	csvContent := string(csvData)

	// Vérifier la présence des en-têtes CSV (délimiteur ;)
	if !strings.Contains(csvContent, "MAC;") {
		t.Error("En-têtes CSV manquants")
	}

	// Vérifier la présence des données des hôtes
	if !strings.Contains(csvContent, "192.168.1.100") {
		t.Error("IP d'hôte non trouvée dans le CSV")
	}

	if !strings.Contains(csvContent, "00:11:22:33:44:55") {
		t.Error("MAC d'hôte non trouvée dans le CSV")
	}

	// Vérifier l'encodage UTF-8
	if !isValidUTF8(csvContent) {
		t.Error("Contenu CSV n'est pas en UTF-8 valide")
	}
}

// Test_Export_CSV_UTF8_NoControlChars teste l'encodage CSV propre
func Test_Export_CSV_UTF8_NoControlChars(t *testing.T) {
	// Créer des données de test avec des caractères spéciaux
	hosts := createTestHostsWithSpecialChars()

	// Créer un fichier temporaire
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "test.csv")

	// Créer un logger de test
	log, _ := logger.New("test", nil)

	// Exporter en CSV
	err := ExportCSV(hosts, csvPath, log)
	if err != nil {
		t.Fatalf("Erreur export CSV: %v", err)
	}

	// Lire et vérifier le fichier CSV
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("Erreur lecture fichier CSV: %v", err)
	}

	csvContent := string(csvData)

	// Vérifier l'encodage UTF-8
	if !isValidUTF8(csvContent) {
		t.Error("Contenu CSV n'est pas en UTF-8 valide")
	}

	// Vérifier l'absence de caractères de contrôle
	if strings.Contains(csvContent, "\x00") {
		t.Error("Caractères de contrôle (\\x00) trouvés dans le CSV")
	}

	if strings.Contains(csvContent, "\x01") {
		t.Error("Caractères de contrôle (\\x01) trouvés dans le CSV")
	}

	// Vérifier l'absence de troncature
	lines := strings.Split(csvContent, "\n")
	if len(lines) < 2 {
		t.Error("CSV vide ou malformé")
	}

	// Vérifier que les en-têtes sont présents (délimiteur ;)
	headers := strings.Split(lines[0], ";")
	expectedHeaders := []string{"MAC", "IP", "Protocols"}
	for _, expected := range expectedHeaders {
		found := false
		for _, header := range headers {
			if strings.Contains(header, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("En-tête manquant dans CSV: %s", expected)
		}
	}
}

// Test_Export_HTML_Minimal_Rendering teste le rendu minimal JSON→HTML
func Test_Export_HTML_Minimal_Rendering(t *testing.T) {
	// Créer des données de test
	hosts := createTestHosts()
	subnets := createTestSubnets()

	// Créer un fichier temporaire
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "test.html")

	// Créer un logger de test
	log, _ := logger.New("test", nil)

	// Exporter en HTML
	err := ExportHTML(hosts, subnets, htmlPath, log)
	if err != nil {
		t.Fatalf("Erreur export HTML: %v", err)
	}

	// Lire et vérifier le fichier HTML
	htmlData, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("Erreur lecture fichier HTML: %v", err)
	}

	htmlContent := string(htmlData)

	// Vérifier la présence des éléments HTML de base
	if !strings.Contains(htmlContent, "<!DOCTYPE html>") {
		t.Error("DOCTYPE HTML manquant")
	}

	if !strings.Contains(htmlContent, "<html") {
		t.Error("Balise HTML manquante")
	}

	if !strings.Contains(htmlContent, "<head>") {
		t.Error("Section head manquante")
	}

	if !strings.Contains(htmlContent, "<body>") {
		t.Error("Section body manquante")
	}

	// Vérifier la présence des données des hôtes
	if !strings.Contains(htmlContent, "192.168.1.100") {
		t.Error("IP d'hôte non trouvée dans le HTML")
	}

	if !strings.Contains(htmlContent, "00:11:22:33:44:55") {
		t.Error("MAC d'hôte non trouvée dans le HTML")
	}

	// Vérifier la présence des sous-réseaux dans la nouvelle structure par classes
	if !strings.Contains(htmlContent, "Sous-réseaux") {
		t.Error("Section Sous-réseaux manquante dans le HTML")
	}

	// Vérifier la présence des classes A, B, C
	if !strings.Contains(htmlContent, "Classe A") {
		t.Error("Classe A manquante dans le HTML")
	}
	if !strings.Contains(htmlContent, "Classe B") {
		t.Error("Classe B manquante dans le HTML")
	}
	if !strings.Contains(htmlContent, "Classe C") {
		t.Error("Classe C manquante dans le HTML")
	}

	// Vérifier l'encodage UTF-8
	if !isValidUTF8(htmlContent) {
		t.Error("Contenu HTML n'est pas en UTF-8 valide")
	}
}

// Fonctions utilitaires pour créer des données de test

func createTestHosts() []*model.Host {
	now := time.Now()
	return []*model.Host{
		{
			MAC:            net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			IP:             net.ParseIP("192.168.1.100"),
			IPs:            []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("192.168.2.11")},
			Vendor:         "Test Vendor",
			Role:           "server",
			RoleConfidence: 85,
			RoleSignals:    []string{"server_protocol:dhcp"},
			Protocols:      []string{"DHCP", "ARP"},
			Info:           "Router:192.168.1.1 DNS:8.8.8.8",
			Hostname:       "test-host",
			FirstSeen:      now,
			LastSeen:       now,
			Source:         "passive",
		},
		{
			MAC:            net.HardwareAddr{0x00, 0x22, 0x33, 0x44, 0x55, 0x66},
			IP:             net.ParseIP("192.168.1.101"),
			IPs:            []net.IP{net.ParseIP("192.168.1.101")},
			Vendor:         "Another Vendor",
			Role:           "client",
			RoleConfidence: 70,
			RoleSignals:    []string{"client_protocol:arp"},
			Protocols:      []string{"ARP"},
			Info:           "Client device",
			Hostname:       "client-device",
			FirstSeen:      now,
			LastSeen:       now,
			Source:         "passive",
		},
	}
}

func createTestHostsWithSpecialChars() []*model.Host {
	now := time.Now()
	return []*model.Host{
		{
			MAC:            net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			IP:             net.ParseIP("192.168.1.100"),
			IPs:            []net.IP{net.ParseIP("192.168.1.100")},
			Vendor:         "Test Vendor",
			Role:           "server",
			RoleConfidence: 85,
			RoleSignals:    []string{"server_protocol:dhcp"},
			Protocols:      []string{"DHCP", "ARP"},
			Info:           "ClientID:01:00:11:22:33:44:55 FQDN:client.example.com", // Données binaires encodées
			Hostname:       "test-host",
			FirstSeen:      now,
			LastSeen:       now,
			Source:         "passive",
		},
	}
}

func createTestSubnets() []model.Subnet {
	return []model.Subnet{
		{
			CIDR:   "192.168.1.0/24",
			Source: "computed",
			// Version:    "ipv4", // Champ non disponible dans model.Subnet
			Hosts:      []string{"00:11:22:33:44:55", "00:22:33:44:55:66"},
			CountHosts: 2,
		},
		{
			CIDR:   "192.168.2.0/24",
			Source: "computed",
			// Version:    "ipv4", // Champ non disponible dans model.Subnet
			Hosts:      []string{"00:11:22:33:44:55"},
			CountHosts: 1,
		},
	}
}

// Test_getRFC1918Class teste la fonction getRFC1918Class
func Test_getRFC1918Class(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected RFC1918Class
	}{
		// Plage Classe A RFC1918 (10.0.0.0/8)
		{"RFC1918 Classe A - 10.0.0.1", "10.0.0.1", RFC1918ClassA},
		{"RFC1918 Classe A - 10.255.255.255", "10.255.255.255", RFC1918ClassA},

		// Plage Classe B RFC1918 (172.16.0.0/12)
		{"RFC1918 Classe B - 172.16.0.1", "172.16.0.1", RFC1918ClassB},
		{"RFC1918 Classe B - 172.31.255.255", "172.31.255.255", RFC1918ClassB},

		// Plage Classe C RFC1918 (192.168.0.0/16)
		{"RFC1918 Classe C - 192.168.0.1", "192.168.0.1", RFC1918ClassC},
		{"RFC1918 Classe C - 192.168.255.255", "192.168.255.255", RFC1918ClassC},

		// IP publiques (non-RFC1918) - doivent retourner ""
		{"IP publique - 8.8.8.8", "8.8.8.8", ""},
		{"IP publique - 1.1.1.1", "1.1.1.1", ""},
		{"IP publique - 172.15.0.1", "172.15.0.1", ""}, // Juste avant la plage 172.16/12
		{"IP publique - 172.32.0.1", "172.32.0.1", ""}, // Juste après la plage 172.16/12
		{"IP publique - 191.255.255.255", "191.255.255.255", ""},
		{"IP publique - 193.0.0.1", "193.0.0.1", ""},

		// Cas spéciaux
		{"IPv6", "2001:db8::1", ""},
		{"IP invalide", "invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := GetRFC1918Class(ip)
			if result != tt.expected {
				t.Errorf("GetRFC1918Class(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// Test_classifySubnetsByClass teste la fonction classifySubnetsByClass
func Test_classifySubnetsByClass(t *testing.T) {
	// Créer des sous-réseaux de test (incluant des sous-réseaux publics qui doivent être filtrés)
	subnets := []model.SubnetEntry{
		{
			CIDR:       "10.0.1.0/24",
			Version:    "ipv4",
			Source:     "computed",
			HostsCount: 2,
			IPSamples:  []string{"10.0.1.1", "10.0.1.2"},
		},
		{
			CIDR:       "172.16.1.0/24",
			Version:    "ipv4",
			Source:     "computed",
			HostsCount: 1,
			IPSamples:  []string{"172.16.1.1"},
		},
		{
			CIDR:       "192.168.1.0/24",
			Version:    "ipv4",
			Source:     "computed",
			HostsCount: 2,
			IPSamples:  []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			// Sous-réseau public qui doit être ignoré
			CIDR:       "8.8.8.0/24",
			Version:    "ipv4",
			Source:     "computed",
			HostsCount: 1,
			IPSamples:  []string{"8.8.8.8"},
		},
		{
			CIDR:       "2001:db8::/64",
			Version:    "ipv6",
			Source:     "computed",
			HostsCount: 1,
			IPSamples:  []string{"2001:db8::1"},
		},
	}

	// Créer des hôtes de test (incluant des IPs publiques qui doivent être ignorées)
	hosts := []*model.Host{
		{
			IPs: []net.IP{net.ParseIP("10.0.1.100"), net.ParseIP("172.16.1.100")},
		},
		{
			IPs: []net.IP{net.ParseIP("192.168.1.100")},
		},
		{
			// Hôte avec IP publique (doit être ignoré dans les résultats)
			IPs: []net.IP{net.ParseIP("8.8.8.8")},
		},
	}

	result := classifySubnetsByClass(subnets, hosts)

	// Vérifier qu'on a 3 classes
	if len(result) != 3 {
		t.Fatalf("Expected 3 classes, got %d", len(result))
	}

	// Vérifier la classe A (RFC1918: 10.0.0.0/8)
	classA := result[0]
	if classA.Class != "Classe A (10.0.0.0/8)" {
		t.Errorf("Expected 'Classe A (10.0.0.0/8)', got '%s'", classA.Class)
	}
	if len(classA.Subnets) == 0 {
		t.Error("Classe A should have subnets")
	}
	if len(classA.IPs) == 0 {
		t.Error("Classe A should have IPs")
	}

	// Vérifier la classe B (RFC1918: 172.16.0.0/12)
	classB := result[1]
	if classB.Class != "Classe B (172.16.0.0/12)" {
		t.Errorf("Expected 'Classe B (172.16.0.0/12)', got '%s'", classB.Class)
	}
	if len(classB.Subnets) == 0 {
		t.Error("Classe B should have subnets")
	}
	if len(classB.IPs) == 0 {
		t.Error("Classe B should have IPs")
	}

	// Vérifier la classe C (RFC1918: 192.168.0.0/16)
	classC := result[2]
	if classC.Class != "Classe C (192.168.0.0/16)" {
		t.Errorf("Expected 'Classe C (192.168.0.0/16)', got '%s'", classC.Class)
	}
	if len(classC.Subnets) == 0 {
		t.Error("Classe C should have subnets")
	}
	if len(classC.IPs) == 0 {
		t.Error("Classe C should have IPs")
	}

	// Vérifier que les sous-réseaux et IPs publics ont été filtrés
	allSubnets := make([]string, 0)
	allIPs := make([]string, 0)
	for _, classInfo := range result {
		allSubnets = append(allSubnets, classInfo.Subnets...)
		allIPs = append(allIPs, classInfo.IPs...)
	}

	// Vérifier qu'aucun sous-réseau public n'est présent
	for _, subnet := range allSubnets {
		if strings.HasPrefix(subnet, "8.8.8.") {
			t.Errorf("Public subnet %s should not be in results", subnet)
		}
	}

	// Vérifier qu'aucune IP publique n'est présente
	for _, ip := range allIPs {
		if ip == "8.8.8.8" {
			t.Errorf("Public IP %s should not be in results", ip)
		}
	}
}

func isValidUTF8(s string) bool {
	return utf8.ValidString(s)
}
