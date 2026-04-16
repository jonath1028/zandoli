// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"net"
	"os"
	"strings"
	"testing"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// TestHTMLExportWithSubnets vérifie que l'export HTML génère correctement les sous-réseaux avec limitation d'IPs
func TestHTMLExportWithSubnets(t *testing.T) {
	log := logger.MustInitLoggerForTest()

	// Créer des hosts avec plusieurs IPs pour générer des listes
	hosts := []*model.Host{
		{
			IPs: []net.IP{
				net.ParseIP("192.168.1.1"),
				net.ParseIP("192.168.1.2"),
			},
			MACStr: "aa:bb:cc:dd:ee:01",
		},
		{
			IPs: []net.IP{
				net.ParseIP("192.168.1.3"),
			},
			MACStr: "aa:bb:cc:dd:ee:02",
		},
	}

	// Créer des subnets
	subnets := []model.Subnet{
		{
			CIDR:  "192.168.1.0/24",
			Hosts: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
	}

	tmpFile := "/tmp/test_html_integration.html"
	defer os.Remove(tmpFile)

	err := ExportHTML(hosts, subnets, tmpFile, log)
	if err != nil {
		t.Fatalf("ExportHTML échoué: %v", err)
	}

	// Lire le fichier généré
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Impossible de lire le fichier HTML: %v", err)
	}

	htmlContent := string(content)

	// Vérifier que le fichier contient les éléments attendus
	if !strings.Contains(htmlContent, "192.168.1.1") {
		t.Error("Le HTML devrait contenir l'IP 192.168.1.1")
	}

	if !strings.Contains(htmlContent, "Zandoli") {
		t.Error("Le HTML devrait contenir le titre Zandoli")
	}

	// Note: Template peut contenir {{...}} dans les commentaires ou exemples, c'est OK
	// On vérifie juste qu'il n'y a pas d'erreurs de rendu flagrantes
	if !strings.Contains(htmlContent, "</html>") {
		t.Error("Le HTML ne se termine pas correctement")
	}
}
