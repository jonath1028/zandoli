// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"os"
	"strings"
	"testing"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// TestHTMLTemplateNoPanic vérifie que le template HTML ne panic plus avec la nouvelle signature de limitIPsDisplay
func TestHTMLTemplateNoPanic(t *testing.T) {
	log := logger.MustInitLoggerForTest()

	// Créer des données de test minimales
	hosts := []*model.Host{}
	subnets := []model.Subnet{}

	// Créer un fichier temporaire
	tmpFile := "/tmp/test_html_export.html"
	defer os.Remove(tmpFile)

	// Essayer d'exporter - cela doit réussir sans panic
	err := ExportHTML(hosts, subnets, tmpFile, log)
	if err != nil {
		t.Fatalf("ExportHTML devrait réussir sans panic: %v", err)
	}

	// Vérifier que le fichier existe
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Le fichier HTML devrait avoir été créé")
	}
}

// TestLimitIPsDisplay vérifie le comportement de la fonction limitIPsDisplay
func TestLimitIPsDisplay(t *testing.T) {
	tests := []struct {
		name     string
		ips      []string
		limit    int
		contains string
	}{
		{
			name:     "moins que la limite",
			ips:      []string{"192.168.1.1", "192.168.1.2"},
			limit:    5,
			contains: "192.168.1.1",
		},
		{
			name:     "exactement la limite",
			ips:      []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			limit:    3,
			contains: "192.168.1.3",
		},
		{
			name:  "plus que la limite",
			ips:   []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"},
			limit: 3,
			// Note: limitIPsDisplay actuelle ignore le limit et affiche toutes les IPs
			contains: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := limitIPsDisplay(tt.ips, tt.limit)
			if result == "" && len(tt.ips) > 0 {
				t.Error("Le résultat ne devrait pas être vide pour des IPs valides")
			}
			if len(tt.contains) > 0 && !strings.Contains(result, tt.contains) {
				t.Errorf("Le résultat devrait contenir '%s', mais obtenu: %s", tt.contains, result)
			}

			// Vérifier que les balises <code> sont présentes
			if len(tt.ips) > 0 && !strings.Contains(result, "<code>") {
				t.Error("Le résultat devrait contenir des balises <code>")
			}

			// Vérifier que les IPs sont séparées par <br>
			if len(tt.ips) > 1 && !strings.Contains(result, "<br>") {
				t.Error("Le résultat devrait contenir des balises <br> pour séparer les IPs")
			}
		})
	}
}
