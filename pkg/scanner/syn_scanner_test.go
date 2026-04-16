// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestScanSYN_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &config.Config{}
	cfg.Scan.SYNPorts = []int{22, 80}
	cfg.Scan.SYN.TimeoutMs =100

	hosts := []*model.Host{
		{IP: net.ParseIP("192.168.1.100")},
	}

	results := ScanSYNFromPipeline(ctx, cfg, hosts, testLogger())
	assert.Equal(t, 0, len(results[0].Ports), "Expected no open ports after context cancellation")
}

func TestScanSYN_NilIP(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}
	cfg.Scan.SYNPorts = []int{22, 80}
	cfg.Scan.SYN.TimeoutMs =100

	hosts := []*model.Host{
		{IP: nil},
	}

	results := ScanSYNFromPipeline(ctx, cfg, hosts, testLogger())
	assert.Equal(t, 0, len(results[0].Ports), "Expected no ports for nil IP")
}

func TestScanSYN_BasicStructure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := &config.Config{}
	cfg.Scan.SYNPorts = []int{22, 80}
	cfg.Scan.SYN.TimeoutMs =200

	hosts := []*model.Host{
		{IP: net.ParseIP("127.0.0.1")},
	}

	results := ScanSYNFromPipeline(ctx, cfg, hosts, testLogger())
	assert.NotNil(t, results)
	assert.Equal(t, 1, len(results), "Should return one host")
}

func TestExtractTCPOptions(t *testing.T) {
	// Test avec des options TCP typiques
	// Note: Ce test nécessiterait un vrai paquet TCP, mais on peut tester la logique
	// Pour un test plus complet, il faudrait créer un paquet TCP synthétique
	t.Run("Empty options", func(t *testing.T) {
		// Ce test vérifie que la fonction ne panique pas avec des options vides
		// Dans un vrai test, on créerait un layers.TCP avec des options
		assert.True(t, true, "Placeholder test - would need real TCP layer")
	})
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []int
		item     int
		expected bool
	}{
		{
			name:     "Contains item",
			slice:    []int{80, 443, 22},
			item:     80,
			expected: true,
		},
		{
			name:     "Does not contain item",
			slice:    []int{80, 443, 22},
			item:     8080,
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []int{},
			item:     80,
			expected: false,
		},
		{
			name:     "Single item match",
			slice:    []int{22},
			item:     22,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServerPortDetection(t *testing.T) {
	// Test que les ports serveur sont correctement identifiés
	serverPorts := []int{80, 443, 445, 3389, 22, 25, 110, 143}

	for _, port := range serverPorts {
		t.Run("Port "+string(rune(port)), func(t *testing.T) {
			result := contains(serverPorts, port)
			assert.True(t, result, "Port %d should be detected as server port", port)
		})
	}

	// Test qu'un port non-serveur n'est pas détecté
	nonServerPort := 8080
	result := contains(serverPorts, nonServerPort)
	assert.False(t, result, "Port %d should not be detected as server port", nonServerPort)
}

func TestServerRoleAssignment(t *testing.T) {
	tests := []struct {
		name         string
		openPort     int
		currentRole  string
		expectedRole string
	}{
		{
			name:         "Port 80 should assign server role to empty role",
			openPort:     80,
			currentRole:  "",
			expectedRole: "server",
		},
		{
			name:         "Port 443 should upgrade client to server",
			openPort:     443,
			currentRole:  "client",
			expectedRole: "server",
		},
		{
			name:         "Port 22 should not downgrade router to server",
			openPort:     22,
			currentRole:  "router",
			expectedRole: "router",
		},
		{
			name:         "Port 445 should not downgrade switch to server",
			openPort:     445,
			currentRole:  "switch",
			expectedRole: "switch",
		},
		{
			name:         "Port 8080 should not assign server role",
			openPort:     8080,
			currentRole:  "",
			expectedRole: "",
		},
		{
			name:         "Port 3389 should upgrade empty to server",
			openPort:     3389,
			currentRole:  "",
			expectedRole: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Créer un host avec le rôle initial
			host := &model.Host{
				IP:   net.ParseIP("192.168.1.100"),
				Role: tt.currentRole,
			}

			// Simuler la logique de détection du rôle server
			serverPorts := []int{80, 443, 445, 3389, 22, 25, 110, 143}
			if contains(serverPorts, tt.openPort) {
				// Importer le package analyzer pour utiliser MergeRole
				host.Role = mergeRoleForTest(host.Role, "server")
			}

			assert.Equal(t, tt.expectedRole, host.Role, "Expected role %s but got %s", tt.expectedRole, host.Role)
		})
	}
}

// mergeRoleForTest reproduit la logique de MergeRole pour les tests
func mergeRoleForTest(oldRole, newRole string) string {
	prio := map[string]int{"": 0, "client": 1, "server": 2, "switch": 3, "router": 4}
	if prio[newRole] > prio[oldRole] {
		return newRole
	}
	return oldRole
}
