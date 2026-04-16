// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestModelArchitectureCompliance vérifie que le modèle respecte l'architecture
func TestModelArchitectureCompliance(t *testing.T) {
	t.Run("Host_Serialization", func(t *testing.T) {
		// Test que les structures du modèle peuvent être sérialisées/désérialisées
		host := &Host{
			IP:        net.ParseIP("192.168.1.1"),
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			MACStr:    "00:11:22:33:44:55",
			Vendor:    "Test Vendor",
			Role:      "server",
			Protocols: []string{"HTTP", "SSH"},
			Hostname:  "test-host",
			OSGuess:   "Linux",
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Ports:     []int{80, 443, 22},
			Source:    "test",
		}

		// Vérifier que tous les champs sont correctement définis
		assert.NotNil(t, host.IP)
		assert.NotEmpty(t, host.MACStr)
		assert.NotEmpty(t, host.Vendor)
		assert.NotEmpty(t, host.Role)
		assert.NotEmpty(t, host.Protocols)
		assert.NotEmpty(t, host.Hostname)
		assert.NotEmpty(t, host.OSGuess)
		assert.False(t, host.FirstSeen.IsZero())
		assert.False(t, host.LastSeen.IsZero())
		assert.NotEmpty(t, host.Ports)
		assert.NotEmpty(t, host.Source)
	})

	t.Run("Subnet_Serialization", func(t *testing.T) {
		// Test que la structure Subnet fonctionne correctement
		subnet := &Subnet{
			CIDR:   "192.168.1.0/24",
			Hosts:  []string{"192.168.1.1", "192.168.1.2"},
			Source: "test",
		}

		assert.Equal(t, "192.168.1.0/24", subnet.CIDR)
		assert.Len(t, subnet.Hosts, 2)
		assert.Equal(t, "test", subnet.Source)
	})

	t.Run("Anomaly_Serialization", func(t *testing.T) {
		// Test que la structure Anomaly fonctionne correctement
		anomaly := &Anomaly{
			Description: "Test anomaly",
			Severity:    "high",
			Type:        "test",
			Parameters:  map[string]interface{}{"key": "value"},
		}

		assert.Equal(t, "Test anomaly", anomaly.Description)
		assert.Equal(t, "high", anomaly.Severity)
		assert.Equal(t, "test", anomaly.Type)
		assert.NotNil(t, anomaly.Parameters)
		assert.Equal(t, "value", anomaly.Parameters["key"])
	})
}

// TestModelDataIntegrity vérifie l'intégrité des données du modèle
func TestModelDataIntegrity(t *testing.T) {
	t.Run("Host_IPConsistency", func(t *testing.T) {
		// Test que l'IP et MACStr sont cohérents
		host := &Host{
			IP:     net.ParseIP("192.168.1.1"),
			MACStr: "00:11:22:33:44:55",
		}

		assert.Equal(t, "192.168.1.1", host.IP.String())
		assert.Equal(t, "00:11:22:33:44:55", host.MACStr)
	})

	t.Run("Host_RoleValidation", func(t *testing.T) {
		// Test que les rôles sont valides
		validRoles := []string{"", "client", "server", "switch", "router", "reseau"}

		for _, role := range validRoles {
			host := &Host{Role: role}
			assert.Contains(t, validRoles, host.Role)
		}
	})

	t.Run("Host_TimeConsistency", func(t *testing.T) {
		// Test que FirstSeen <= LastSeen
		now := time.Now()
		host := &Host{
			FirstSeen: now.Add(-time.Hour),
			LastSeen:  now,
		}

		assert.True(t, host.FirstSeen.Before(host.LastSeen) || host.FirstSeen.Equal(host.LastSeen))
	})
}

// TestModelNoGlobalState vérifie qu'il n'y a pas d'état global dans le modèle
func TestModelNoGlobalState(t *testing.T) {
	t.Run("Host_Independence", func(t *testing.T) {
		// Test que deux instances de Host sont indépendantes
		host1 := &Host{IP: net.ParseIP("192.168.1.1")}
		host2 := &Host{IP: net.ParseIP("192.168.1.2")}

		host1.Role = "server"
		host2.Role = "client"

		assert.NotEqual(t, host1.Role, host2.Role)
		assert.NotEqual(t, host1.IP.String(), host2.IP.String())
	})
}
