// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter_test

import (
	"strings"
	"testing"

	"zandoli/pkg/exporter"
	"zandoli/pkg/model"
)

// TestRenderL2Summary teste la fonction RenderL2Summary avec les nouveaux détails L2
func TestRenderL2Summary(t *testing.T) {
	tests := []struct {
		name     string
		host     model.Host
		expected string
	}{
		{
			name: "Aucun signal L2",
			host: model.Host{
				MACStr:    "aa:bb:cc:12:34:56",
				L2Signals: model.L2SignalsInfo{},
			},
			expected: "—",
		},
		{
			name: "EAPOL seulement",
			host: model.Host{
				MACStr:    "00:11:22:33:44:55",
				Protocols: []string{"EAPOL"},
			},
			expected: "🟢 <strong>802.1X</strong> (EAPOL)",
		},
		{
			name: "CDP avec détails",
			host: model.Host{
				MACStr: "00:11:22:12:34:56",
				CDP: &model.CDPInfo{
					DeviceID:    "Switch-Core-01",
					Platform:    "Catalyst 2960",
					Version:     "v15.2(4)S6",
					PortID:      "Gi0/1",
					NativeVLAN:  10,
					DecodedCaps: []string{"Router", "Switch"},
				},
			},
			expected: "🟡 <strong>CDP</strong><br>└─ <code>Switch-Core-01</code><br>└─ Catalyst 2960<br>└─ v15.2(4)S6<br>└─ Port: <code>Gi0/1</code><br>└─ Native VLAN: 10",
		},
		{
			name: "LLDP avec détails",
			host: model.Host{
				MACStr: "00:11:22:33:44:66",
				LLDP: &model.LLDPInfo{
					ChassisID:    "00:11:22:33:44:55",
					SysName:      "Chassis-01",
					SysDescr:     "Cisco IOS Software, C2960",
					PortID:       "Gi0/24",
					Capabilities: []string{"Bridge", "Router"},
				},
			},
			expected: "🔵 <strong>LLDP</strong><br>└─ Chassis: <code>00:11:22:33:44:55</code><br>└─ Chassis-01<br>└─ Cisco IOS Software, C2960<br>└─ Port: <code>Gi0/24</code><br>└─ Caps: Bridge, Router",
		},
		{
			name: "STP avec détails",
			host: model.Host{
				MACStr: "00:11:22:33:44:77",
				STP: &model.STPInfo{
					BridgeID:     "32768.aa:bb:cc:dd:ee:ff",
					RootBridgeID: "32768.11:22:33:44:55:66",
					PortID:       128,
					RootPathCost: 200000,
					HelloTime:    256, // 1 seconde
					IsRoot:       false,
				},
			},
			expected: "🔴 <strong>STP</strong><br>└─ Bridge: <code>32768.aa:bb:cc:dd:ee:ff</code><br>└─ Root: <code>32768.11:22:33:44:55:66</code><br>└─ Port: 128<br>└─ Cost: 200000<br>└─ Hello: 1.0s",
		},
		{
			name: "STP Root Bridge",
			host: model.Host{
				MACStr: "00:11:22:33:44:88",
				STP: &model.STPInfo{
					BridgeID:     "32768.aa:bb:cc:dd:ee:ff",
					RootBridgeID: "32768.aa:bb:cc:dd:ee:ff",
					IsRoot:       true,
				},
			},
			expected: "🔴 <strong>STP</strong><br>└─ Bridge: <code>32768.aa:bb:cc:dd:ee:ff</code><br>└─ Root Bridge: <code>32768.aa:bb:cc:dd:ee:ff</code> <em>(this device)</em>",
		},
		{
			name: "VLANs avec primary",
			host: model.Host{
				MACStr:      "00:11:22:33:44:99",
				VLANs:       []int{10, 20, 30},
				PrimaryVLAN: 20,
			},
			expected: "⚪ <strong>VLANs</strong><br>└─ Primary: <code>20</code><br>└─ All: 10, 20, 30",
		},
		{
			name: "Combinaison complète",
			host: model.Host{
				MACStr:    "00:11:22:33:44:aa",
				Protocols: []string{"EAPOL"},
				CDP: &model.CDPInfo{
					DeviceID: "Switch-01",
					Platform: "Catalyst 2960",
				},
				VLANs:       []int{10, 20},
				PrimaryVLAN: 10,
			},
			expected: "🟡 <strong>CDP</strong><br>└─ <code>Switch-01</code><br>└─ Catalyst 2960<br><br>🟢 <strong>802.1X</strong> (EAPOL)<br><br>⚪ <strong>VLANs</strong><br>└─ Primary: <code>10</code><br>└─ All: 10, 20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := exporter.RenderL2Summary(tt.host)
			if result != tt.expected {
				t.Errorf("RenderL2Summary() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestRenderVLANCell teste la fonction renderVLANCell
func TestRenderVLANCell(t *testing.T) {
	tests := []struct {
		name     string
		host     model.Host
		expected string
	}{
		{
			name: "VLANStats vide",
			host: model.Host{
				VLANStats: map[int]int{},
			},
			expected: "—",
		},
		{
			name: "Un seul VLAN",
			host: model.Host{
				VLANStats: map[int]int{
					10: 124,
				},
			},
			expected: "10: 124 frames",
		},
		{
			name: "Plusieurs VLANs",
			host: model.Host{
				VLANStats: map[int]int{
					20: 3,
					10: 124,
					30: 1,
				},
			},
			expected: "10: 124 frames, 20: 3 frames, 30: 1 frames",
		},
		{
			name: "VLANStats nil",
			host: model.Host{
				VLANStats: nil,
			},
			expected: "—",
		},
		{
			name: "VLANs avec zéro frames",
			host: model.Host{
				VLANStats: map[int]int{
					10: 0,
					20: 5,
				},
			},
			expected: "10: 0 frames, 20: 5 frames",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := exporter.RenderVLANCell(tt.host)
			if result != tt.expected {
				t.Errorf("renderVLANCell() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestRenderVLANCellIntegration teste l'intégration avec des données réelles
func TestRenderVLANCellIntegration(t *testing.T) {
	// Test avec des VLANs typiques
	host := model.Host{
		VLANStats: map[int]int{
			10: 124,
			20: 3,
		},
	}

	result := exporter.RenderVLANCell(host)
	expected := "10: 124 frames, 20: 3 frames"

	if result != expected {
		t.Errorf("renderVLANCell() = %q, want %q", result, expected)
	}

	// Vérifier que tous les éléments attendus sont présents
	if !strings.Contains(result, "10:") {
		t.Error("Expected VLAN 10 not found in result")
	}
	if !strings.Contains(result, "124") {
		t.Error("Expected frame count 124 not found in result")
	}
	if !strings.Contains(result, "20:") {
		t.Error("Expected VLAN 20 not found in result")
	}
	if !strings.Contains(result, "3") {
		t.Error("Expected frame count 3 not found in result")
	}
}
