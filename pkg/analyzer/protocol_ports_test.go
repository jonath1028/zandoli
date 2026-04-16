// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestAddProtocolPorts(t *testing.T) {
	tests := []struct {
		name          string
		protocols     []string
		expectedPorts []int
	}{
		{
			name:          "MDNS protocol should add port 5353",
			protocols:     []string{"MDNS"},
			expectedPorts: []int{5353},
		},
		{
			name:          "SSDP protocol should add port 1900",
			protocols:     []string{"SSDP"},
			expectedPorts: []int{1900},
		},
		{
			name:          "LLMNR protocol should add port 5355",
			protocols:     []string{"LLMNR"},
			expectedPorts: []int{5355},
		},
		{
			name:          "NBNS protocol should add port 137",
			protocols:     []string{"NBNS"},
			expectedPorts: []int{137},
		},
		{
			name:          "DHCP protocol should add port 67",
			protocols:     []string{"DHCP"},
			expectedPorts: []int{67},
		},
		{
			name:          "Multiple protocols should add multiple ports",
			protocols:     []string{"MDNS", "SSDP", "LLMNR"},
			expectedPorts: []int{5353, 1900, 5355},
		},
		{
			name:          "Unknown protocol should not add ports",
			protocols:     []string{"UNKNOWN"},
			expectedPorts: []int{},
		},
		{
			name:          "Empty protocols should not add ports",
			protocols:     []string{},
			expectedPorts: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Créer un ParsedRecord de test
			srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
			pkt := model.PacketEvent{
				SrcMAC:    srcMAC,
				Timestamp: time.Now(),
			}

			record := NewParsedRecord(pkt)
			record.Protocols = tt.protocols
			record.Ports = []int{} // Initialiser vide

			// Appeler la fonction à tester
			addProtocolPorts(record)

			// Vérifier que les ports attendus sont présents
			assert.Equal(t, len(tt.expectedPorts), len(record.Ports), "Nombre de ports incorrect")

			for _, expectedPort := range tt.expectedPorts {
				assert.Contains(t, record.Ports, expectedPort, "Port %d devrait être présent", expectedPort)
			}
		})
	}
}

// DISABLED: Methods getProtocolTransport and mergeTransportInfo removed from simplified aggregator
/*
func TestGetProtocolTransport(t *testing.T) {
	agg := NewAggregator()

	tests := []struct {
		name              string
		protocols         []string
		port              int
		expectedTransport string
	}{
		{
			name:              "MDNS port 5353 should be UDP",
			protocols:         []string{"MDNS"},
			port:              5353,
			expectedTransport: "udp",
		},
		{
			name:              "SSDP port 1900 should be UDP",
			protocols:         []string{"SSDP"},
			port:              1900,
			expectedTransport: "udp",
		},
		{
			name:              "Unknown port should default to UDP",
			protocols:         []string{"UNKNOWN"},
			port:              9999,
			expectedTransport: "udp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := agg.getProtocolTransport(tt.protocols, tt.port)
			assert.Equal(t, tt.expectedTransport, transport)
		})
	}
}

func TestMergeTransportInfoWithProtocolPorts(t *testing.T) {
	// Créer un host de test
	host := &model.Host{
		Services: model.ServicesInfo{
			TCP: []int{},
			UDP: []int{},
		},
	}

	// Créer un ParsedRecord avec des protocoles connus
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Timestamp: time.Now(),
	}

	record := NewParsedRecord(pkt)
	record.Protocols = []string{"MDNS", "SSDP"}
	record.Ports = []int{5353, 1900} // Ports des protocoles connus
	record.Transport = "udp"
	record.DstPort = 5353

	// Créer un agrégateur et appeler mergeTransportInfo
	agg := NewAggregator()
	agg.mergeTransportInfo(host, record)

	// Vérifier que les ports UDP sont correctement ajoutés
	assert.Contains(t, host.Services.UDP, 5353, "Port mDNS 5353 devrait être dans UDP")
	assert.Contains(t, host.Services.UDP, 1900, "Port SSDP 1900 devrait être dans UDP")
	assert.Empty(t, host.Services.TCP, "Aucun port TCP ne devrait être ajouté")
}
*/
