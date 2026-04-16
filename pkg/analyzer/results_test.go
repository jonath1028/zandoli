// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"slices"
	"testing"

	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestDetectAnomalies_IPDuplicate(t *testing.T) {
	aggregator := NewAggregator()

	// Créer deux hôtes avec la même IP mais des MAC différentes
	mac1 := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	mac2 := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02}
	ip := net.ParseIP("192.168.1.100")

	record1 := &ParsedRecord{
		MAC:       mac1,
		IP:        ip,
		Protocols: []string{"DHCP"},
		Source:    "passive",
	}

	record2 := &ParsedRecord{
		MAC:       mac2,
		IP:        ip,
		Protocols: []string{"DHCP"},
		Source:    "passive",
	}

	aggregator.Merge(record1)
	aggregator.Merge(record2)
	aggregator.DetectAnomalies()

	hosts := aggregator.GetAll()
	assert.Equal(t, 2, len(hosts))

	// Vérifier que les deux hôtes ont l'anomalie "IP duplicate"
	hasAnomaly := false
	for _, host := range hosts {
		if slices.ContainsFunc(host.Anomalies, func(a model.Anomaly) bool {
			return a.Type == "ip_duplicate" || a.Description == "IP duplicate"
		}) {
			hasAnomaly = true
			break
		}
	}

	if !hasAnomaly {
		t.Errorf("Expected at least one host to have ip_duplicate anomaly. Hosts: %+v", hosts)
		for i, host := range hosts {
			t.Logf("Host %d: MAC=%s, IP=%v, Anomalies=%+v", i, host.MACStr, host.IP, host.Anomalies)
		}
	}
}

func TestDetectAnomalies_MACMultipleIP(t *testing.T) {
	aggregator := NewAggregator()

	// Créer un hôte avec plusieurs IP
	mac := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")

	record1 := &ParsedRecord{
		MAC:       mac,
		IP:        ip1,
		Protocols: []string{"DHCP"},
		Source:    "passive",
	}

	record2 := &ParsedRecord{
		MAC:       mac,
		IP:        ip2,
		Protocols: []string{"DHCP"},
		Source:    "passive",
	}

	aggregator.Merge(record1)
	aggregator.Merge(record2)
	aggregator.DetectAnomalies()

	hosts := aggregator.GetAll()
	assert.Equal(t, 1, len(hosts))

	// Vérifier que l'hôte a l'anomalie "MAC multiple IP"
	assert.True(t, slices.ContainsFunc(hosts[0].Anomalies, func(a model.Anomaly) bool {
		return a.Type == "mac_multiple_ip" || a.Description == "MAC multiple IP"
	}))
}

func TestDetectAnomalies_SilentHost(t *testing.T) {
	aggregator := NewAggregator()

	// Créer un hôte OnlyARP sans protocole ni port
	mac := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	ip := net.ParseIP("192.168.1.100")

	record := &ParsedRecord{
		MAC:     mac,
		IP:      ip,
		OnlyARP: true,
		Source:  "active",
	}

	aggregator.Merge(record)
	aggregator.DetectAnomalies()

	hosts := aggregator.GetAll()
	assert.Equal(t, 1, len(hosts))

	// Vérifier que l'hôte a l'anomalie "silent host"
	assert.True(t, slices.ContainsFunc(hosts[0].Anomalies, func(a model.Anomaly) bool {
		return a.Type == "silent_host" || a.Description == "silent host"
	}))
}

func TestDetectAnomalies_NoAnomalies(t *testing.T) {
	aggregator := NewAggregator()

	// Créer un hôte normal avec protocole et port
	mac := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	ip := net.ParseIP("192.168.1.100")

	record := &ParsedRecord{
		MAC:       mac,
		IP:        ip,
		Protocols: []string{"DHCP"},
		Ports:     []int{80, 443},
		Source:    "passive",
	}

	aggregator.Merge(record)
	aggregator.DetectAnomalies()

	hosts := aggregator.GetAll()
	assert.Equal(t, 1, len(hosts))

	// Vérifier qu'il n'y a pas d'anomalies
	assert.Empty(t, hosts[0].Anomalies)
}
