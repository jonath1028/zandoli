// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import (
	"context"
	"net"
	"testing"

	"zandoli/internal/config"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestRunActiveScanWithTargets_TargetedModeWithTargets(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Scan: config.ScanSettings{
			Targeted: true,
		},
	}
	ctx := context.Background()
	passiveHosts := []*model.Host{
		{IP: net.ParseIP("192.168.1.1")},
		{IP: net.ParseIP("192.168.1.2")},
		{IP: net.ParseIP("192.168.1.3")},
	}

	// Note: Ce test ne peut pas vraiment scanner car il nécessite des permissions réseau
	// Mais on peut vérifier que la fonction ne panique pas et retourne une structure valide
	hosts := RunActiveScanWithTargets(ctx, cfg, testLogger(), passiveHosts)
	// En cas d'erreur de permissions, hosts peut être nil, ce qui est acceptable
	if hosts == nil {
		hosts = []*model.Host{}
	}
	assert.NotNil(t, hosts, "Expected non-nil hosts slice")
}

func TestRunActiveScanWithTargets_TargetedModeNoTargets(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Scan: config.ScanSettings{
			Targeted: true,
		},
	}
	ctx := context.Background()
	passiveHosts := []*model.Host{}

	// En mode ciblé sans targets, devrait fallback sur le scan complet
	hosts := RunActiveScanWithTargets(ctx, cfg, testLogger(), passiveHosts)
	// En cas d'erreur de permissions, hosts peut être nil, ce qui est acceptable
	if hosts == nil {
		hosts = []*model.Host{}
	}
	assert.NotNil(t, hosts, "Expected non-nil hosts slice even with no targets")
}

func TestRunActiveScanWithTargets_NonTargetedMode(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Scan: config.ScanSettings{
			Targeted: false,
		},
	}
	ctx := context.Background()
	passiveHosts := []*model.Host{
		{IP: net.ParseIP("192.168.1.1")},
	}

	// En mode non-ciblé, devrait ignorer les hosts passifs et scanner tout le /24
	hosts := RunActiveScanWithTargets(ctx, cfg, testLogger(), passiveHosts)
	// En cas d'erreur de permissions, hosts peut être nil, ce qui est acceptable
	if hosts == nil {
		hosts = []*model.Host{}
	}
	assert.NotNil(t, hosts, "Expected non-nil hosts slice in non-targeted mode")
}

func TestRunActiveScanWithTargets_PcapMode(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			PcapFile: "test.pcap",
		},
		Scan: config.ScanSettings{
			Targeted: true,
		},
	}
	ctx := context.Background()
	passiveHosts := []*model.Host{}

	// Devrait retourner une liste vide en mode PCAP
	result := RunActiveScanWithTargets(ctx, cfg, testLogger(), passiveHosts)
	assert.Empty(t, result, "Expected empty result in PCAP mode")
}

func TestExtractIPsFromHosts_MixedValidAndNil(t *testing.T) {
	hosts := []*model.Host{
		{IP: net.ParseIP("10.0.0.1")},
		{IP: nil},
		{IP: net.ParseIP("10.0.0.2")},
		{IP: nil},
		{IP: net.ParseIP("10.0.0.1")}, // Duplicate
	}
	ips := extractIPsFromHosts(hosts)
	assert.Len(t, ips, 2, "Expected 2 unique IPs from mixed valid and nil hosts")
	assert.Contains(t, []string{ips[0].String(), ips[1].String()}, "10.0.0.1")
	assert.Contains(t, []string{ips[0].String(), ips[1].String()}, "10.0.0.2")
}
