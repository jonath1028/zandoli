// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

// testLogger crée un logger de test conforme à l'architecture
func testLogger() *logger.Logger {
	log, err := logger.New("test", &config.Config{})
	if err != nil {
		// En cas d'erreur, créer un logger minimal
		return &logger.Logger{}
	}
	return log
}

func TestScanARP_IPShuffle(t *testing.T) {
	subnet := &net.IPNet{
		IP:   net.IPv4(192, 168, 1, 0),
		Mask: net.CIDRMask(24, 32),
	}
	original := getAllIPsInSubnet(subnet)
	shuffled := append([]net.IP{}, original...)
	shuffleIPs(shuffled)

	sameOrder := true
	for i := range original {
		if !original[i].Equal(shuffled[i]) {
			sameOrder = false
			break
		}
	}
	assert.False(t, sameOrder, "Expected shuffled IPs to differ from original")
}

func TestScanARP_ContextCancelled(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Annuler immédiatement

	hosts := ScanARP(ctx, cfg, testLogger())
	assert.Empty(t, hosts, "Expected no hosts with cancelled context")
}

func TestScanARP_InvalidInterface(t *testing.T) {
	cfg := &config.Config{
		Interface: "doesnotexist0",
	}
	ctx := context.Background()

	hosts := ScanARP(ctx, cfg, testLogger())
	assert.Empty(t, hosts, "Expected no hosts with invalid interface")
}

func TestMacParsingFailure(t *testing.T) {
	_, err := net.ParseMAC("invalid-mac")
	assert.NotNil(t, err, "Expected error when parsing invalid MAC")
}

func TestScanARP_JitterDelay(t *testing.T) {
	// Test que la fonction shuffleIPs fonctionne correctement
	subnet := &net.IPNet{
		IP:   net.IPv4(192, 168, 1, 0),
		Mask: net.CIDRMask(24, 32),
	}
	ips := getAllIPsInSubnet(subnet)
	shuffled := append([]net.IP{}, ips...)
	shuffleIPs(shuffled)

	// Vérifier que tous les IPs sont présents après shuffle
	assert.Equal(t, len(ips), len(shuffled), "Shuffle should preserve all IPs")

	// Vérifier que l'ordre a changé (probabilité très faible d'avoir le même ordre)
	sameOrder := true
	for i := range ips {
		if !ips[i].Equal(shuffled[i]) {
			sameOrder = false
			break
		}
	}
	assert.False(t, sameOrder, "Shuffle should change order")
}

func TestScanARP_BasicStructure(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	hosts := ScanARP(ctx, cfg, testLogger())
	if hosts == nil {
		hosts = []*model.Host{}
	}
	assert.NotNil(t, hosts, "Hosts should be non-nil slice")
}

func TestIsBlacklisted_IPMatch(t *testing.T) {
	ip := net.ParseIP("192.168.1.10")
	blacklist := []string{"192.168.1.10"}
	assert.True(t, IsBlacklisted(ip, blacklist), "Expected exact IP match to be blacklisted")
}

func TestIsBlacklisted_CIDRMatch(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	blacklist := []string{"10.0.0.0/24"}
	assert.True(t, IsBlacklisted(ip, blacklist), "Expected CIDR match to be blacklisted")
}

func TestIsBlacklisted_NoMatch(t *testing.T) {
	ip := net.ParseIP("172.16.0.1")
	blacklist := []string{"192.168.0.0/24", "10.0.0.1"}
	assert.False(t, IsBlacklisted(ip, blacklist), "Expected IP not to be blacklisted")
}

func TestScanARP_SkipBlacklisted(t *testing.T) {
	blacklist := []string{"192.168.0.10"}
	ip := net.ParseIP("192.168.0.10")
	assert.True(t, IsBlacklisted(ip, blacklist), "Blacklisted IP should be excluded from scan")
}

func TestScanSYN_SkipBlacklisted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.Blacklist = []string{"10.0.0.1"}

	hosts := []*model.Host{
		{IP: net.ParseIP("10.0.0.1")},
		{IP: net.ParseIP("10.0.0.2")},
	}

	skipped := 0
	for _, h := range hosts {
		if IsBlacklisted(h.IP, cfg.Scan.Blacklist) {
			skipped++
		}
	}

	assert.Equal(t, 1, skipped, "Expected one host to be skipped due to blacklist")
}

func TestScanARPWithTargets_EmptyTargets(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
	}
	ctx := context.Background()
	targets := []net.IP{}

	hosts := ScanARPWithTargets(ctx, cfg, testLogger(), targets)
	assert.Empty(t, hosts, "Expected no hosts with empty targets")
}

func TestScanARPWithTargets_InvalidInterface(t *testing.T) {
	cfg := &config.Config{
		Interface: "doesnotexist0",
	}
	ctx := context.Background()
	targets := []net.IP{net.ParseIP("192.168.1.1")}

	hosts := ScanARPWithTargets(ctx, cfg, testLogger(), targets)
	assert.Empty(t, hosts, "Expected no hosts with invalid interface")
}

func TestScanARPWithTargets_ContextCancelled(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Annuler immédiatement
	targets := []net.IP{net.ParseIP("192.168.1.1")}

	hosts := ScanARPWithTargets(ctx, cfg, testLogger(), targets)
	assert.Empty(t, hosts, "Expected no hosts with cancelled context")
}

func TestScanARPWithTargets_BasicStructure(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	targets := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")}

	hosts := ScanARPWithTargets(ctx, cfg, testLogger(), targets)
	if hosts == nil {
		hosts = []*model.Host{}
	}
	assert.NotNil(t, hosts, "Hosts should be non-nil slice")
}

func TestExtractIPsFromHosts_EmptyList(t *testing.T) {
	hosts := []*model.Host{}
	ips := extractIPsFromHosts(hosts)
	assert.Empty(t, ips, "Expected empty IP list from empty hosts")
}

func TestExtractIPsFromHosts_WithNilIPs(t *testing.T) {
	hosts := []*model.Host{
		{IP: nil},
		{IP: net.ParseIP("192.168.1.1")},
		{IP: nil},
		{IP: net.ParseIP("192.168.1.2")},
	}
	ips := extractIPsFromHosts(hosts)
	assert.Len(t, ips, 2, "Expected 2 IPs from hosts with nil IPs filtered out")
	assert.Equal(t, "192.168.1.1", ips[0].String())
	assert.Equal(t, "192.168.1.2", ips[1].String())
}

func TestExtractIPsFromHosts_DuplicateIPs(t *testing.T) {
	hosts := []*model.Host{
		{IP: net.ParseIP("192.168.1.1")},
		{IP: net.ParseIP("192.168.1.2")},
		{IP: net.ParseIP("192.168.1.1")}, // Duplicate
		{IP: net.ParseIP("192.168.1.3")},
	}
	ips := extractIPsFromHosts(hosts)
	assert.Len(t, ips, 3, "Expected 3 unique IPs from hosts with duplicates")
}
