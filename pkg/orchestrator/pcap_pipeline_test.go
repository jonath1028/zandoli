// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"zandoli/internal/logger"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/exporter"
	"zandoli/pkg/fusion"
	"zandoli/pkg/model"
	"zandoli/pkg/sniffer"
)

func TestPCAPPipeline_DHCPMinimal(t *testing.T) {
	log := logger.MustInitLoggerForTest()

	packetChan := make(chan model.PacketEvent, 100)

	ctx := context.Background()
	scanID := "test-scan-id"
	pcapPath := filepath.Join("..", "..", "testdata", "dhcp.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Skipping DHCP PCAP test: testdata/dhcp.pcap not present")
	}

	sniff := sniffer.NewPcapSniffer(pcapPath, packetChan, log, false)

	resultChan := make(chan []*model.Host, 1)
	go func() {
		resultChan <- analyzer.Analyze(ctx, packetChan, scanID, log)
	}()

	if err := sniff.Start(ctx); err != nil {
		t.Fatalf("Failed to start pcap sniffer: %v", err)
	}

	passiveResults := <-resultChan

	if len(passiveResults) != 3 {
		t.Errorf("Expected 3 hosts, got %d", len(passiveResults))
	}

	for _, h := range passiveResults {
		if h.Role != "client" && h.Role != "server" {
			t.Errorf("Unexpected role: %s", h.Role)
		}
		if len(h.Protocols) == 0 || h.Protocols[0] != "dhcp" {
			t.Errorf("Expected dhcp protocol, got %v", h.Protocols)
		}
	}

	tmpDir := t.TempDir()
	exportPath := filepath.Join(tmpDir, "hosts.json")
	allHosts := fusion.MergeResults(passiveResults, nil)

	if err := exporter.ExportAll(allHosts, exportPath, log); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("Failed to read exported JSON: %v", err)
	}

	var hosts []*model.Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if len(hosts) != 3 {
		t.Errorf("Expected 3 hosts in exported file, got %d", len(hosts))
	}
}
