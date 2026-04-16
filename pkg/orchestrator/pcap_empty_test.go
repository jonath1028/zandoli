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

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// ensureEmptyPCAP crée un fichier PCAP vide avec un en-tête valide si le fichier n'existe pas
func ensureEmptyPCAP(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	// Write a standard PCAP header (Ethernet)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	// no packets written → empty trace with valid header
	return nil
}

func TestPCAPPipeline_EmptyFile(t *testing.T) {
	log := logger.MustInitLoggerForTest()

	packetChan := make(chan model.PacketEvent, 100)

	ctx := context.Background()
	scanID := "test-empty"

	// PCAP vide (créé automatiquement si manquant)
	pcapPath := filepath.Join("..", "..", "testdata", "empty.pcap")
	require.NoError(t, ensureEmptyPCAP(pcapPath))

	sniff := sniffer.NewPcapSniffer(pcapPath, packetChan, log, false)

	resultChan := make(chan []*model.Host, 1)
	go func() {
		resultChan <- analyzer.Analyze(ctx, packetChan, scanID, log)
	}()

	if err := sniff.Start(ctx); err != nil {
		t.Fatalf("PCAP sniffer failed: %v", err)
	}

	passiveResults := <-resultChan

	if len(passiveResults) != 0 {
		t.Errorf("Expected 0 hosts from empty PCAP, got %d", len(passiveResults))
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

	// L'exporteur génère un objet JSON avec une structure spécifique
	var exportData struct {
		Version    string        `json:"version"`
		GeneratedAt string       `json:"generatedAt"`
		Count      int           `json:"count"`
		Hosts      []*model.Host `json:"hosts"`
	}

	if err := json.Unmarshal(data, &exportData); err != nil {
		t.Fatalf("Invalid exported JSON format: %v", err)
	}

	if exportData.Count != 0 {
		t.Errorf("Expected 0 hosts in exported file, got %d", exportData.Count)
	}
	if len(exportData.Hosts) != 0 {
		t.Errorf("Expected 0 hosts in exported file, got %d", len(exportData.Hosts))
	}
}
