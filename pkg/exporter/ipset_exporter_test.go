// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

func TestExportIPSets(t *testing.T) {
	// Créer un répertoire temporaire pour les tests
	tmpDir := t.TempDir()

	// Créer un logger de test
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create test logger: %v", err)
	}

	// Créer des hôtes de test avec différents types d'IP
	hosts := []*model.Host{
		{
			IP:        net.ParseIP("10.0.0.5"),
			MACStr:    "00:11:22:33:44:55",
			Vendor:    "TestVendor1",
			IPs:       []net.IP{net.ParseIP("10.0.0.5")},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        net.ParseIP("172.16.2.10"),
			MACStr:    "00:11:22:33:44:66",
			Vendor:    "TestVendor2",
			IPs:       []net.IP{net.ParseIP("172.16.2.10"), net.ParseIP("8.8.8.8")}, // mix privé/public
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        net.ParseIP("192.168.1.3"),
			MACStr:    "00:11:22:33:44:77",
			Vendor:    "TestVendor3",
			IPs:       []net.IP{net.ParseIP("192.168.1.3")},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        net.ParseIP("1.1.1.1"),
			MACStr:    "00:11:22:33:44:88",
			Vendor:    "TestVendor4",
			IPs:       []net.IP{net.ParseIP("1.1.1.1")}, // IP publique uniquement
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	// Exporter les IP sets
	err = ExportIPSets(hosts, tmpDir, log)
	if err != nil {
		t.Fatalf("ExportIPSets failed: %v", err)
	}

	// Vérifier que les fichiers ont été créés
	privateFile := filepath.Join(tmpDir, "private_ips.json")
	publicFile := filepath.Join(tmpDir, "public_ips.json")

	if _, err := os.Stat(privateFile); os.IsNotExist(err) {
		t.Fatalf("private_ips.json was not created")
	}
	if _, err := os.Stat(publicFile); os.IsNotExist(err) {
		t.Fatalf("public_ips.json was not created")
	}

	// Lire et vérifier le contenu des fichiers
	var privateSet IPSet
	var publicSet IPSet

	// Vérifier private_ips.json
	privateData, err := os.ReadFile(privateFile)
	if err != nil {
		t.Fatalf("Failed to read private_ips.json: %v", err)
	}

	err = json.Unmarshal(privateData, &privateSet)
	if err != nil {
		t.Fatalf("Failed to unmarshal private_ips.json: %v", err)
	}

	// Vérifier que les IP privées sont correctes
	expectedPrivate := []string{"10.0.0.5", "172.16.2.10", "192.168.1.3"}
	if privateSet.Count != len(expectedPrivate) {
		t.Errorf("Expected %d private IPs, got %d", len(expectedPrivate), privateSet.Count)
	}

	for _, expectedIP := range expectedPrivate {
		found := false
		for _, actualIP := range privateSet.IPs {
			if actualIP == expectedIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected private IP %s not found in result", expectedIP)
		}
	}

	// Vérifier que les IP sont triées
	if !sort.StringsAreSorted(privateSet.IPs) {
		t.Error("Private IPs are not sorted")
	}

	// Vérifier public_ips.json
	publicData, err := os.ReadFile(publicFile)
	if err != nil {
		t.Fatalf("Failed to read public_ips.json: %v", err)
	}

	err = json.Unmarshal(publicData, &publicSet)
	if err != nil {
		t.Fatalf("Failed to unmarshal public_ips.json: %v", err)
	}

	// Vérifier que les IP publiques sont correctes
	expectedPublic := []string{"1.1.1.1", "8.8.8.8"}
	if publicSet.Count != len(expectedPublic) {
		t.Errorf("Expected %d public IPs, got %d", len(expectedPublic), publicSet.Count)
	}

	for _, expectedIP := range expectedPublic {
		found := false
		for _, actualIP := range publicSet.IPs {
			if actualIP == expectedIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected public IP %s not found in result", expectedIP)
		}
	}

	// Vérifier que les IP sont triées
	if !sort.StringsAreSorted(publicSet.IPs) {
		t.Error("Public IPs are not sorted")
	}
}

func TestExportIPSets_EmptyHosts(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create test logger: %v", err)
	}

	err = ExportIPSets([]*model.Host{}, tmpDir, log)
	if err != nil {
		t.Fatalf("ExportIPSets failed with empty hosts: %v", err)
	}

	// Vérifier que les fichiers ont été créés avec des ensembles vides
	privateFile := filepath.Join(tmpDir, "private_ips.json")
	publicFile := filepath.Join(tmpDir, "public_ips.json")

	var privateSet IPSet
	var publicSet IPSet

	privateData, err := os.ReadFile(privateFile)
	if err != nil {
		t.Fatalf("Failed to read private_ips.json: %v", err)
	}

	err = json.Unmarshal(privateData, &privateSet)
	if err != nil {
		t.Fatalf("Failed to unmarshal private_ips.json: %v", err)
	}

	if privateSet.Count != 0 {
		t.Errorf("Expected 0 private IPs, got %d", privateSet.Count)
	}

	publicData, err := os.ReadFile(publicFile)
	if err != nil {
		t.Fatalf("Failed to read public_ips.json: %v", err)
	}

	err = json.Unmarshal(publicData, &publicSet)
	if err != nil {
		t.Fatalf("Failed to unmarshal public_ips.json: %v", err)
	}

	if publicSet.Count != 0 {
		t.Errorf("Expected 0 public IPs, got %d", publicSet.Count)
	}
}
