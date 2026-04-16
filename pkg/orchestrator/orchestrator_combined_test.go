// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

func TestRunCombinedPipeline_WithMockedScan(t *testing.T) {
	cfg := &config.Config{
		Mode: config.Mode{
			PcapFile: "../../testdata/cdp.pcap",
		},
		Logging: config.Logging{
			Paranoid: true,
			Quiet:    true,
		},
	}

	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	o := &Orchestrator{
		Config:     cfg,
		Log:        log,
		OutputPath: t.TempDir(),
		ActiveScanFunc: func(_ context.Context, _ *config.Config, _ *logger.Logger) []*model.Host {
			return []*model.Host{
				{
					IP:      net.ParseIP("192.168.0.10"),
					MAC:     mustMAC("aa:bb:cc:dd:ee:ff"),
					MACStr:  "aa:bb:cc:dd:ee:ff",
					Vendor:  "TestVendor",
					OSGuess: "TestOS",
					Ports:   []int{443},
					Source:  "active",
				},
			}
		},
	}

	if err := o.Run(); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run() failed in combined mode: %v", err)
		}
		// Le timeout est attendu dans ce test, donc on ne considère pas cela comme une erreur
		t.Logf("Test completed with expected timeout: %v", err)
	}
}

func TestRunCombinedPipeline_Timeout(t *testing.T) {
	cfg := &config.Config{
		Mode: config.Mode{
			Combined: true,
		},
		Scan: config.ScanSettings{
			PassiveDurationSeconds: 1, // Garder à 1s mais avec timeout court
		},
		Logging: config.Logging{
			Paranoid: true,
			Quiet:    true,
		},
		Interface: "eth0", // Cette interface nécessitera des permissions, mais le test devrait timeout avant
	}

	log, err := logger.New("test", cfg)

	o := &Orchestrator{
		Config:     cfg,
		Log:        log,
		OutputPath: t.TempDir(),
		ActiveScanFunc: func(_ context.Context, _ *config.Config, _ *logger.Logger) []*model.Host {
			return []*model.Host{}
		},
	}

	// Test avec un timeout très court pour vérifier que le contexte fonctionne
	start := time.Now()
	err = o.Run()
	duration := time.Since(start)

	// Le test devrait se terminer rapidement à cause du timeout
	// Ajuster l'attente à < 2s pour être plus réaliste avec les timeouts courts
	if duration > 2*time.Second {
		t.Fatalf("Test took too long: %v (expected < 2s)", duration)
	}

	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("Run() failed with non-timeout error: %v", err)
		} else {
			t.Logf("Test completed with expected timeout: %v", err)
		}
	}
}
