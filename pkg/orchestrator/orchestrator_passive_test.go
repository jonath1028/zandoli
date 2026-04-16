// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
)

func TestRunPassivePipeline(t *testing.T) {
	cfg := &config.Config{
		Mode: config.Mode{
			Passive: true,
		},
		Scan: config.ScanSettings{
			PassiveDurationSeconds: 1, // Garder à 1s mais avec timeout court
		},
		Logging: config.Logging{
			Paranoid: true,
			Quiet:    true,
		},
		Interface: "lo",
	}

	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	o := &Orchestrator{
		Config:     cfg,
		Log:        log,
		OutputPath: t.TempDir(),
	}

	// Utiliser un timeout plus court pour éviter les blocages
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Exécuter le test avec un timeout
	done := make(chan error, 1)
	go func() {
		done <- o.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			// Check if it's a permission error (expected in test environments without CAP_NET_RAW)
			if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "Operation not permitted") || strings.Contains(err.Error(), "CAP_NET_RAW") {
				t.Logf("Test completed with expected permission error: %v", err)
			} else {
				t.Fatalf("Run() failed in passive mode with unexpected error: %v", err)
			}
		}
	case <-ctx.Done():
		t.Fatalf("Test timed out after 2 seconds")
	}
}
