// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"os"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
)

func TestRunPCAPPipeline(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := tmpDir + "/empty.pcap"
	if err := os.WriteFile(pcapPath, []byte{}, 0644); err != nil {
		t.Fatalf("failed to create dummy pcap: %v", err)
	}

	cfg := &config.Config{
		Mode: config.Mode{
			PcapFile: pcapPath,
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
		OutputPath: tmpDir,
	}

	_, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := o.Run(); err != nil {
		t.Fatalf("Run() failed in pcap mode: %v", err)
	}
}
