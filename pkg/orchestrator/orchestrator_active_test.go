// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"net"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

func TestRunActivePipeline(t *testing.T) {
	cfg := &config.Config{
		Mode: config.Mode{
			Active: true,
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
					IP:     net.ParseIP("192.168.0.10"),
					MAC:    mustMAC("aa:bb:cc:dd:ee:ff"),
					MACStr: "aa:bb:cc:dd:ee:ff",
				},
			}
		},
	}

	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := o.Run(); err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
}
