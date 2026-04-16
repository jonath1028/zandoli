// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"net"
	"testing"

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

func TestOrchestrator_CombinedModeWithTargetedScan(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Combined: true,
		},
		Scan: config.ScanSettings{
			Targeted: true,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	o := NewOrchestrator(cfg, testLogger(), "test_output")
	assert.NotNil(t, o, "Expected non-nil orchestrator")
	assert.Equal(t, cfg, o.Config, "Expected config to match")
	assert.Equal(t, "test_output", o.OutputPath, "Expected output path to match")
}

func TestOrchestrator_ActiveModeWithTargetedScan(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Active: true,
		},
		Scan: config.ScanSettings{
			Targeted: true,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	o := NewOrchestrator(cfg, testLogger(), "test_output")
	assert.NotNil(t, o, "Expected non-nil orchestrator")
	assert.Equal(t, cfg, o.Config, "Expected config to match")
	assert.Equal(t, "test_output", o.OutputPath, "Expected output path to match")
}

func TestOrchestrator_DefaultActiveScanFunc(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Active: true,
		},
		Scan: config.ScanSettings{
			Targeted: false,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	o := NewOrchestrator(cfg, testLogger(), "test_output")
	assert.NotNil(t, o.ActiveScanFunc, "Expected default ActiveScanFunc to be set")
}

func TestOrchestrator_CustomActiveScanFunc(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Active: true,
		},
		Scan: config.ScanSettings{
			Targeted: false,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	customFunc := func(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host {
		return []*model.Host{
			{IP: net.ParseIP("192.168.1.1")},
		}
	}

	o := &Orchestrator{
		Config:         cfg,
		Log:            testLogger(),
		OutputPath:     "test_output",
		ActiveScanFunc: customFunc,
	}

	assert.NotNil(t, o.ActiveScanFunc, "Expected custom ActiveScanFunc to be set")
}

func TestOrchestrator_ConfigValidation(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Combined: true,
		},
		Scan: config.ScanSettings{
			Targeted: true,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	o := NewOrchestrator(cfg, testLogger(), "test_output")

	// Vérifier que la configuration est correctement stockée
	assert.True(t, o.Config.Scan.Targeted, "Expected targeted mode to be enabled")
	assert.True(t, o.Config.Mode.Combined, "Expected combined mode to be enabled")
	assert.Equal(t, "lo", o.Config.Interface, "Expected interface to be lo")
}

func TestOrchestrator_LoggerInitialization(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Mode: config.Mode{
			Active: true,
		},
		Scan: config.ScanSettings{
			Targeted: false,
		},
		Output: config.OutputPaths{
			BaseDir: "test_output",
		},
	}

	log := testLogger()
	o := NewOrchestrator(cfg, log, "test_output")

	assert.Equal(t, log, o.Log, "Expected logger to match")
	assert.NotNil(t, o.Log, "Expected logger to be non-nil")
}
