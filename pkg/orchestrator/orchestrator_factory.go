// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package orchestrator provides constructors for Orchestrator.
package orchestrator

import (
	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/scanner"
)

// NewOrchestrator initializes a new Orchestrator instance.
func NewOrchestrator(cfg *config.Config, log *logger.Logger, outputPath string) *Orchestrator {
	o := &Orchestrator{
		Config:     cfg,
		Log:        log,
		OutputPath: outputPath,
	}

	// Set default ActiveScanFunc if not overridden
	if o.ActiveScanFunc == nil {
		o.ActiveScanFunc = scanner.RunActiveScan
	}

	return o
}

