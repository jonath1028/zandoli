// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package orchestrator defines the core struct used to coordinate modules.
package orchestrator

import (
	"context"
	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// Orchestrator coordinates the execution of the pipeline.
type Orchestrator struct {
	Config          *config.Config
	Log             *logger.Logger
	OutputPath      string

	// ActiveScanFunc allows injection of the active scan logic for testing or customization.
	ActiveScanFunc func(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host
}

