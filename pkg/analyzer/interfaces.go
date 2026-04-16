// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"zandoli/internal/logger"
	"zandoli/internal/oui"
	"zandoli/pkg/model"
)

// HostAggregator defines the interface for host aggregation and anomaly detection.
type HostAggregator interface {
	Merge(record *ParsedRecord)
	GetAll() []*model.Host
	DetectAnomalies()
	SetLogger(log *logger.Logger)
	SetOUIMap(ouiMap *oui.Map)
}

// Compile-time check: *Aggregator must satisfy HostAggregator.
var _ HostAggregator = (*Aggregator)(nil)
