// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides centralized packet analysis and routing by protocol.
package analyzer

import (
	"context"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/sniffer"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

// ModeKey is the context key used to pass the analysis mode ("live", "pcap").
const ModeKey contextKey = "mode"

// AnalysisStack represents the complete analysis stack components
type AnalysisStack struct {
	Dispatcher *Dispatcher
	Aggregator *Aggregator
	Logger     *logger.Logger
	Metrics    *sniffer.AnalyzerMetrics
}

// newAnalysisStack creates a complete analysis stack with proper initialization order.
// This ensures consistent initialization between offline and live modes, preventing crashes.
func newAnalysisStack(log *logger.Logger, opts *Options) (*AnalysisStack, error) {
	// 1. Initialize aggregator
	aggregator := NewAggregator()
	aggregator.SetLogger(log)
	if opts != nil && opts.OUIMap != nil {
		aggregator.SetOUIMap(opts.OUIMap)
	}

	// 2. Initialize metrics
	var metrics *sniffer.AnalyzerMetrics
	if opts != nil {
		metrics = sniffer.NewAnalyzerMetricsWithOptions(log, opts.EnableMetrics, opts.SampleRate)
	} else {
		metrics = sniffer.NewAnalyzerMetricsWithOptions(log, false, 0)
	}

	// 3. Initialize dispatcher with all dependencies
	dispatcher := NewDispatcher(log, aggregator, opts, metrics)

	// 4. Log initialization success
	log.Info().
		Bool("dispatcher_ready", true).
		Bool("aggregator_ready", true).
		Bool("metrics_ready", metrics != nil).
		Msg("analysis-stack: dispatcher ready")

	return &AnalysisStack{
		Dispatcher: dispatcher,
		Aggregator: aggregator,
		Logger:     log,
		Metrics:    metrics,
	}, nil
}

// Analyze reads packets from the channel and dispatches them to protocol-specific parsers.
func Analyze(ctx context.Context, packetChan <-chan model.PacketEvent, scanID string, log *logger.Logger) []*model.Host {
	return AnalyzeWithOptions(ctx, packetChan, scanID, log, false, 0, 0)
}

// AnalyzeWithOptions reads packets from the channel and dispatches them with custom options.
func AnalyzeWithOptions(ctx context.Context, packetChan <-chan model.PacketEvent, scanID string, log *logger.Logger, enableMetrics bool, sampleRate int, workers int) []*model.Host {
	log.Debug().Msg("Analyzer started")
	log.Debug().Bool("enableMetrics", enableMetrics).Int("sampleRate", sampleRate).Int("workers", workers).Msg("Performance options")

	opts := &Options{
		EnableMetrics: enableMetrics,
		SampleRate:    sampleRate,
		Workers:       workers,
		TraceEnabled:  false,
	}

	return AnalyzeWithCustomOptions(ctx, packetChan, scanID, log, opts)
}

// AnalyzeWithCustomOptions reads packets from the channel and dispatches them with fully custom options.
// It returns the collected hosts when analysis is complete.
func AnalyzeWithCustomOptions(ctx context.Context, packetChan <-chan model.PacketEvent, scanID string, log *logger.Logger, opts *Options) []*model.Host {
	log.Debug().Msg("Analyzer started")
	if opts != nil {
		log.Debug().Bool("enableMetrics", opts.EnableMetrics).Int("sampleRate", opts.SampleRate).Int("workers", opts.Workers).Msg("Performance options")
	}

	stack, err := newAnalysisStack(log, opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize analysis stack")
		return nil
	}

	// Add mode-specific logging
	mode := "live"
	if modeStr, ok := ctx.Value(ModeKey).(string); ok && modeStr != "" {
		mode = modeStr
	}
	log.Debug().Str("mode", mode).Msg("analysis-stack: dispatcher ready")

	log.Debug().Msg("Using sequential packet processing")

	// Detect anomalies periodically
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Analyzer stopped")
			break loop

		case pkt, ok := <-packetChan:
			if !ok {
				break loop
			}
			stack.Dispatcher.Dispatch(pkt)

		case <-ticker.C:
			stack.Aggregator.DetectAnomalies()
		}
	}

	// Final anomaly detection
	stack.Aggregator.DetectAnomalies()

	// Log performance statistics
	log.Warn().Msg("=== ANALYZER PERFORMANCE STATISTICS ===")
	processedPackets := stack.Dispatcher.GetProcessedPacketsCount()
	log.Warn().Uint64("total_packets_processed", processedPackets).Msg("Successfully processed packets")
	stack.Dispatcher.LogPerformanceStats()

	return stack.Aggregator.GetAll()
}

// GetTopologySubnets returns the VLAN-aware topology subnets
func GetTopologySubnets() []model.SubnetEntry {
	// Simplified aggregator no longer tracks topology subnets
	return []model.SubnetEntry{}
}
