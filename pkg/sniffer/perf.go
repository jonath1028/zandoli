// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package sniffer provides performance metrics tracking for packet analyzers.
package sniffer

import (
	"sync"
	"time"

	"zandoli/internal/logger"
)

// AnalyzerMetrics tracks performance metrics for each analyzer function
type AnalyzerMetrics struct {
	mu            sync.RWMutex
	metrics       map[string]*AnalyzerStats
	log           *logger.Logger
	scanStartTime time.Time
	enabled       bool   // Whether metrics collection is enabled
	sampleRate    int    // Sample every Nth packet (0 = disabled)
	packetCount   uint64 // Total packet counter for sampling
}

// AnalyzerStats contains performance statistics for a single analyzer
type AnalyzerStats struct {
	PacketCount   uint64        // Number of packets processed
	TotalDuration time.Duration // Total execution duration
	MinDuration   time.Duration // Minimum execution duration
	MaxDuration   time.Duration // Maximum execution duration
	AvgDuration   time.Duration // Average execution duration
	LastExecuted  time.Time     // Last execution
	ErrorCount    uint64        // Nombre d'erreurs
}

// NewAnalyzerMetrics creates a new AnalyzerMetrics instance
func NewAnalyzerMetrics(log *logger.Logger) *AnalyzerMetrics {
	return &AnalyzerMetrics{
		metrics:       make(map[string]*AnalyzerStats),
		log:           log,
		scanStartTime: time.Now(),
		enabled:       true,
		sampleRate:    0, // Disabled by default for performance
		packetCount:   0,
	}
}

// NewAnalyzerMetricsWithOptions creates a new AnalyzerMetrics instance with custom options
func NewAnalyzerMetricsWithOptions(log *logger.Logger, enabled bool, sampleRate int) *AnalyzerMetrics {
	return &AnalyzerMetrics{
		metrics:       make(map[string]*AnalyzerStats),
		log:           log,
		scanStartTime: time.Now(),
		enabled:       enabled,
		sampleRate:    sampleRate,
		packetCount:   0,
	}
}

// RecordExecution records the execution of an analyzer function
func (am *AnalyzerMetrics) RecordExecution(analyzerName string, duration time.Duration, success bool) {
	// Skip recording if metrics are disabled
	if !am.enabled {
		return
	}

	// Apply sampling if enabled
	if am.sampleRate > 0 {
		am.mu.Lock()
		am.packetCount++
		shouldSample := (am.packetCount % uint64(am.sampleRate)) == 0
		am.mu.Unlock()

		if !shouldSample {
			return
		}
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	stats, exists := am.metrics[analyzerName]
	if !exists {
		stats = &AnalyzerStats{
			MinDuration: duration,
			MaxDuration: duration,
		}
		am.metrics[analyzerName] = stats
	}

	// Update statistics
	stats.PacketCount++
	stats.TotalDuration += duration
	stats.LastExecuted = time.Now()

	if !success {
		stats.ErrorCount++
	}

	// Update min/max durations
	if duration < stats.MinDuration {
		stats.MinDuration = duration
	}
	if duration > stats.MaxDuration {
		stats.MaxDuration = duration
	}

	// Calculate the average duration
	if stats.PacketCount > 0 {
		stats.AvgDuration = stats.TotalDuration / time.Duration(stats.PacketCount)
	}
}

// GetStats returns statistics for a specific analyzer
func (am *AnalyzerMetrics) GetStats(analyzerName string) *AnalyzerStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats, exists := am.metrics[analyzerName]
	if !exists {
		return &AnalyzerStats{}
	}

	// Return a copy to avoid concurrent access
	return &AnalyzerStats{
		PacketCount:   stats.PacketCount,
		TotalDuration: stats.TotalDuration,
		MinDuration:   stats.MinDuration,
		MaxDuration:   stats.MaxDuration,
		AvgDuration:   stats.AvgDuration,
		LastExecuted:  stats.LastExecuted,
		ErrorCount:    stats.ErrorCount,
	}
}

// GetAllStats returns a copy of all analyzer statistics
func (am *AnalyzerMetrics) GetAllStats() map[string]*AnalyzerStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make(map[string]*AnalyzerStats)
	for name, stats := range am.metrics {
		result[name] = &AnalyzerStats{
			PacketCount:   stats.PacketCount,
			TotalDuration: stats.TotalDuration,
			MinDuration:   stats.MinDuration,
			MaxDuration:   stats.MaxDuration,
			AvgDuration:   stats.AvgDuration,
			LastExecuted:  stats.LastExecuted,
			ErrorCount:    stats.ErrorCount,
		}
	}

	return result
}

// GetTotalStats returns aggregate statistics across all analyzers
func (am *AnalyzerMetrics) GetTotalStats() (totalPackets uint64, totalDuration time.Duration, totalErrors uint64, analyzerCount int) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, stats := range am.metrics {
		totalPackets += stats.PacketCount
		totalDuration += stats.TotalDuration
		totalErrors += stats.ErrorCount
	}

	return totalPackets, totalDuration, totalErrors, len(am.metrics)
}

// GetScanDuration returns the total scan duration
func (am *AnalyzerMetrics) GetScanDuration() time.Duration {
	return time.Since(am.scanStartTime)
}

// LogStats logs comprehensive performance statistics
func (am *AnalyzerMetrics) LogStats() {
	am.LogStatsWithProcessedPackets(0)
}

// LogStatsWithProcessedPackets logs comprehensive performance statistics with global processed packets count
func (am *AnalyzerMetrics) LogStatsWithProcessedPackets(processedPackets uint64) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	scanDuration := am.GetScanDuration()
	totalPackets, totalDuration, totalErrors, analyzerCount := am.GetTotalStats()

	// Log global statistics
	am.log.Info().
		Dur("scan_duration", scanDuration).
		Uint64("total_packets_processed", processedPackets).
		Uint64("analyzer_packets_processed", totalPackets).
		Dur("total_analysis_time", totalDuration).
		Uint64("total_errors", totalErrors).
		Int("active_analyzers", analyzerCount).
		Msg("=== PERFORMANCE METRICS SUMMARY ===")

	// Log des statistiques par analyseur
	for name, stats := range am.metrics {
		if stats.PacketCount > 0 {
			successRate := float64(stats.PacketCount-stats.ErrorCount) / float64(stats.PacketCount) * 100

			am.log.Info().
				Str("analyzer", name).
				Uint64("packets_processed", stats.PacketCount).
				Dur("total_time", stats.TotalDuration).
				Dur("avg_time", stats.AvgDuration).
				Dur("min_time", stats.MinDuration).
				Dur("max_time", stats.MaxDuration).
				Uint64("errors", stats.ErrorCount).
				Float64("success_rate", successRate).
				Time("last_executed", stats.LastExecuted).
				Msg("Analyzer performance")
		}
	}

	// Log performance metrics
	if totalPackets > 0 {
		avgTimePerPacket := totalDuration / time.Duration(totalPackets)
		packetsPerSecond := float64(totalPackets) / scanDuration.Seconds()

		am.log.Info().
			Dur("avg_time_per_packet", avgTimePerPacket).
			Float64("packets_per_second", packetsPerSecond).
			Msg("Performance metrics")
	}
}

// Clear removes all statistics (useful for testing or reset)
func (am *AnalyzerMetrics) Clear() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.metrics = make(map[string]*AnalyzerStats)
	am.scanStartTime = time.Now()
}

// MeasureExecution measures the execution of an analyzer function
func (am *AnalyzerMetrics) MeasureExecution(analyzerName string, fn func() error) error {
	// Skip measurement if metrics are disabled
	if !am.enabled {
		return fn()
	}

	// Apply sampling if enabled
	if am.sampleRate > 0 {
		am.mu.Lock()
		am.packetCount++
		shouldSample := (am.packetCount % uint64(am.sampleRate)) == 0
		am.mu.Unlock()

		if !shouldSample {
			return fn()
		}
	}

	start := time.Now()
	err := fn()
	duration := time.Since(start)

	am.RecordExecution(analyzerName, duration, err == nil)

	return err
}

// SetEnabled enables or disables metrics collection
func (am *AnalyzerMetrics) SetEnabled(enabled bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.enabled = enabled
}

// SetSampleRate sets the sampling rate (0 = disabled, N = sample every Nth packet)
func (am *AnalyzerMetrics) SetSampleRate(rate int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.sampleRate = rate
}

// IsEnabled returns whether metrics collection is enabled
func (am *AnalyzerMetrics) IsEnabled() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.enabled
}

// GetSampleRate returns the current sampling rate
func (am *AnalyzerMetrics) GetSampleRate() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.sampleRate
}

// GetTopSlowestAnalyzers retourne les analyseurs les plus lents
func (am *AnalyzerMetrics) GetTopSlowestAnalyzers(limit int) []string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	type analyzerWithAvg struct {
		name string
		avg  time.Duration
	}

	var analyzers []analyzerWithAvg
	for name, stats := range am.metrics {
		if stats.PacketCount > 0 {
			analyzers = append(analyzers, analyzerWithAvg{name, stats.AvgDuration})
		}
	}

	// Sort by descending average duration
	for i := 0; i < len(analyzers); i++ {
		for j := i + 1; j < len(analyzers); j++ {
			if analyzers[i].avg < analyzers[j].avg {
				analyzers[i], analyzers[j] = analyzers[j], analyzers[i]
			}
		}
	}

	// Limit the number of results
	if limit > 0 && limit < len(analyzers) {
		analyzers = analyzers[:limit]
	}

	result := make([]string, len(analyzers))
	for i, a := range analyzers {
		result[i] = a.name
	}

	return result
}
