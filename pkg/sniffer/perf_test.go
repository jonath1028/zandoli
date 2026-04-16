// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

import (
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
)

func TestAnalyzerMetrics(t *testing.T) {
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	metrics := NewAnalyzerMetrics(log)

	// Test d'enregistrement d'exécutions
	metrics.RecordExecution("TestAnalyzer", 100*time.Microsecond, true)
	metrics.RecordExecution("TestAnalyzer", 200*time.Microsecond, true)
	metrics.RecordExecution("TestAnalyzer", 50*time.Microsecond, false)

	// Vérifier les statistiques
	stats := metrics.GetStats("TestAnalyzer")
	if stats.PacketCount != 3 {
		t.Errorf("Expected packet count 3, got %d", stats.PacketCount)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("Expected error count 1, got %d", stats.ErrorCount)
	}
	if stats.MinDuration != 50*time.Microsecond {
		t.Errorf("Expected min duration 50μs, got %v", stats.MinDuration)
	}
	if stats.MaxDuration != 200*time.Microsecond {
		t.Errorf("Expected max duration 200μs, got %v", stats.MaxDuration)
	}
	expectedAvg := 116 * time.Microsecond // (100 + 200 + 50) / 3
	// Tolérance de 1 microseconde pour les arrondis
	if stats.AvgDuration < expectedAvg-time.Microsecond || stats.AvgDuration > expectedAvg+time.Microsecond {
		t.Errorf("Expected avg duration around %v, got %v", expectedAvg, stats.AvgDuration)
	}

	// Test de la fonction MeasureExecution
	var result string
	err = metrics.MeasureExecution("MeasureTest", func() error {
		time.Sleep(1 * time.Millisecond)
		result = "success"
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result != "success" {
		t.Errorf("Expected result 'success', got %s", result)
	}

	// Vérifier que les statistiques ont été mises à jour
	measureStats := metrics.GetStats("MeasureTest")
	if measureStats.PacketCount != 1 {
		t.Errorf("Expected packet count 1 for MeasureTest, got %d", measureStats.PacketCount)
	}
	if measureStats.MinDuration < 1*time.Millisecond {
		t.Errorf("Expected min duration >= 1ms, got %v", measureStats.MinDuration)
	}
}

func TestAnalyzerMetricsConcurrency(t *testing.T) {
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	metrics := NewAnalyzerMetrics(log)

	// Test de concurrence
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			metrics.RecordExecution("ConcurrentTest", 100*time.Microsecond, true)
			done <- true
		}()
	}

	// Attendre que toutes les goroutines se terminent
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := metrics.GetStats("ConcurrentTest")
	if stats.PacketCount != 10 {
		t.Errorf("Expected packet count 10, got %d", stats.PacketCount)
	}
}

func TestAnalyzerMetricsTopSlowest(t *testing.T) {
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	metrics := NewAnalyzerMetrics(log)

	// Ajouter des analyseurs avec différentes durées
	metrics.RecordExecution("FastAnalyzer", 10*time.Microsecond, true)
	metrics.RecordExecution("FastAnalyzer", 20*time.Microsecond, true)

	metrics.RecordExecution("SlowAnalyzer", 100*time.Microsecond, true)
	metrics.RecordExecution("SlowAnalyzer", 200*time.Microsecond, true)

	metrics.RecordExecution("MediumAnalyzer", 50*time.Microsecond, true)
	metrics.RecordExecution("MediumAnalyzer", 60*time.Microsecond, true)

	// Tester GetTopSlowestAnalyzers
	slowest := metrics.GetTopSlowestAnalyzers(2)
	if len(slowest) != 2 {
		t.Errorf("Expected 2 slowest analyzers, got %d", len(slowest))
	}
	if slowest[0] != "SlowAnalyzer" {
		t.Errorf("Expected SlowAnalyzer to be first, got %s", slowest[0])
	}
	if slowest[1] != "MediumAnalyzer" {
		t.Errorf("Expected MediumAnalyzer to be second, got %s", slowest[1])
	}
}

func TestAnalyzerMetricsTotalStats(t *testing.T) {
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	metrics := NewAnalyzerMetrics(log)

	metrics.RecordExecution("Analyzer1", 100*time.Microsecond, true)
	metrics.RecordExecution("Analyzer1", 200*time.Microsecond, false)
	metrics.RecordExecution("Analyzer2", 50*time.Microsecond, true)

	totalPackets, totalDuration, totalErrors, analyzerCount := metrics.GetTotalStats()

	if totalPackets != 3 {
		t.Errorf("Expected total packets 3, got %d", totalPackets)
	}
	if totalDuration != 350*time.Microsecond {
		t.Errorf("Expected total duration 350μs, got %v", totalDuration)
	}
	if totalErrors != 1 {
		t.Errorf("Expected total errors 1, got %d", totalErrors)
	}
	if analyzerCount != 2 {
		t.Errorf("Expected analyzer count 2, got %d", analyzerCount)
	}
}
