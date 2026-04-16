// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"zandoli/internal/config"
)

func TestNew_TestMode(t *testing.T) {
	// Test avec folder vide (mode test)
	cfg := &config.Config{}
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if log == nil {
		t.Fatal("Expected logger, got nil")
	}

	// Test avec folder "test" (mode test)
	log2, err := New("test", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if log2 == nil {
		t.Fatal("Expected logger, got nil")
	}
}

func TestNew_StandardMode(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{}

	log, err := New(tmpDir, cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if log == nil {
		t.Fatal("Expected logger, got nil")
	}

	// Vérifier que le fichier de log existe directement dans tmpDir
	logFile := filepath.Join(tmpDir, "scan_execution.log")

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Fatalf("Expected log file to exist at %s", logFile)
	}
}

func TestLogger_LogLevels(t *testing.T) {
	cfg := &config.Config{}
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test des différents niveaux de log
	log.Info().Msg("Test info message")
	log.Warn().Msg("Test warning message")
	log.Error().Msg("Test error message")
	log.Debug().Msg("Test debug message")

	// Test avec des champs
	log.Info().
		Str("key", "value").
		Int("number", 42).
		Bool("flag", true).
		Msg("Test structured log")
}

func TestLogger_WithFields(t *testing.T) {
	cfg := &config.Config{}
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test avec des champs supplémentaires
	logger := log.With().
		Str("component", "test").
		Int("version", 1).
		Logger()

	logger.Info().Msg("Test message with fields")
	logger.Warn().Str("warning_type", "test").Msg("Test warning with fields")
}

func TestLogger_ConcurrentLogging(t *testing.T) {
	cfg := &config.Config{}
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test de logging concurrent
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				log.Info().
					Int("goroutine", id).
					Int("iteration", j).
					Msg("Concurrent log message")
			}
			done <- true
		}(i)
	}

	// Attendre que toutes les goroutines se terminent
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestLogger_TimeFormat(t *testing.T) {
	cfg := &config.Config{}
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test que le format de temps est correct
	now := time.Now()
	log.Info().
		Time("timestamp", now).
		Msg("Test timestamp formatting")
}

func TestLogger_ConfigIntegration(t *testing.T) {
	// Test avec différentes configurations
	testCases := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "default config",
			cfg:  &config.Config{},
		},
		{
			name: "verbose config",
			cfg: &config.Config{
				Logging: config.Logging{
					Verbose:  true,
					Quiet:    false,
					Paranoid: false,
				},
			},
		},
		{
			name: "quiet config",
			cfg: &config.Config{
				Logging: config.Logging{
					Verbose:  false,
					Quiet:    true,
					Paranoid: false,
				},
			},
		},
		{
			name: "paranoid config",
			cfg: &config.Config{
				Logging: config.Logging{
					Verbose:  false,
					Quiet:    false,
					Paranoid: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log, err := New("", tc.cfg)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if log == nil {
				t.Fatal("Expected logger, got nil")
			}

			// Test que le logger fonctionne avec cette config
			log.Info().Msg("Test message")
			log.Warn().Msg("Test warning")
			log.Error().Msg("Test error")
		})
	}
}

func TestLogger_ConsoleFallback(t *testing.T) {
	// Test que le fallback console fonctionne quand file logging est désactivé
	cfg := &config.Config{}

	// Test avec folder vide (mode test) - doit utiliser console uniquement
	log, err := New("", cfg)
	if err != nil {
		t.Fatalf("Expected no error for console fallback, got %v", err)
	}
	if log == nil {
		t.Fatal("Expected logger for console fallback, got nil")
	}

	// Test que le logger fonctionne en mode console
	log.Info().Msg("Console fallback test message")
	log.Warn().Msg("Console fallback test warning")
	log.Error().Msg("Console fallback test error")

	// Test avec folder "test" (mode test) - doit utiliser console uniquement
	log2, err2 := New("test", cfg)
	if err2 != nil {
		t.Fatalf("Expected no error for test mode console fallback, got %v", err2)
	}
	if log2 == nil {
		t.Fatal("Expected logger for test mode console fallback, got nil")
	}

	// Test que le logger fonctionne en mode test
	log2.Info().Msg("Test mode console fallback message")
}
