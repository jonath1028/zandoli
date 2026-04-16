// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"zandoli/internal/config"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger
type Logger struct {
	zerolog.Logger
}

// New returns a new logger based on the config and output folder.
// If folder == "" or "test", disables file logging (used for unit tests).
func New(folder string, cfg *config.Config) (*Logger, error) {
	// Test mode: only stdout, no file creation
	if folder == "" || folder == "test" {
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		log := zerolog.New(consoleWriter).With().Timestamp().Logger()
		return &Logger{log}, nil
	}

	// Configurer le niveau de log selon les flags
	var logLevel zerolog.Level
	if cfg.Logging.Quiet {
		logLevel = zerolog.WarnLevel
	} else if cfg.Logging.Verbose {
		logLevel = zerolog.DebugLevel
	} else {
		// Default mode: Info (no debug)
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Validate that the base folder exists and is writable
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %q: %w", folder, err)
	}

	// Test if the directory is writable by creating a temporary file
	testFile := filepath.Join(folder, ".write_test")
	if f, err := os.Create(testFile); err != nil {
		return nil, err
	} else {
		f.Close()
		os.Remove(testFile) // Clean up test file
	}

	// Create scan-specific log file directly in the base folder (no dated subfolder)
	logFilePath := filepath.Join(folder, "scan_execution.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open scan log file %q: %w", logFilePath, err)
	}

	// Also try to write to output/zandoli_application.log global (best-effort)
	// Si le dossier n'existe pas (tests), on l'ignore silencieusement
	var writers []io.Writer
	globalLogPath := "output/zandoli_application.log"
	if err := os.MkdirAll("output", 0o755); err == nil {
		if globalLogFile, err := os.OpenFile(globalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			writers = append(writers, globalLogFile)
		}
	}
	writers = append(writers, logFile)

	// Determine output writers based on configuration
	var logger zerolog.Logger

	if cfg.Logging.Paranoid {
		// Paranoid mode: fichiers uniquement, jamais stdout
		multi := zerolog.MultiLevelWriter(writers...)
		logger = zerolog.New(multi).With().Timestamp().Logger()
	} else if cfg.Logging.Verbose {
		// Verbose mode: human-readable console + JSON files
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
		allWriters := append([]io.Writer{consoleWriter}, writers...)
		multi := zerolog.MultiLevelWriter(allWriters...)
		logger = zerolog.New(multi).With().Timestamp().Logger()
	} else {
		// Default mode (or quiet): files only, NO console
		multi := zerolog.MultiLevelWriter(writers...)
		logger = zerolog.New(multi).With().Timestamp().Logger()
	}
	return &Logger{logger}, nil
}
