// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package logger

import (
	"os"

	"github.com/rs/zerolog"
)

// MustInitLoggerForTest returns a structured logger for unit tests.
func MustInitLoggerForTest() *Logger {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
	zlog := zerolog.New(output).With().Timestamp().Logger()
	return &Logger{zlog} // ✅ pas Logger: zlog
}

