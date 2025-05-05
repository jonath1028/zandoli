package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

func InitLoggerFromConfig(levelStr string, logFilePath string) {
        consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
        var multiWriter io.Writer = consoleWriter

        if logFilePath != "" {
                file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
                if err == nil {
                        multiWriter = io.MultiWriter(consoleWriter, file)
                } else {
                        consoleWriter.FormatMessage = func(i interface{}) string {
                                return "[LOGGER ERROR] " + i.(string)
                        }
                        consoleWriter.Write([]byte("Failed to open log file, falling back to console only.\n"))
                }
        }

        var level zerolog.Level
        switch levelStr {
        case "debug":
                level = zerolog.DebugLevel
        case "info", "":
                level = zerolog.InfoLevel
        case "warn":
                level = zerolog.WarnLevel
        case "error":
                level = zerolog.ErrorLevel
        case "fatal":
                level = zerolog.FatalLevel
        default:
                level = zerolog.InfoLevel
        }

        Logger = zerolog.New(multiWriter).With().Timestamp().Logger().Level(level)
}

