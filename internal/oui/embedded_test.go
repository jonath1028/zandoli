// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package oui

import (
	"strings"
	"testing"
)

func TestEmbeddedOUIData(t *testing.T) {
	if EmbeddedOUIData == "" {
		t.Fatal("EmbeddedOUIData is empty")
	}

	lines := strings.Split(EmbeddedOUIData, "\n")
	if len(lines) < 1000 {
		t.Fatalf("EmbeddedOUIData seems too small: got %d lines, expected at least 1000", len(lines))
	}

	// Vérifier qu'il y a des entrées OUI valides
	foundValidEntry := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// Vérifier le format MAC (AA:BB:CC ou AA-BB-CC)
			mac := strings.ToUpper(parts[0])
			if len(mac) >= 8 && (strings.Contains(mac, ":") || strings.Contains(mac, "-")) {
				foundValidEntry = true
				break
			}
		}
	}

	if !foundValidEntry {
		t.Fatal("No valid OUI entries found in EmbeddedOUIData")
	}
}
