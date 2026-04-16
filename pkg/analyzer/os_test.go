// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"testing"
)

func TestGuessOS(t *testing.T) {
	tests := []struct {
		name     string
		ttl      int
		win      int
		opts     []string
		expected string
		minScore int
	}{
		{
			name:     "Windows typical - TTL 128, Win 65535",
			ttl:      128,
			win:      65535,
			opts:     []string{"MSS:1460", "WSCALE:8", "SACK_PERMITTED"},
			expected: "Windows",
			minScore: 5,
		},
		{
			name:     "Linux typical - TTL 64, Win 5840",
			ttl:      64,
			win:      5840,
			opts:     []string{"MSS:1460", "WSCALE:7", "SACK_PERMITTED"},
			expected: "Linux",
			minScore: 5,
		},
		{
			name:     "BSD typical - TTL 255, Win 4128",
			ttl:      255,
			win:      4128,
			opts:     []string{"MSS:1460", "SACK_PERMITTED"},
			expected: "BSD",
			minScore: 4,
		},
		{
			name:     "Windows alternative - TTL 128, Win 64240",
			ttl:      128,
			win:      64240,
			opts:     []string{"MSS:1460", "SACK_PERMITTED"},
			expected: "Windows",
			minScore: 4,
		},
		{
			name:     "Linux alternative - TTL 64, Win 29200",
			ttl:      64,
			win:      29200,
			opts:     []string{"MSS:1460", "WSCALE:8"},
			expected: "Linux",
			minScore: 4,
		},
		{
			name:     "Unknown OS - unusual values",
			ttl:      50,
			win:      1000,
			opts:     []string{},
			expected: "Other",
			minScore: 1,
		},
		{
			name:     "Edge case - TTL 0, Win 0",
			ttl:      0,
			win:      0,
			opts:     []string{},
			expected: "Other",
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osGuess, osScore := GuessOS(tt.ttl, tt.win, tt.opts)

			if osGuess != tt.expected {
				t.Errorf("GuessOS() OS = %v, want %v", osGuess, tt.expected)
			}

			if osScore < tt.minScore {
				t.Errorf("GuessOS() score = %v, want at least %v", osScore, tt.minScore)
			}

			if osScore > 10 {
				t.Errorf("GuessOS() score = %v, should not exceed 10", osScore)
			}
		})
	}
}

func TestExtractMSS(t *testing.T) {
	tests := []struct {
		name     string
		opt      string
		expected int
	}{
		{
			name:     "Valid MSS",
			opt:      "MSS:1460",
			expected: 1460,
		},
		{
			name:     "MSS with extra text",
			opt:      "MSS:1300 extra",
			expected: 1300,
		},
		{
			name:     "Invalid MSS format",
			opt:      "MSS:abc",
			expected: 0,
		},
		{
			name:     "Empty MSS",
			opt:      "MSS:",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMSS(tt.opt)
			if result != tt.expected {
				t.Errorf("extractMSS() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Valid number",
			input:    "1460",
			expected: 1460,
		},
		{
			name:     "Number with text",
			input:    "1300abc",
			expected: 1300,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: 0,
		},
		{
			name:     "Non-numeric",
			input:    "abc",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseInt(tt.input)
			if err != nil {
				t.Errorf("parseInt() error = %v", err)
			}
			if result != tt.expected {
				t.Errorf("parseInt() = %v, want %v", result, tt.expected)
			}
		})
	}
}
