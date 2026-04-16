// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"testing"
)

func TestContainsString(t *testing.T) {
	tests := []struct {
		name     string
		haystack []string
		needle   string
		expected bool
	}{
		{
			name:     "Exact match",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "service2",
			expected: true,
		},
		{
			name:     "No match",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "service4",
			expected: false,
		},
		{
			name:     "Case insensitive match",
			haystack: []string{"Service1", "SERVICE2", "service3"},
			needle:   "service2",
			expected: true,
		},
		{
			name:     "Case insensitive match reverse",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "SERVICE2",
			expected: true,
		},
		{
			name:     "Trim spaces match",
			haystack: []string{" service1 ", "  service2  ", "service3"},
			needle:   "service2",
			expected: true,
		},
		{
			name:     "Trim spaces needle",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "  service2  ",
			expected: true,
		},
		{
			name:     "Both trim and case insensitive",
			haystack: []string{" Service1 ", "  SERVICE2  ", "service3"},
			needle:   "  service2  ",
			expected: true,
		},
		{
			name:     "Empty needle",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "",
			expected: false,
		},
		{
			name:     "Empty haystack",
			haystack: []string{},
			needle:   "service1",
			expected: false,
		},
		{
			name:     "Needle with only spaces",
			haystack: []string{"service1", "service2", "service3"},
			needle:   "   ",
			expected: false,
		},
		{
			name:     "Haystack with only spaces",
			haystack: []string{"   ", "service2", "service3"},
			needle:   "service1",
			expected: false,
		},
		{
			name:     "Complex whitespace and case",
			haystack: []string{"\t Service1\n", "  SERVICE2  ", "service3"},
			needle:   "\n  service2\t",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsString(tt.haystack, tt.needle)
			if result != tt.expected {
				t.Errorf("ContainsString(%v, %q) = %v, expected %v", tt.haystack, tt.needle, result, tt.expected)
			}
		})
	}
}
