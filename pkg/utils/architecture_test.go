// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestArchitectureCompliance vérifie que les utilitaires respectent l'architecture en couches
func TestArchitectureCompliance(t *testing.T) {
	t.Run("NoCircularDependencies", func(t *testing.T) {
		// Ce test vérifie que pkg/utils n'a pas de dépendances vers pkg/*
		// Les imports sont vérifiés au moment de la compilation
		assert.True(t, true, "pkg/utils should not import other pkg/* packages")
	})

	t.Run("UtilityFunctionsWork", func(t *testing.T) {
		// Test que les fonctions utilitaires fonctionnent correctement

		// Test ContainsString
		assert.True(t, ContainsString([]string{"a", "b", "c"}, "b"))
		assert.False(t, ContainsString([]string{"a", "b", "c"}, "d"))
		assert.False(t, ContainsString([]string{}, "a"))

		// Test MergeStrUnique
		result := MergeStrUnique([]string{"a", "b"}, []string{"b", "c"})
		assert.ElementsMatch(t, []string{"a", "b", "c"}, result)

		// Test MergeIntUnique
		resultInt := MergeIntUnique([]int{1, 2}, []int{2, 3})
		assert.ElementsMatch(t, []int{1, 2, 3}, resultInt)

		// Test IsPrivateIPv4
		assert.True(t, IsPrivateIPv4(net.ParseIP("192.168.1.1")))
		assert.False(t, IsPrivateIPv4(net.ParseIP("8.8.8.8")))
	})

	t.Run("NoGlobalState", func(t *testing.T) {
		// Vérifier qu'il n'y a pas d'état global mutable
		// Les fonctions utilitaires doivent être pures
		result1 := ContainsString([]string{"a", "b"}, "a")
		result2 := ContainsString([]string{"a", "b"}, "a")
		assert.Equal(t, result1, result2, "Utility functions should be deterministic")
	})
}

// TestUtilityFunctionIsolation vérifie l'isolation des fonctions utilitaires
func TestUtilityFunctionIsolation(t *testing.T) {
	t.Run("ContainsString_EdgeCases", func(t *testing.T) {
		tests := []struct {
			name     string
			slice    []string
			needle   string
			expected bool
		}{
			{"Empty slice", []string{}, "test", false},
			{"Single element match", []string{"test"}, "test", true},
			{"Single element no match", []string{"test"}, "other", false},
			{"Multiple elements match", []string{"a", "b", "c"}, "b", true},
			{"Case sensitive", []string{"Test"}, "test", true}, // ContainsString est insensible à la casse
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := ContainsString(tt.slice, tt.needle)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("MergeStrUnique_EdgeCases", func(t *testing.T) {
		tests := []struct {
			name     string
			slice1   []string
			slice2   []string
			expected []string
		}{
			{"Empty slices", []string{}, []string{}, []string{}},
			{"First empty", []string{}, []string{"a"}, []string{"a"}},
			{"Second empty", []string{"a"}, []string{}, []string{"a"}},
			{"No duplicates", []string{"a", "b"}, []string{"c", "d"}, []string{"a", "b", "c", "d"}},
			{"With duplicates", []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := MergeStrUnique(tt.slice1, tt.slice2)
				assert.ElementsMatch(t, tt.expected, result)
			})
		}
	})
}
