// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import "strings"

// AppendUnique appends items to a slice, skipping any that are already present.
func AppendUnique[T comparable](slice []T, items ...T) []T {
	for _, item := range items {
		found := false
		for _, existing := range slice {
			if existing == item {
				found = true
				break
			}
		}
		if !found {
			slice = append(slice, item)
		}
	}
	return slice
}

// ContainsString checks if a string is present in a slice (case-insensitive, trimmed)
// Robust version: trim + case-insensitive
func ContainsString(hay []string, needle string) bool {
	n := strings.TrimSpace(strings.ToLower(needle))
	for _, s := range hay {
		if strings.TrimSpace(strings.ToLower(s)) == n {
			return true
		}
	}
	return false
}

// MergeIntUnique merges two int slices, removing duplicates
func MergeIntUnique(a, b []int) []int {
	seen := make(map[int]bool)
	result := make([]int, 0, len(a)+len(b))

	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	return result
}

// MergeStrUnique merges two string slices, removing duplicates
func MergeStrUnique(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	return result
}
