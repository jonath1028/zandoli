// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

// StrengthPriority returns the numeric priority of a strength level
func StrengthPriority(strength string) int {
	switch strength {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
