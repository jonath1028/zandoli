// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"time"
)

// IsSafeTime ensures that a time.Time is safe to marshal as JSON.
func IsSafeTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1971 && t.Year() <= 9999
}
