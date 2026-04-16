// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import "strings"

// ParseInfoParts parses an information string into a key-value map
func ParseInfoParts(info string) map[string]string {
	parts := make(map[string]string)

	// Split by semicolon and parse key=value pairs
	sections := strings.Split(info, "; ")
	for _, section := range sections {
		if strings.Contains(section, "=") {
			kv := strings.SplitN(section, "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				parts[key] = value
			}
		}
	}

	return parts
}
