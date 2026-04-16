// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package ui

import (
	"fmt"
	"strings"
	"time"
)

func PrintProgressBar(name string, total int, displayType string, eta string, stepDelay time.Duration) func(int) {
	fmt.Printf("\033[97m%-10s\033[0m ▶ [\033[92m%s\033[0m] \033[92m%s\033[0m  \r", name, strings.Repeat("░", 40), "")

	return func(i int) {
		// Protection against division by zero and negative values
		if total <= 0 {
			bar := strings.Repeat("░", 40)
			status := "0%"
			if displayType == "time" {
				status = "0s / 0s"
			} else {
				status = "0 / 0  ETA: N/A"
			}
			fmt.Printf("\r\033[97m%-10s\033[0m ▶ [\033[92m%s\033[0m] \033[92m%s\033[0m  ", name, bar, status)
			return
		}

		// Protection against negative values
		if i < 0 {
			i = 0
		}
		if i > total {
			i = total
		}

		filled := i * 40 / total
		empty := 40 - filled
		bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

		var status string
		if displayType == "time" {
			status = fmt.Sprintf("%2ds / %2ds", i, total)
		} else {
			status = fmt.Sprintf("%3d / %3d  ETA: %s", i, total, eta)
		}

		fmt.Printf("\r\033[97m%-10s\033[0m ▶ [\033[92m%s\033[0m] \033[92m%s\033[0m  ", name, bar, status)

		if i == total {
			fmt.Println()
		}
	}
}
