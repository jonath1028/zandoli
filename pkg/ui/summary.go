// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package ui

import (
	"fmt"
	"zandoli/pkg/model"
)

// PrintScanSummary renders the summary of the scan to the CLI.
func PrintScanSummary(scanID string, all []*model.Host, passive []*model.Host, active []*model.Host, outputDir string) {
	anomalies := 0
	for _, h := range all {
		if len(h.Anomalies) > 0 {
			anomalies++
		}
	}

	fmt.Println("\033[90m================ ZANDOLI SUMMARY ================\033[0m")
	fmt.Printf("\033[97mScan ID      :\033[0m \033[92m%s\033[0m\n", scanID)
	fmt.Printf("\033[97mProfile      :\033[0m \033[92mdefault\033[0m\n")
	fmt.Printf("\033[97mTotal Hosts  :\033[0m \033[92m%d\033[0m\n", len(all))
	fmt.Printf("\033[97mFrom Passive :\033[0m \033[92m%d\033[0m\n", len(passive))
	fmt.Printf("\033[97mFrom Active  :\033[0m \033[92m%d\033[0m\n", len(active))
	fmt.Printf("\033[97mWith Anomaly :\033[0m \033[92m%d\033[0m\n", anomalies)
	fmt.Printf("\033[97mExported To  :\033[0m \033[92m%s\033[0m\n", outputDir)
	fmt.Println("\033[90m==================================================\033[0m")
}

