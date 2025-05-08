package ui

import (
	"fmt"
	"strings"

	"zandoli/pkg/sniffer"
)

// DisplaySummary affiche un récapitulatif des hôtes découverts
func DisplaySummary(hosts []sniffer.Host) {
	if len(hosts) == 0 {
		fmt.Println("========== SCAN SUMMARY ==========")
		fmt.Println("No hosts discovered.")
		fmt.Println("==================================")
		return
	}

	passive := filterHostsByMethod(hosts, "passive")
	active := filterHostsByMethod(hosts, "active")

	fmt.Println("========== SCAN SUMMARY ==========")
	if len(passive) > 0 {
		fmt.Printf("🟢 Passive Discovery (Total: %d)\n", len(passive))
		displayHostsTable(passive)
	}
	if len(active) > 0 {
		fmt.Printf("🔴 Active Discovery (Total: %d)\n", len(active))
		displayHostsTable(active)
	}

	fmt.Printf("\n🧮 Total hosts discovered: %d\n", len(hosts))
	fmt.Println("==================================")
}

func filterHostsByMethod(hosts []sniffer.Host, method string) []sniffer.Host {
	var result []sniffer.Host
	for _, h := range hosts {
		if strings.ToLower(h.DetectionMethod) == method {
			result = append(result, h)
		}
	}
	return result
}
