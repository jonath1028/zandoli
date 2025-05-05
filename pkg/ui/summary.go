package ui

import (
	"fmt"
	"sort"
	"strings"

	"zandoli/pkg/sniffer"
)

func DisplaySummary(hosts []sniffer.Host) {
	if len(hosts) == 0 {
		fmt.Println("\n========== SCAN SUMMARY ==========")
		fmt.Println("No hosts discovered.")
		fmt.Println("==================================\n")
		return
	}

	passive := filterByMethod(hosts, "passive")
	active := filterByMethod(hosts, "active")

	fmt.Println("\n========== SCAN SUMMARY ==========\n")
	if len(passive) > 0 {
		fmt.Printf("🟢 Passive Discovery (Total: %d)\n", len(passive))
		displayTable(passive)
	}
	if len(active) > 0 {
		fmt.Printf("🔴 Active Discovery (Total: %d)\n", len(active))
		displayTable(active)
	}

	fmt.Printf("\n🧮 Total hosts discovered: %d\n", len(hosts))
	fmt.Println("==================================\n")
}

func filterByMethod(hosts []sniffer.Host, method string) []sniffer.Host {
	var result []sniffer.Host
	for _, h := range hosts {
		if strings.ToLower(h.DetectionMethod) == method {
			result = append(result, h)
		}
	}
	return result
}

func displayTable(hosts []sniffer.Host) {
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP.String() < hosts[j].IP.String()
	})

	divider := "+----------------+---------------------+---------------------------+-------------------+-------------+------------------------------+"
	fmt.Println(divider)
	fmt.Printf("| %-15s | %-19s | %-25s | %-17s | %-11s | %-28s |\n",
		"IP Address", "MAC Address", "Vendor", "Detection Method", "Category", "Protocols")
	fmt.Println(divider)

	for _, h := range hosts {
		vendor := truncate(h.Vendor, 25)
		if vendor == "" {
			vendor = "Unknown"
		}
		protos := truncate(formatProtocols(h.ProtocolsSeen), 28)

		fmt.Printf("| %-15s | %-19s | %-25s | %-17s | %-11s | %-28s |\n",
			h.IP.String(),
			h.MAC.String(),
			vendor,
			h.DetectionMethod,
			h.Category,
			protos,
		)
	}

	fmt.Println(divider)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func formatProtocols(m map[string]bool) string {
	if len(m) == 0 {
		return ""
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

