// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import "strings"

// InferCategory returns a category based on vendor string only.
// This is the Level 6 (lowest confidence) fallback. For full signal-based
// classification, use ClassifyHost() instead.
func InferCategory(vendor string) string {
	if vendor == "" {
		return "unknown"
	}
	v := strings.ToLower(vendor)

	// Ordered by specificity to avoid ambiguous matches (e.g., "hp" inside "hpe aruba")
	for _, entry := range vendorCategories {
		if strings.Contains(v, entry.keyword) {
			return entry.category
		}
	}

	return "unknown"
}

// vendorCategory maps a vendor substring to a category, checked in order.
type vendorCategory struct {
	keyword  string
	category string
}

// vendorCategories is ordered so more-specific matches come before ambiguous ones.
var vendorCategories = []vendorCategory{
	// Network — check before generic "hp" to avoid misclassifying "hpe aruba"
	{"hpe aruba", "network"},
	{"procurve", "network"},
	{"cisco", "network"},
	{"meraki", "network"},
	{"aruba", "network"},
	{"juniper", "network"},
	{"ubiquiti", "network"},
	{"tp-link", "network"},
	{"netgear", "network"},
	{"mikrotik", "network"},
	{"zyxel", "network"},
	{"fortinet", "network"},
	{"arista", "network"},
	{"brocade", "network"},
	{"ruckus", "network"},
	// Printer
	{"canon", "printer"},
	{"epson", "printer"},
	{"brother", "printer"},
	{"xerox", "printer"},
	{"ricoh", "printer"},
	{"lexmark", "printer"},
	{"kyocera", "printer"},
	// Client / computer
	{"dell", "client"},
	{"lenovo", "client"},
	{"compal", "client"},
	{"lcfc", "client"},
	{"intel", "client"},
	{"microsoft", "client"},
	{"apple", "client"},
	{"samsung", "client"},
	{"xiaomi", "client"},
	// IoT
	{"espressif", "iot"},
	{"tuya", "iot"},
	// VM
	{"pcs systemtechnik", "server"},
	{"vmware", "server"},
	// NAS
	{"synology", "server"},
	{"qnap", "server"},
}
