// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"strings"
)

// NormalizeVendor normalise le nom d'un vendeur pour la comparaison
func NormalizeVendor(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	// variantes courantes
	v = strings.ReplaceAll(v, "  ", " ")
	v = strings.ReplaceAll(v, "corporation", "")
	v = strings.ReplaceAll(v, "corp.", "")
	v = strings.ReplaceAll(v, "inc.", "")
	v = strings.TrimSpace(v)
	return v
}

// networkVendorKeywords contains keywords for network equipment vendors
// Positive list: if the vendor OUI contains one of these words (case-insensitive), it is a network device
var networkVendorKeywords = []string{
	"cisco",
	"meraki",
	"juniper",
	"junos",
	"palo alto",
	"fortinet",
	"fortios",
	"arista",
	"aruba",
	"hpe aruba",
	"edgecore",
	"ruckus",
	"extreme networks",
	"checkpoint",
	"check point",
	"sophos",
	"f5 networks",
	"mist systems",
	"ruijie",
	"ubiquiti",
	"mikrotik",
	"zyxel",
	"brocade",
	// CPE/consumer routers we want to consider as "network":
	"avm",
	"fritz!box",
	"sercomm",
	"tp-link",
	"netgear",
}

// excludedVendorKeywords contains vendors to explicitly exclude (client/server workstations)
var excludedVendorKeywords = []string{
	"apple",
	"dell",
	"hp inc",
	"lenovo",
	"microsoft",
	"intel",
	"raspberry pi",
	"realtek",
	"wistron",
	"congatec",
	// huawei : ambigu (terminaux/phones) ⇒ exclu du fallback OUI
	"huawei",
}

// IsNetworkVendor checks if an OUI vendor corresponds to a network device.
// Returns true if it is a network device, false otherwise.
func IsNetworkVendor(vendor string) bool {
	if vendor == "" || vendor == "Unknown" {
		return false
	}

	s := NormalizeVendor(vendor)

	// Check exclusions first
	for _, excluded := range excludedVendorKeywords {
		if strings.Contains(s, excluded) {
			return false
		}
	}

	// Check network keywords
	for _, keyword := range networkVendorKeywords {
		if strings.Contains(s, keyword) {
			return true
		}
	}

	return false
}
