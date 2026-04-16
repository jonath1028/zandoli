// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"strings"

	"zandoli/pkg/model"
)

// Classification represents the result of host classification.
type Classification struct {
	Category   string   // network, server, client, iot, printer, unknown
	Confidence int      // 0-100
	Signals    []string // what determined this classification
	Source     string   // "cdp", "lldp", "l2", "role", "services", "os", "vendor"
}

// ClassifyHost determines the functional category of a host using a hierarchical
// signal-based approach. Higher-confidence signals (CDP/LLDP capabilities) take
// precedence over lower-confidence ones (vendor OUI substring matching).
func ClassifyHost(host *model.Host) Classification {
	// Level 1: CDP/LLDP capabilities (confidence 95-100)
	if c, ok := classifyFromCDP(host); ok {
		return c
	}
	if c, ok := classifyFromLLDP(host); ok {
		return c
	}

	// Level 2: L2 protocol presence (confidence 85-95)
	if c, ok := classifyFromL2(host); ok {
		return c
	}

	// Level 3: Network role signals (confidence 75-85)
	if c, ok := classifyFromRole(host); ok {
		return c
	}

	// Level 4: Service/protocol signals (confidence 60-75)
	if c, ok := classifyFromServices(host); ok {
		return c
	}

	// Level 5: OS fingerprint hints (confidence 40-60)
	if c, ok := classifyFromOS(host); ok {
		return c
	}

	// Level 6: Vendor OUI fallback (confidence 20-40)
	if c, ok := classifyFromVendor(host); ok {
		return c
	}

	return Classification{Category: "unknown", Confidence: 0, Source: "none"}
}

// classifyFromCDP checks CDP capabilities for device self-declaration.
func classifyFromCDP(host *model.Host) (Classification, bool) {
	if host.CDP == nil {
		return Classification{}, false
	}

	caps := host.CDP.DecodedCaps
	if len(caps) == 0 && host.CDP.Capabilities != 0 {
		// Decode from raw capability bits
		if host.CDP.Capabilities&0x01 != 0 {
			caps = append(caps, "Router")
		}
		if host.CDP.Capabilities&0x08 != 0 {
			caps = append(caps, "Switch")
		}
	}

	for _, cap := range caps {
		c := strings.ToLower(cap)
		if c == "router" || c == "switch" || c == "bridge" {
			return Classification{
				Category:   "network",
				Confidence: 100,
				Signals:    []string{"CDP_CAP:" + cap},
				Source:     "cdp",
			}, true
		}
	}

	// CDP platform containing server keywords
	platform := strings.ToLower(host.CDP.Platform)
	if containsAny(platform, "server", "esxi", "hyperv") {
		return Classification{
			Category:   "server",
			Confidence: 95,
			Signals:    []string{"CDP_PLATFORM:" + host.CDP.Platform},
			Source:     "cdp",
		}, true
	}

	// CDP present but no specific capability matched → still network device
	if host.CDP.DeviceID != "" {
		return Classification{
			Category:   "network",
			Confidence: 95,
			Signals:    []string{"CDP_DEVICE:" + host.CDP.DeviceID},
			Source:     "cdp",
		}, true
	}

	return Classification{}, false
}

// classifyFromLLDP checks LLDP capabilities for device self-declaration.
func classifyFromLLDP(host *model.Host) (Classification, bool) {
	if host.LLDP == nil {
		return Classification{}, false
	}

	for _, cap := range host.LLDP.Capabilities {
		c := strings.ToLower(cap)
		if c == "router" || c == "bridge" || c == "wlan ap" || c == "repeater" {
			return Classification{
				Category:   "network",
				Confidence: 100,
				Signals:    []string{"LLDP_CAP:" + cap},
				Source:     "lldp",
			}, true
		}
		if c == "telephone" {
			// Cisco IP phones declare "Telephone" capability
			return Classification{
				Category:   "iot",
				Confidence: 95,
				Signals:    []string{"LLDP_CAP:Telephone"},
				Source:     "lldp",
			}, true
		}
	}

	// LLDP sysDescr containing server software
	if host.LLDP.SysDescr != "" {
		descr := strings.ToLower(host.LLDP.SysDescr)
		if containsAny(descr, "server", "esxi", "hyperv") {
			return Classification{
				Category:   "server",
				Confidence: 95,
				Signals:    []string{"LLDP_DESCR:" + host.LLDP.SysDescr},
				Source:     "lldp",
			}, true
		}
	}

	// LLDP present with sysName → network device
	if host.LLDP.SysName != "" {
		return Classification{
			Category:   "network",
			Confidence: 95,
			Signals:    []string{"LLDP_SYSNAME:" + host.LLDP.SysName},
			Source:     "lldp",
		}, true
	}

	return Classification{}, false
}

// classifyFromL2 checks L2 protocol signals (STP, EAPOL, HSRP, VRRP).
func classifyFromL2(host *model.Host) (Classification, bool) {
	// HSRP/VRRP — gateway redundancy is a definitive network signal
	if len(host.GatewayRedundancy) > 0 {
		proto := host.GatewayRedundancy[0].Protocol
		return Classification{
			Category:   "network",
			Confidence: 95,
			Signals:    []string{"GW_REDUNDANCY:" + proto},
			Source:     "l2",
		}, true
	}

	if host.STP != nil || host.L2Signals.STP {
		return Classification{
			Category:   "network",
			Confidence: 90,
			Signals:    []string{"STP_BPDU"},
			Source:     "l2",
		}, true
	}
	if host.L2Signals.EAPOL {
		return Classification{
			Category:   "network",
			Confidence: 85,
			Signals:    []string{"EAPOL_AUTHENTICATOR"},
			Source:     "l2",
		}, true
	}
	return Classification{}, false
}

// classifyFromRole checks inferred role and DHCP gateway signals.
func classifyFromRole(host *model.Host) (Classification, bool) {
	// Gateway heuristic: .1 or .254 IP with routing signals
	if host.IP != nil && len(host.IP) >= 4 {
		lastOctet := host.IP[len(host.IP)-1]
		if lastOctet == 1 || lastOctet == 254 {
			// Check for routing protocols
			for _, proto := range host.Protocols {
				p := strings.ToUpper(proto)
				if p == "SSDP" || p == "IGMP" {
					return Classification{
						Category:   "network",
						Confidence: 80,
						Signals:    []string{"GATEWAY_IP", proto},
						Source:     "role",
					}, true
				}
			}
		}
	}

	// DHCP server
	for _, port := range host.Services.UDP {
		if port == 67 {
			return Classification{
				Category:   "server",
				Confidence: 80,
				Signals:    []string{"DHCP_SERVER"},
				Source:     "role",
			}, true
		}
	}

	// DNS server
	if host.Role == "server" {
		for _, port := range host.Services.UDP {
			if port == 53 {
				return Classification{
					Category:   "server",
					Confidence: 75,
					Signals:    []string{"DNS_SERVER"},
					Source:     "role",
				}, true
			}
		}
	}

	return Classification{}, false
}

// classifyFromServices checks TCP/UDP service patterns.
func classifyFromServices(host *model.Host) (Classification, bool) {
	// SMB server
	if host.Role == "server" {
		for _, port := range host.Services.TCP {
			if port == 445 || port == 139 {
				return Classification{
					Category:   "server",
					Confidence: 70,
					Signals:    []string{"SMB_SERVER"},
					Source:     "services",
				}, true
			}
		}
	}

	// Many open TCP server ports → server
	if len(host.Services.TCP) >= 3 && host.Role == "server" {
		return Classification{
			Category:   "server",
			Confidence: 65,
			Signals:    []string{"MULTI_TCP_SERVICES"},
			Source:     "services",
		}, true
	}

	// mDNS/SSDP with IoT-like vendor
	if hasProtocol(host, "SSDP") || hasProtocol(host, "mDNS") {
		vendor := strings.ToLower(host.Vendor)
		if containsAny(vendor, "nest", "ring", "sonos", "philips", "hue", "tuya", "espressif", "shelly", "tasmota") {
			return Classification{
				Category:   "iot",
				Confidence: 70,
				Signals:    []string{"MDNS_SSDP_IOT_VENDOR"},
				Source:     "services",
			}, true
		}
	}

	return Classification{}, false
}

// classifyFromOS checks OS fingerprint combined with other signals.
func classifyFromOS(host *model.Host) (Classification, bool) {
	os := strings.ToLower(host.OSGuess)

	if os == "embedded" || os == "other" {
		vendor := strings.ToLower(host.Vendor)
		if isNetworkVendorStr(vendor) {
			return Classification{
				Category:   "network",
				Confidence: 50,
				Signals:    []string{"OS_EMBEDDED", "VENDOR_NETWORK"},
				Source:     "os",
			}, true
		}
		if containsAny(vendor, "espressif", "tuya", "nest", "ring", "sonos") {
			return Classification{
				Category:   "iot",
				Confidence: 45,
				Signals:    []string{"OS_EMBEDDED", "VENDOR_IOT"},
				Source:     "os",
			}, true
		}
	}

	return Classification{}, false
}

// classifyFromVendor is the last-resort vendor OUI fallback.
func classifyFromVendor(host *model.Host) (Classification, bool) {
	vendor := strings.ToLower(host.Vendor)
	if vendor == "" || vendor == "unknown" {
		return Classification{}, false
	}

	// Network vendors (comprehensive list matching oui_network.go)
	if isNetworkVendorStr(vendor) {
		return Classification{
			Category:   "network",
			Confidence: 35,
			Signals:    []string{"VENDOR:" + host.Vendor},
			Source:     "vendor",
		}, true
	}

	// Printer vendors — use specific keywords to avoid "hp" substring matching
	if containsAny(vendor, "canon", "epson", "brother", "xerox", "ricoh", "lexmark", "konica", "kyocera") {
		return Classification{
			Category:   "printer",
			Confidence: 35,
			Signals:    []string{"VENDOR:" + host.Vendor},
			Source:     "vendor",
		}, true
	}

	// IoT vendors
	if containsAny(vendor, "espressif", "tuya", "nest", "ring", "sonos", "philips hue", "shelly", "tasmota") {
		return Classification{
			Category:   "iot",
			Confidence: 30,
			Signals:    []string{"VENDOR:" + host.Vendor},
			Source:     "vendor",
		}, true
	}

	// Computer vendors → client
	if containsAny(vendor, "dell", "lenovo", "apple", "samsung", "intel", "microsoft", "realtek", "compal", "lcfc", "wistron") {
		return Classification{
			Category:   "client",
			Confidence: 25,
			Signals:    []string{"VENDOR:" + host.Vendor},
			Source:     "vendor",
		}, true
	}

	// VM vendors
	if containsAny(vendor, "vmware", "pcs systemtechnik", "xensource") {
		return Classification{
			Category:   "server",
			Confidence: 25,
			Signals:    []string{"VENDOR_VM:" + host.Vendor},
			Source:     "vendor",
		}, true
	}

	return Classification{}, false
}

// isNetworkVendorStr checks if a lowercased vendor string matches network equipment.
func isNetworkVendorStr(vendor string) bool {
	return containsAny(vendor, "cisco", "meraki", "juniper", "junos", "palo alto",
		"fortinet", "fortios", "arista", "aruba", "hpe aruba", "edgecore",
		"ruckus", "extreme networks", "checkpoint", "check point", "sophos",
		"f5 networks", "mist systems", "ruijie", "ubiquiti", "mikrotik",
		"zyxel", "brocade", "avm", "fritz!box", "sercomm", "tp-link", "netgear",
		"procurve", "allied telesis", "dlink", "d-link", "huawei")
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasProtocol checks if a host has a specific protocol in its list.
func hasProtocol(host *model.Host, proto string) bool {
	for _, p := range host.Protocols {
		if strings.EqualFold(p, proto) {
			return true
		}
	}
	return false
}
