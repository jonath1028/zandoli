// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides role inference capabilities based on CDP capabilities and L2 signals.
package analyzer

import (
	"strings"

	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// NormalizeRole normalizes role values to the three final categories: client, server, reseau
func NormalizeRole(r string) string {
	r = strings.ToLower(r)
	// strip common accents to avoid mismatches with maps keyed on "reseau"
	replacer := strings.NewReplacer("é", "e", "è", "e", "ê", "e", "ë", "e", "à", "a", "â", "a")
	r = replacer.Replace(r)

	switch r {
	case "router", "switch", "network_device", "repeater", "access_point", "reseau", "reseaux":
		return "reseau"
	case "server", "serveur":
		return "server"
	case "client":
		return "client"
	default:
		return r
	}
}

// CDP Capability bits (decimal values as specified)
const (
	CDPCapRouter   = 0x01 // Router
	CDPCapTB       = 0x02 // Transparent Bridge
	CDPCapSRB      = 0x04 // Source Route Bridge
	CDPCapSwitch   = 0x08 // Switch/Bridge
	CDPCapHost     = 0x10 // Host
	CDPCapIGMP     = 0x20 // IGMP
	CDPCapRepeater = 0x40 // Repeater
	CDPCapPhone    = 0x80 // Phone/AP
)

// InferRole analyzes a host and infers its role with confidence and signals
func InferRole(host *model.Host) *model.RoleInfo {
	if host == nil {
		return nil
	}

	// A) L2 "strongest of all" (absolute short-circuit)
	// Before any other logic, if the host has an authentic L2 signal, immediately set the role
	hasL2 := (host.L2Signals.CDP || host.L2Signals.LLDP || host.L2Signals.STP || host.L2Signals.EAPOL) ||
		(host.CDP != nil || host.LLDP != nil || host.STP != nil)
	if hasL2 {
		role := "reseau"
		return &model.RoleInfo{Role: NormalizeRole(role), Confidence: 100, Signals: []string{"L2_PRESENT"}}
	}

	// B) OUI → Network (fallback if no L2)
	// If the vendor OUI corresponds to a network device, classify as network
	if host.Vendor != "" && utils.IsNetworkVendor(host.Vendor) {
		signals := []string{"OUI_INFRA", "OUI:" + host.Vendor}
		return &model.RoleInfo{
			Role:       NormalizeRole("reseau"),
			Confidence: 90,
			Signals:    signals,
			Rationale:  "Network device identified by OUI vendor",
		}
	}

	// C) Gateway heuristic: IP ending in .1 or .254 + SSDP/UPnP → residential gateway
	// Covers consumer routers (TP-Link, Netgear...) whose OUI is unknown in the local database
	if host.IP != nil && len(host.IP) >= 4 {
		lastOctet := host.IP[len(host.IP)-1]
		if lastOctet == 1 || lastOctet == 254 {
			for _, proto := range host.Protocols {
				if strings.ToUpper(proto) == "SSDP" || strings.ToUpper(proto) == "IGMP" {
					return &model.RoleInfo{
						Role:       NormalizeRole("reseau"),
						Confidence: 80,
						Signals:    []string{"GATEWAY_IP", proto},
						Rationale:  "Residential gateway detected by IP suffix and UPnP/IGMP",
					}
				}
			}
		}
	}

	// If we reach here, no L2 or network OUI: Client vs Server inference based on specific signals
	// D) Actual Client vs Server decision
	csRole, csScoreData := inferClientServer(host)

	// Calculate confidence based on scores
	csConfidence := csScoreData.server
	if csScoreData.client > csScoreData.server {
		csConfidence = csScoreData.client
	}
	// Normalize confidence (cap at 85 to let L2/network take precedence)
	if csConfidence > 85 {
		csConfidence = 85
	}

	// If we have no strong signal, use a fallback
	if csConfidence < 20 {
		csRole = "client"
		csConfidence = 30
		csScoreData.signals = append(csScoreData.signals, "default_assumption")
	}

	return &model.RoleInfo{
		Role:       NormalizeRole(csRole),
		Confidence: csConfidence,
		Signals:    csScoreData.signals,
		Rationale:  "Client/Server role inferred from behavioral signals",
	}
}

// decodeCDPCapabilities decodes CDP capabilities bitmask into human-readable strings
func decodeCDPCapabilities(capabilities uint32) []string {
	var decoded []string

	if capabilities&CDPCapRouter != 0 {
		decoded = append(decoded, "Router")
	}
	if capabilities&CDPCapTB != 0 {
		decoded = append(decoded, "Transparent Bridge")
	}
	if capabilities&CDPCapSRB != 0 {
		decoded = append(decoded, "Source Route Bridge")
	}
	if capabilities&CDPCapSwitch != 0 {
		decoded = append(decoded, "Switch/Bridge")
	}
	if capabilities&CDPCapHost != 0 {
		decoded = append(decoded, "Host")
	}
	if capabilities&CDPCapIGMP != 0 {
		decoded = append(decoded, "IGMP")
	}
	if capabilities&CDPCapRepeater != 0 {
		decoded = append(decoded, "Repeater")
	}
	if capabilities&CDPCapPhone != 0 {
		decoded = append(decoded, "Phone/AP")
	}

	return decoded
}

// csScore represents client/server scoring for role inference
type csScore struct {
	client  int
	server  int
	signals []string
}

// inferClientServer infers client vs server role based on behavioral signals
// C) Actual Client vs Server decision based on specific signals
func inferClientServer(host *model.Host) (role string, score csScore) {
	var s csScore

	// --- SERVER signals (responses/services) ---

	// DHCP: strong server signal if present
	for _, proto := range host.Protocols {
		if strings.Contains(strings.ToUpper(proto), "DHCP") {
			s.server += 25
			s.signals = append(s.signals, "DHCP_OFFER_ACK")
			break
		}
	}

	// TCP SYN-ACK : ports serveur bien connus
	if len(host.Services.TCP) > 0 {
		serverPorts := map[int]bool{
			80: true, 443: true, 22: true, 23: true, 21: true,
			445: true, 139: true, 3389: true, 53: true, 25: true,
			110: true, 143: true, 3306: true, 5432: true, 1433: true,
		}
		for _, port := range host.Services.TCP {
			if serverPorts[port] {
				s.server += 25
				s.signals = append(s.signals, "TCP_SYNACK")
				break
			}
		}
	}

	// DNS Response : port 53 TCP/UDP
	for _, proto := range host.Protocols {
		if strings.Contains(strings.ToUpper(proto), "DNS") {
			for _, port := range host.Services.TCP {
				if port == 53 {
					s.server += 25
					s.signals = append(s.signals, "DNS_RESPONSE")
					goto dnsFound
				}
			}
			for _, port := range host.Services.UDP {
				if port == 53 {
					s.server += 25
					s.signals = append(s.signals, "DNS_RESPONSE")
					goto dnsFound
				}
			}
		dnsFound:
			break
		}
	}

	// HTTP Server : ports 80/443
	for _, proto := range host.Protocols {
		if strings.Contains(strings.ToUpper(proto), "HTTP") {
			for _, port := range host.Services.TCP {
				if port == 80 || port == 443 {
					s.server += 25
					s.signals = append(s.signals, "HTTP_SERVER_HDR")
					goto httpFound
				}
			}
		httpFound:
			break
		}
	}

	// SMB Response : ports 445/139
	for _, proto := range host.Protocols {
		if strings.Contains(strings.ToUpper(proto), "SMB") {
			for _, port := range host.Services.TCP {
				if port == 445 || port == 139 {
					s.server += 20
					s.signals = append(s.signals, "SMB_NEGOTIATE_RSP")
					goto smbFound
				}
			}
		smbFound:
			break
		}
	}

	// RDP : port 3389
	for _, port := range host.Services.TCP {
		if port == 3389 {
			s.server += 20
			s.signals = append(s.signals, "RDP_COOKIE")
			break
		}
	}

	// NTP Response : port 123 UDP
	for _, port := range host.Services.UDP {
		if port == 123 {
			s.server += 15
			s.signals = append(s.signals, "NTP_RESPONSE")
			break
		}
	}

	// --- Signaux CLIENT (initiations) ---

	// TCP SYN out : multiples protocoles actifs sans ports serveur
	hasServerPorts := len(host.Services.TCP) > 0 || len(host.Services.UDP) > 0

	if !hasServerPorts && len(host.Protocols) >= 2 {
		s.client += 20
		s.signals = append(s.signals, "TCP_SYN_OUT")
	}

	// DNS Query : DNS sans port serveur
	if !hasServerPorts {
		for _, proto := range host.Protocols {
			if strings.Contains(strings.ToUpper(proto), "DNS") {
				s.client += 15
				s.signals = append(s.signals, "DNS_QUERY")
				break
			}
		}
	}

	// HTTP Request : HTTP sans port serveur
	if !hasServerPorts {
		for _, proto := range host.Protocols {
			if strings.Contains(strings.ToUpper(proto), "HTTP") {
				s.client += 15
				s.signals = append(s.signals, "HTTP_REQUEST")
				break
			}
		}
	}

	// SMB Request : SMB sans port serveur
	if !hasServerPorts {
		for _, proto := range host.Protocols {
			if strings.Contains(strings.ToUpper(proto), "SMB") {
				s.client += 15
				s.signals = append(s.signals, "SMB_NEGOTIATE_REQ")
				break
			}
		}
	}

	// NTP Query : NTP sans port serveur
	if !hasServerPorts {
		for _, proto := range host.Protocols {
			if strings.Contains(strings.ToUpper(proto), "NTP") {
				s.client += 10
				s.signals = append(s.signals, "NTP_QUERY")
				break
			}
		}
	}

	// --- Decision (if we reach here, no L2) ---
	switch {
	case s.server > s.client+5:
		role = "server"
	case s.client > s.server+5:
		role = "client"
	default:
		// Equal/close: if at least one real server signal → server, otherwise client
		if s.server > 0 {
			role = "server"
		} else {
			role = "client"
		}
	}

	return role, s
}
