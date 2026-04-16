// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package exporter handles structured export of discovered Hosts to JSON.
package exporter

import (
	"encoding/json"
	"os"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// ExportAll is a variable to allow mocking in tests
var ExportAll = exportAll

// ExportSubnets exports subnets to JSON file
func ExportSubnets(subnets []model.Subnet, path string, log *logger.Logger) error {
	// Filter subnets to include IPv4 /24 and IPv6 /64
	filteredSubnets := utils.FilterSubnets(subnets)

	f, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to create subnets.json")
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	err = enc.Encode(filteredSubnets)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to write subnets.json")
		return err
	}

	log.Info().
		Int("count", len(filteredSubnets)).
		Str("path", path).
		Msg("Exported subnets to JSON")

	return nil
}

// JSONHost represents a Host with custom JSON serialization
type JSONHost struct {
	IP               string                `json:"ip,omitempty"`   // Primary IPv4 (legacy)
	IPv6             string                `json:"ipv6,omitempty"` // Primary IPv6 (new field)
	MACStr           string                `json:"macStr,omitempty"`
	Vendor           string                `json:"vendor,omitempty"`
	Role             string                `json:"role,omitempty"`           // Unified role (single source of truth)
	RoleConfidence   int                   `json:"roleConfidence,omitempty"` // Role confidence (0-100)
	RoleSignals      []string              `json:"roleSignals,omitempty"`    // Signals used for role inference
	Protocols        []string              `json:"protocols,omitempty"`
	Info             string                `json:"info,omitempty"`
	Hostname         string                `json:"hostname,omitempty"`
	TTL              int                   `json:"ttl,omitempty"`
	OSGuess          string                `json:"osGuess,omitempty"`
	OSScore          uint8                 `json:"osScore,omitempty"`
	OSSignals        []string              `json:"osSignals,omitempty"`
	WindowSize       int                   `json:"windowSize,omitempty"`
	TCPOptions       *model.TCPOptions     `json:"tcpOptions,omitempty"`
	FirstSeen        *time.Time            `json:"firstSeen,omitempty"`
	LastSeen         *time.Time            `json:"lastSeen,omitempty"`
	Anomalies        []model.Anomaly       `json:"anomalies,omitempty"`
	Ports            []int                 `json:"ports,omitempty"`
	Source           string                `json:"source,omitempty"`
	OnlyARP          bool                  `json:"onlyArp,omitempty"`
	TTLAvg           uint8                 `json:"ttlAvg,omitempty"`
	Category         string                `json:"category,omitempty"`
	VLANs            []int                 `json:"vlans,omitempty"`
	VLANStats        map[int]int           `json:"vlanStats,omitempty"`
	PrimaryVLAN      int                   `json:"primaryVlan,omitempty"`
	PacketCount      uint64                `json:"packetCount,omitempty"`
	ByteCount        uint64                `json:"byteCount,omitempty"`
	SecurityFeatures []string              `json:"securityFeatures,omitempty"`
	IPs              []string              `json:"ips,omitempty"` // List of all observed IPs (for multi-IP hosts)
	IPsAll           []model.IPObservation `json:"ipsAll"`        // All observed IPs with their strength
	ProtocolsByIP    map[string][]string   `json:"protocolsByIP"` // IP -> observed protocols mapping
	// L2 Protocol details - always visible when present
	CDP             *model.CDPInfo  `json:"cdp,omitempty"`              // CDP details: device_id, port_id, platform, version, capabilities, native_vlan
	LLDP            *model.LLDPInfo `json:"lldp,omitempty"`             // LLDP details: chassis_id, port_id, sys_name, sys_descr, mgmt_addrs, capabilities
	STP               *model.STPInfo                  `json:"stp,omitempty"`                // STP details: bridge_id, root_bridge_id, root_path_cost, port_id, timers
	GatewayRedundancy []model.GatewayRedundancyInfo  `json:"gateway_redundancy,omitempty"` // HSRP/VRRP redundancy data
	DetectionSource   string                         `json:"detection_source,omitempty"`   // "ARP", "DHCP", "LLDP", "EAPOL", etc.

	// New fields for port and L2 signal standardization
	L2Signals model.L2SignalsInfo `json:"l2,omitempty"`       // Consolidated L2 signals
	Services  model.ServicesInfo  `json:"services,omitempty"` // Detected TCP/UDP services
}

// Export represents the canonical JSON export format
type Export struct {
	Version     string                   `json:"version"`
	GeneratedAt string                   `json:"generatedAt"`
	Count       int                      `json:"count"`
	Hosts       []map[string]interface{} `json:"hosts"`
	Subnets     []model.Subnet           `json:"subnets,omitempty"`
	Topology    *Topology                `json:"topology,omitempty"`
}

// Topology represents the network topology information
type Topology struct {
	Subnets []model.SubnetEntry `json:"subnets"`
}

// convertToJSONHost converts a model.Host to JSONHost with proper field handling
func convertToJSONHost(host *model.Host) JSONHost {
	jsonHost := JSONHost{
		MACStr:           host.MACStr,
		Vendor:           host.Vendor,
		Role:             host.Role,           // Single source of truth
		RoleConfidence:   host.RoleConfidence, // Role confidence
		RoleSignals:      host.RoleSignals,    // Signals used
		Protocols:        host.Protocols,
		Info:             host.Info,
		Hostname:         host.Hostname,
		TTL:              host.TTL,
		OSGuess:          host.OSGuess,
		OSScore:          host.OSScore,
		OSSignals:        host.OSSignals,
		WindowSize:       host.WindowSize,
		TCPOptions:       host.TCPOptions,
		Ports:            host.Ports,
		Source:           host.Source,
		OnlyARP:          host.OnlyARP,
		TTLAvg:           host.TTLAvg,
		Category:         host.Category,
		VLANs:            host.VLANs,
		VLANStats:        host.VLANStats,
		PrimaryVLAN:      host.PrimaryVLAN,
		PacketCount:      host.PacketCount,
		ByteCount:        host.ByteCount,
		SecurityFeatures: host.SecurityFeatures,
		Anomalies:        host.Anomalies,
		CDP:              host.CDP,
		LLDP:              host.LLDP,
		STP:               host.STP,
		GatewayRedundancy: host.GatewayRedundancy,
		DetectionSource:  host.Source,                            // Use existing Source field for detection_source
		IPsAll:           cleanIPsAll(host.IPsAll),               // Cleaned IP observations
		ProtocolsByIP:    cleanProtocolsByIP(host.ProtocolsByIP), // Cleaned IP -> protocols mapping
		L2Signals:        host.L2Signals,                         // Consolidated L2 signals
		Services:         host.Services,                          // Detected TCP/UDP services

		// IPsAll and ProtocolsByIP fields are already initialized in the structure
	}

	// Handle IP addresses
	if host.IP != nil {
		jsonHost.IP = host.IP.String()
	}

	// Handle IPv6 primary address
	if host.IPv6Primary != nil {
		jsonHost.IPv6 = host.IPv6Primary.String()
	}

	// Handle IPs list - collect all unique IPs from host.IPs
	allIPs := make([]string, 0)
	ipSet := make(map[string]bool)

	// Add all IPs from the IPs list
	for _, ip := range host.IPs {
		ipStr := ip.String()
		if !ipSet[ipStr] {
			allIPs = append(allIPs, ipStr)
			ipSet[ipStr] = true
		}
	}

	// Add IPs from anomalies if present (for backward compatibility)
	for _, anomaly := range host.Anomalies {
		if anomaly.Type == "mac_multiple_ip" && anomaly.Parameters != nil {
			if ips, ok := anomaly.Parameters["ips"].([]string); ok {
				for _, ip := range ips {
					if !ipSet[ip] {
						allIPs = append(allIPs, ip)
						ipSet[ip] = true
					}
				}
			}
		}
	}

	if len(allIPs) > 0 {
		jsonHost.IPs = allIPs
	}

	// Handle timestamps with proper formatting
	if !host.FirstSeen.IsZero() {
		jsonHost.FirstSeen = &host.FirstSeen
	}
	if !host.LastSeen.IsZero() {
		jsonHost.LastSeen = &host.LastSeen
	}

	return jsonHost
}

func exportAll(hosts []*model.Host, path string, log *logger.Logger) error {
	validJSONHosts := make([]map[string]interface{}, 0, len(hosts))

	for _, h := range hosts {
		if !utils.IsSafeTime(h.FirstSeen) || !utils.IsSafeTime(h.LastSeen) {
			log.Warn().
				Str("mac", h.MACStr).
				Time("firstSeen", h.FirstSeen).
				Time("lastSeen", h.LastSeen).
				Msg("Skipped host with invalid timestamp")
			continue
		}

		// Convert to JSONHost first, then to map[string]interface{}
		jsonHost := convertToJSONHost(h)

		// Convert JSONHost to map[string]interface{} for canonical format
		hostMap := make(map[string]interface{})

		// Helper function to add field only if not empty/zero/nil
		addIfNotEmpty := func(key string, value interface{}) {
			if value == nil {
				return // Ignore nil values
			}

			switch v := value.(type) {
			case string:
				if v != "" && v != "<nil>" {
					hostMap[key] = v
				}
			case int:
				if v != 0 {
					hostMap[key] = v
				}
			case uint8:
				if v != 0 {
					hostMap[key] = v
				}
			case uint64:
				if v != 0 {
					hostMap[key] = v
				}
			case bool:
				if v {
					hostMap[key] = v
				}
			case []string:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case []int:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case []model.Anomaly:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case map[string]int:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case *time.Time:
				if v != nil && !v.IsZero() {
					hostMap[key] = v
				}
			case *model.TCPOptions:
				if v != nil {
					hostMap[key] = v
				}
			case *model.CDPInfo:
				if v != nil {
					hostMap[key] = v
				}
			case *model.LLDPInfo:
				if v != nil {
					hostMap[key] = v
				}
			case *model.STPInfo:
				if v != nil {
					hostMap[key] = v
				}
			case []model.GatewayRedundancyInfo:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case []model.IPObservation:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case map[string][]string:
				if len(v) > 0 {
					hostMap[key] = v
				}
			case model.L2SignalsInfo:
				// Check if at least one authentic L2 signal is present
				// (only CDP, LLDP, STP, 802.1X/EAPOL, VLAN)
				if len(v.VLANs) > 0 || v.EAPOL || v.STP || v.LLDP || v.CDP {
					hostMap[key] = v
				}
			case model.ServicesInfo:
				// Check if at least one field is non-empty
				if len(v.TCP) > 0 || len(v.UDP) > 0 {
					hostMap[key] = v
				}
			default:
				// Check that the value is not a "<nil>" string
				if str, ok := v.(string); ok && str == "<nil>" {
					return // Ignore "<nil>" strings
				}
				hostMap[key] = v
			}
		}

		addIfNotEmpty("ip", jsonHost.IP)
		addIfNotEmpty("macStr", jsonHost.MACStr)
		addIfNotEmpty("vendor", jsonHost.Vendor)
		addIfNotEmpty("role", jsonHost.Role)
		addIfNotEmpty("roleConfidence", jsonHost.RoleConfidence)
		addIfNotEmpty("roleSignals", jsonHost.RoleSignals)
		addIfNotEmpty("protocols", jsonHost.Protocols)
		addIfNotEmpty("info", jsonHost.Info)
		addIfNotEmpty("hostname", jsonHost.Hostname)
		addIfNotEmpty("ttl", jsonHost.TTL)
		addIfNotEmpty("osGuess", jsonHost.OSGuess)
		addIfNotEmpty("osScore", jsonHost.OSScore)
		addIfNotEmpty("osSignals", jsonHost.OSSignals)
		addIfNotEmpty("windowSize", jsonHost.WindowSize)
		addIfNotEmpty("tcpOptions", jsonHost.TCPOptions)
		addIfNotEmpty("firstSeen", jsonHost.FirstSeen)
		addIfNotEmpty("lastSeen", jsonHost.LastSeen)
		addIfNotEmpty("anomalies", jsonHost.Anomalies)
		addIfNotEmpty("ports", jsonHost.Ports)
		addIfNotEmpty("source", jsonHost.Source)
		addIfNotEmpty("onlyArp", jsonHost.OnlyARP)
		addIfNotEmpty("ttlAvg", jsonHost.TTLAvg)
		addIfNotEmpty("category", jsonHost.Category)
		addIfNotEmpty("vlans", jsonHost.VLANs)
		addIfNotEmpty("vlanStats", jsonHost.VLANStats)
		addIfNotEmpty("primaryVlan", jsonHost.PrimaryVLAN)
		addIfNotEmpty("packetCount", jsonHost.PacketCount)
		addIfNotEmpty("byteCount", jsonHost.ByteCount)
		addIfNotEmpty("securityFeatures", jsonHost.SecurityFeatures)
		addIfNotEmpty("cdp", jsonHost.CDP)
		addIfNotEmpty("lldp", jsonHost.LLDP)
		addIfNotEmpty("stp", jsonHost.STP)
		addIfNotEmpty("gateway_redundancy", jsonHost.GatewayRedundancy)
		addIfNotEmpty("detection_source", jsonHost.DetectionSource)
		addIfNotEmpty("ips", jsonHost.IPs)
		addIfNotEmpty("ipv6", jsonHost.IPv6)
		addIfNotEmpty("ipsAll", jsonHost.IPsAll)
		addIfNotEmpty("protocolsByIP", jsonHost.ProtocolsByIP)
		addIfNotEmpty("l2", jsonHost.L2Signals)
		addIfNotEmpty("services", jsonHost.Services)

		validJSONHosts = append(validJSONHosts, hostMap)
	}

	// Compute subnets from valid hosts
	allSubnets := analyzer.ComputeActiveSubnets(hosts)

	// Retrieve VLAN-aware topology subnets
	topologySubnets := analyzer.GetTopologySubnets()

	// Create the export in canonical format
	export := Export{
		Version:     "1",
		GeneratedAt: time.Now().Format(time.RFC3339),
		Count:       len(validJSONHosts),
		Hosts:       validJSONHosts,
		Subnets:     allSubnets,
		Topology:    &Topology{Subnets: topologySubnets},
	}

	f, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to create hosts.json")
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // Ensure UTF-8 characters are not escaped

	err = enc.Encode(export)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to write hosts.json")
		return err
	}

	log.Info().
		Int("count", len(validJSONHosts)).
		Int("subnets", len(allSubnets)).
		Int("topology_subnets", len(topologySubnets)).
		Str("path", path).
		Msg("Exported hosts, subnets and topology to JSON")
	if len(validJSONHosts) == 0 {
		log.Error().
			Int("total_hosts", len(hosts)).
			Msg("No valid hosts passed the export filter. hosts.json will be empty.")
	}

	return nil
}

// cleanIPsAll cleans and deduplicates the list of IP observations
func cleanIPsAll(ipsAll []model.IPObservation) []model.IPObservation {
	if len(ipsAll) == 0 {
		return nil
	}

	// Create a map to deduplicate by IP
	ipMap := make(map[string]model.IPObservation)

	for _, obs := range ipsAll {
		if obs.IP == nil {
			continue // Ignore nil IPs
		}

		ipStr := obs.IP.String()
		if ipStr == "" || ipStr == "<nil>" {
			continue // Ignore empty or "<nil>" strings
		}

		// Keep the observation with the highest strength
		if existing, exists := ipMap[ipStr]; !exists || model.StrengthPriority(obs.Strength) > model.StrengthPriority(existing.Strength) {
			ipMap[ipStr] = obs
		}
	}

	// Convert the map to a slice
	result := make([]model.IPObservation, 0, len(ipMap))
	for _, obs := range ipMap {
		result = append(result, obs)
	}

	return result
}

// cleanProtocolsByIP cleans and deduplicates the IP -> protocols mapping
func cleanProtocolsByIP(protocolsByIP map[string][]string) map[string][]string {
	if len(protocolsByIP) == 0 {
		return nil
	}

	cleaned := make(map[string][]string)

	for ip, protocols := range protocolsByIP {
		if ip == "" || ip == "<nil>" {
			continue // Ignore empty or "<nil>" IPs
		}

		// Deduplicate and clean protocols
		protocolSet := make(map[string]bool)
		cleanProtocols := make([]string, 0)

		for _, protocol := range protocols {
			if protocol == "" || protocol == "<nil>" {
				continue // Ignore empty or "<nil>" protocols
			}

			if !protocolSet[protocol] {
				protocolSet[protocol] = true
				cleanProtocols = append(cleanProtocols, protocol)
			}
		}

		if len(cleanProtocols) > 0 {
			cleaned[ip] = cleanProtocols
		}
	}

	if len(cleaned) == 0 {
		return nil
	}

	return cleaned
}
