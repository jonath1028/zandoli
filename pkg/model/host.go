// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"net"
	"sort"
	"time"
)

// Host represents a discovered device on the network.
type Host struct {
	IP               net.IP           `json:"ip,omitempty"`   // Primary IPv4 (for compatibility)
	IPv6Primary      net.IP           `json:"ipv6,omitempty"` // Primary IPv6
	IPs              []net.IP         `json:"ips,omitempty"`  // All observed IP addresses (v4 and v6)
	MAC              net.HardwareAddr `json:"-"`
	MACStr           string           `json:"macStr,omitempty"`
	Vendor           string           `json:"vendor,omitempty"`
	Role             string           `json:"role,omitempty"`
	RoleConfidence   int              `json:"roleConfidence,omitempty"` // Role confidence (0-100)
	RoleSignals      []string         `json:"roleSignals,omitempty"`   // Signals used for role inference
	RoleConflict     bool             `json:"roleConflict,omitempty"`  // True if conflicting signals
	Protocols        []string         `json:"protocols,omitempty"`
	Info             string           `json:"info,omitempty"` // Additional protocol-specific information
	TTL              int              `json:"ttl,omitempty"`
	OSGuess          string           `json:"osGuess,omitempty"`
	OSScore          uint8            `json:"osScore,omitempty"`   // OS fingerprinting confidence score (0-100)
	OSSignals        []string         `json:"osSignals,omitempty"` // Sources used for OS detection: vendor, cdp, mdns, tcp
	WindowSize       int              `json:"windowSize,omitempty"`
	TCPOpts          []string         `json:"tcpOpts,omitempty"`    // Legacy TCP options as strings
	TCPOptions       *TCPOptions      `json:"tcpOptions,omitempty"` // Detailed TCP options for OS fingerprinting
	FirstSeen        time.Time        `json:"firstSeen,omitempty"`
	LastSeen         time.Time        `json:"lastSeen,omitempty"`
	Anomalies        []Anomaly        `json:"anomalies,omitempty"`
	Ports            []int            `json:"ports,omitempty"`
	Source           string           `json:"source,omitempty"`           // "passive", "active", "combined"
	OnlyARP          bool             `json:"onlyArp,omitempty"`          // True if discovered only via ARP
	TTLAvg           uint8            `json:"ttlAvg,omitempty"`           // Average observed TTL
	Category         string           `json:"category,omitempty"`         // Functional category, inferred
	Hostname         string           `json:"hostname,omitempty"`         // Discovered hostname
	VLANs            []int            `json:"vlans,omitempty"`            // Observed VLANs
	VLANStats        map[int]int      `json:"vlanStats,omitempty"`        // VLAN frequency by ID
	PrimaryVLAN      int              `json:"primaryVlan,omitempty"`      // Primary VLAN (most frequent)
	PacketCount      uint64           `json:"packetCount,omitempty"`      // Observed packet count
	ByteCount        uint64           `json:"byteCount,omitempty"`        // Observed byte count
	SecurityFeatures []string         `json:"securityFeatures,omitempty"` // Detected security features
	CDP              *CDPInfo         `json:"cdp,omitempty"`              // Cisco Discovery Protocol information
	LLDP             *LLDPInfo        `json:"lldp,omitempty"`             // Link Layer Discovery Protocol information
	STP              *STPInfo         `json:"stp,omitempty"`              // Spanning Tree Protocol information
	RoleInfo         *RoleInfo        `json:"roleInfo,omitempty"`         // Role inference with confidence and signals
	GatewayRedundancy []GatewayRedundancyInfo `json:"gateway_redundancy,omitempty"` // HSRP/VRRP redundancy data
	// IP observation and per-IP protocol tracking
	IPsAll        []IPObservation     `json:"ipsAll,omitempty"`        // All observed IPs with strength
	ProtocolsByIP map[string][]string `json:"protocolsByIP,omitempty"` // IP -> observed protocols

	// L2 signals and service ports
	L2Signals L2SignalsInfo `json:"l2,omitempty"`       // Consolidated L2 signals
	Services  ServicesInfo  `json:"services,omitempty"` // Detected TCP/UDP services
}

// AddPort appends a new port if not already present.
func (h *Host) AddPort(port int) {
	h.Ports = appendUniqueInt(h.Ports, port)
}

// CategorizePorts splits the generic Ports slice into Services.TCP and Services.UDP
// based on well-known UDP port signatures.
func (h *Host) CategorizePorts() {
	h.Services.TCP = make([]int, 0)
	h.Services.UDP = make([]int, 0)

	knownUDP := map[int]bool{
		53: true, 67: true, 68: true, 123: true, 137: true, 138: true,
		161: true, 162: true, 500: true, 514: true, 1900: true, 5353: true, 5355: true,
	}

	for _, port := range h.Ports {
		if knownUDP[port] {
			h.Services.UDP = append(h.Services.UDP, port)
		} else {
			h.Services.TCP = append(h.Services.TCP, port)
		}
	}

	sort.Ints(h.Services.TCP)
	sort.Ints(h.Services.UDP)
}

// appendUniqueInt appends an item to a slice if not already present.
func appendUniqueInt(slice []int, item int) []int {
	for _, v := range slice {
		if v == item {
			return slice
		}
	}
	return append(slice, item)
}

// AddVLAN appends a new VLAN ID if not already present, and updates VLAN statistics.
func (h *Host) AddVLAN(vlan int) {
	h.VLANs = appendUniqueInt(h.VLANs, vlan)

	// Always update VLAN statistics (count each occurrence)
	if h.VLANStats == nil {
		h.VLANStats = make(map[int]int)
	}
	h.VLANStats[vlan]++

	h.updatePrimaryVLAN()
}

// updatePrimaryVLAN updates the primary VLAN based on current statistics
func (h *Host) updatePrimaryVLAN() {
	if len(h.VLANStats) == 0 {
		h.PrimaryVLAN = 0
		return
	}

	maxCount := 0
	primaryVLAN := 0
	for vlanID, count := range h.VLANStats {
		if count > maxCount {
			maxCount = count
			primaryVLAN = vlanID
		}
	}
	h.PrimaryVLAN = primaryVLAN
}

// AddIP adds a new IP to the list if not already present.
func (h *Host) AddIP(ip net.IP) {
	if ip == nil {
		return
	}

	for _, existingIP := range h.IPs {
		if existingIP.Equal(ip) {
			return
		}
	}

	h.IPs = append(h.IPs, ip)
	h.updatePrimaryIP()
}

// updatePrimaryIP updates primary IPv4 and IPv6 separately.
// Rule: IPv4 primary in Host.IP, IPv6 primary in Host.IPv6Primary. No cross-family overwrite.
func (h *Host) updatePrimaryIP() {
	if len(h.IPs) == 0 {
		h.IP = nil
		h.IPv6Primary = nil
		return
	}

	var lastIPv4 net.IP
	for _, ip := range h.IPs {
		if ip.To4() != nil {
			lastIPv4 = ip
		}
	}

	// Find last global/ULA IPv6 (exclude fe80::/10 link-local)
	var lastIPv6 net.IP
	for _, ip := range h.IPs {
		if ip.To16() != nil && ip.To4() == nil && !isLinkLocalIPv6(ip) {
			lastIPv6 = ip
		}
	}

	h.IP = lastIPv4
	h.IPv6Primary = lastIPv6
}

// isLinkLocalIPv6 checks if an IPv6 address is link-local (fe80::/10)
func isLinkLocalIPv6(ip net.IP) bool {
	if ip.To16() == nil || ip.To4() != nil {
		return false
	}
	return len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}

// GetIPv4s returns all IPv4 addresses for this host
func (h *Host) GetIPv4s() []net.IP {
	var ipv4s []net.IP
	for _, ip := range h.IPs {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}
	return ipv4s
}

// GetIPv6s returns all IPv6 addresses for this host
func (h *Host) GetIPv6s() []net.IP {
	var ipv6s []net.IP
	for _, ip := range h.IPs {
		if ip.To16() != nil && ip.To4() == nil {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv6s
}

// GetPrimaryIPv4 returns the primary IPv4 address
func (h *Host) GetPrimaryIPv4() net.IP {
	return h.IP
}

// GetPrimaryIPv6 returns the primary IPv6 address
func (h *Host) GetPrimaryIPv6() net.IP {
	return h.IPv6Primary
}

// GetAllIPsAsStrings returns all IPs as sorted strings
func (h *Host) GetAllIPsAsStrings() []string {
	var ipStrings []string
	for _, ip := range h.IPs {
		ipStrings = append(ipStrings, ip.String())
	}
	sort.Strings(ipStrings)
	return ipStrings
}

// GetIPv4sAsStrings returns all IPv4 addresses as sorted strings
func (h *Host) GetIPv4sAsStrings() []string {
	var ipStrings []string
	for _, ip := range h.IPs {
		if ip.To4() != nil {
			ipStrings = append(ipStrings, ip.String())
		}
	}
	sort.Strings(ipStrings)
	return ipStrings
}

// GetIPv6sAsStrings returns all IPv6 addresses as sorted strings
func (h *Host) GetIPv6sAsStrings() []string {
	var ipStrings []string
	for _, ip := range h.IPs {
		if ip.To16() != nil && ip.To4() == nil {
			ipStrings = append(ipStrings, ip.String())
		}
	}
	sort.Strings(ipStrings)
	return ipStrings
}

// AddIPObservation adds an IP observation with its association strength
func (h *Host) AddIPObservation(ip net.IP, strength string) {
	if ip == nil {
		return
	}

	if h.IPsAll == nil {
		h.IPsAll = make([]IPObservation, 0)
	}

	// Update strength if IP already exists and new strength is higher
	for i, obs := range h.IPsAll {
		if obs.IP.Equal(ip) {
			if StrengthPriority(strength) > StrengthPriority(obs.Strength) {
				h.IPsAll[i].Strength = strength
			}
			return
		}
	}

	h.IPsAll = append(h.IPsAll, IPObservation{IP: ip, Strength: strength})

	// Add to main IP list if strength is sufficient
	if strength == "high" || strength == "medium" {
		h.AddIP(ip)
	}
}

// AddProtocolForIP adds a protocol for a specific IP with deduplication and auto-sort
func (h *Host) AddProtocolForIP(ip net.IP, protocol string) {
	if ip == nil || protocol == "" {
		return
	}

	ipStr := ip.String()

	if h.ProtocolsByIP == nil {
		h.ProtocolsByIP = make(map[string][]string)
	}

	// Deduplicate and sort protocols for this IP
	protocols := h.ProtocolsByIP[ipStr]
	found := false
	for _, p := range protocols {
		if p == protocol {
			found = true
			break
		}
	}
	if !found {
		protocols = append(protocols, protocol)
		sort.Strings(protocols)
		h.ProtocolsByIP[ipStr] = protocols
	}

	// Also add to global protocol list (deduplicated)
	foundGlobal := false
	for _, p := range h.Protocols {
		if p == protocol {
			foundGlobal = true
			break
		}
	}
	if !foundGlobal {
		h.Protocols = append(h.Protocols, protocol)
	}
}

// GetProtocolsByIPSorted returns protocols for a given IP, sorted alphabetically
func (h *Host) GetProtocolsByIPSorted(ip string) []string {
	if h.ProtocolsByIP == nil {
		return []string{}
	}
	protocols, exists := h.ProtocolsByIP[ip]
	if !exists {
		return []string{}
	}
	sorted := make([]string, len(protocols))
	copy(sorted, protocols)
	sort.Strings(sorted)
	return sorted
}

// GetAllProtocolsByIPSorted returns a copy of ProtocolsByIP with all protocols sorted
func (h *Host) GetAllProtocolsByIPSorted() map[string][]string {
	if h.ProtocolsByIP == nil {
		return make(map[string][]string)
	}

	result := make(map[string][]string)
	for ip, protocols := range h.ProtocolsByIP {
		sorted := make([]string, len(protocols))
		copy(sorted, protocols)
		sort.Strings(sorted)
		result[ip] = sorted
	}
	return result
}
