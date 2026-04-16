// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"time"

	"zandoli/pkg/model"
)

// L2Info represents detected layer 2 information
// Only real Layer-2 elements (CDP, LLDP, STP, 802.1X/EAPOL, VLAN)
// OUI/Vendor are NOT L2 elements
type L2Info struct {
	VlanID *int `json:"vlanId,omitempty"` // VLAN ID (nil if not applicable)
	EAPOL  bool `json:"eapol,omitempty"`  // EAPOL (802.1X) detected
	STP    bool `json:"stp,omitempty"`    // STP/RSTP detected
	LLDP   bool `json:"lldp,omitempty"`   // LLDP detected
	CDP    bool `json:"cdp,omitempty"`    // CDP detected
}

// NewParsedRecord creates a new ParsedRecord with basic information from a PacketEvent
func NewParsedRecord(pkt model.PacketEvent) *ParsedRecord {
	record := &ParsedRecord{
		MAC:       pkt.SrcMAC,
		Source:    "passive",
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
		VLANID:    pkt.VLANID,
		Transport: "none", // Default
		SrcPort:   0,
		DstPort:   0,
		L2:        L2Info{},
	}

	// Initialize the VLAN ID in L2 if present
	if pkt.VLANID > 0 {
		record.L2.VlanID = &pkt.VLANID
	}

	return record
}

// ParsedRecord represents a single piece of extracted information
// from a passive packet analysis, before aggregation.
type ParsedRecord struct {
	MAC         net.HardwareAddr
	IP          net.IP   // IP address associated with this record
	Protocols   []string // "DHCP", "LLDP", "802.1X", etc.
	Role        string   // "client", "server", "switch", etc.
	Info        string   // Additional protocol-specific information
	Anomalies   []string
	Ports       []int
	TTL         int
	OnlyARP     bool
	OSGuess     string
	TCPOpts     []string
	OSScore     int
	WindowSize  int               // TCP Window Size for OS fingerprinting
	TCPOptions  *model.TCPOptions // Detailed TCP options for OS fingerprinting
	Source      string            // typically "passive"
	FirstSeen   time.Time
	LastSeen    time.Time
	Vendor      string
	Hostname    string            // Hostname extracted by analyzers (DHCP, NBNS, LLMNR, mDNS)
	VLANID      int               // VLAN identifier observed (-1 means unset)
	CDP         *model.CDPInfo    // Cisco Discovery Protocol information
	LLDP        *model.LLDPInfo   // Link Layer Discovery Protocol information
	STPInfo     *model.STPInfo    // Spanning Tree Protocol information
	GatewayRedundancy *model.GatewayRedundancyInfo // HSRP/VRRP redundancy data
	Extra       map[string]string // Additional protocol-specific fields (e.g., DHCP options)
	RoleSignals []string          // Role signals for inference (e.g., "server_protocol:dhcp")
	// Fields for MDNS/LLMNR attribution validation
	IsQuery   bool   // true if it is a query, false if it is a response
	QName     string // domain name queried in the request
	OwnerName string // owner name of the DNS response
	// New fields for IP and protocol observation
	IPSource net.IP // Source IP of the packet
	IPDest   net.IP // Destination IP of the packet
	L3Proto  string // "IPv4" or "IPv6"
	AppProto string // "NBNS", "SSDP", "mDNS", "LLMNR", "DHCP", "IGMP", "ARP", etc.
	Strength string // "high", "medium", "low" - strength of the IP↔MAC association

	// New fields for port and L2 signal standardization
	Transport string // "tcp", "udp", "none"
	SrcPort   uint16 // Source port (0 if not applicable)
	DstPort   uint16 // Destination port (0 if not applicable)
	L2        L2Info // Layer 2 information
}
