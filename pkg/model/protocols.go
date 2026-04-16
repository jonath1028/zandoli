// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

// TCPOptions represents parsed TCP options for OS fingerprinting
type TCPOptions struct {
	MSS             int      `json:"mss,omitempty"`               // Maximum Segment Size (mode across SYNs)
	WSCALE          int      `json:"wscale,omitempty"`            // Window Scale Factor (mode across SYNs)
	SACKPermitted   bool     `json:"sackPermitted,omitempty"`     // Selective Acknowledgment Permitted (true if seen at least once)
	Timestamp       bool     `json:"timestamp,omitempty"`         // Timestamp Option Present (true if seen at least once)
	NOPCount        int      `json:"nopCount,omitempty"`          // Number of NOP options
	Order           []string `json:"order,omitempty"`             // Order of TCP options (consolidated, realistic sequence)
	MSSSamples      []int    `json:"mss_samples,omitempty"`       // Small array of MSS samples for analysis
	WScaleSamples   []int    `json:"wscale_samples,omitempty"`    // Small array of WScale samples for analysis
	TCPFPConfidence int      `json:"tcp_fp_confidence,omitempty"` // TCP fingerprinting confidence (0-100)
}

// CDPInfo represents Cisco Discovery Protocol information extracted from CDP packets
type CDPInfo struct {
	DeviceID            string   `json:"device_id,omitempty"`           // Device ID (TLV 0x01)
	PortID              string   `json:"port_id,omitempty"`             // Port ID (TLV 0x03)
	Platform            string   `json:"platform,omitempty"`            // Platform (TLV 0x06)
	Version             string   `json:"version,omitempty"`             // Software Version (TLV 0x05)
	Capabilities        uint32   `json:"capabilities,omitempty"`        // Capabilities (TLV 0x04)
	NativeVLAN          int      `json:"native_vlan,omitempty"`         // Native VLAN (TLV 0x0a)
	Addresses           []string `json:"addresses,omitempty"`           // Management addresses
	DecodedCaps         []string `json:"decoded_caps,omitempty"`        // Decoded capabilities (Router, Switch, etc.)
	CapabilitiesDecoded []string `json:"capabilitiesDecoded,omitempty"` // Human-readable capabilities for JSON export
}

// LLDPInfo represents Link Layer Discovery Protocol information
type LLDPInfo struct {
	ChassisID    string   `json:"chassis_id,omitempty"`   // Chassis ID
	PortID       string   `json:"port_id,omitempty"`      // Port ID
	SysName      string   `json:"sys_name,omitempty"`     // System Name
	SysDescr     string   `json:"sys_descr,omitempty"`    // System Description
	MgmtAddrs    []string `json:"mgmt_addrs,omitempty"`   // Management Addresses
	Capabilities []string `json:"capabilities,omitempty"` // System Capabilities (decoded)
}

// RoleInfo represents role inference information with confidence and signals
type RoleInfo struct {
	Role       string   `json:"role,omitempty"`       // Inferred role (router, switch, client, etc.)
	Confidence int      `json:"confidence,omitempty"` // Confidence level (0-100)
	Signals    []string `json:"signals,omitempty"`    // Signals used for inference
	Rationale  string   `json:"rationale,omitempty"`  // Human-readable explanation
}

// STPInfo represents Spanning Tree Protocol information extracted from STP BPDUs
type STPInfo struct {
	RootBridgeID string `json:"root_bridge_id,omitempty"` // Root Bridge ID (priority + MAC)
	RootPathCost uint32 `json:"root_path_cost,omitempty"` // Root Path Cost
	BridgeID     string `json:"bridge_id,omitempty"`      // Bridge ID (priority + MAC)
	PortID       uint16 `json:"port_id,omitempty"`        // Port ID
	HelloTime    uint16 `json:"hello_time,omitempty"`     // Hello Time (in 1/256 seconds)
	MaxAge       uint16 `json:"max_age,omitempty"`        // Max Age (in 1/256 seconds)
	ForwardDelay uint16 `json:"forward_delay,omitempty"`  // Forward Delay (in 1/256 seconds)
	MessageAge   uint16 `json:"message_age,omitempty"`    // Message Age (in 1/256 seconds)
	IsRoot       bool   `json:"is_root,omitempty"`        // True if this bridge is the root
}

// L2SignalsInfo represents consolidated L2 signals for a host.
// Only true Layer-2 elements (CDP, LLDP, STP, 802.1X/EAPOL, VLAN).
// OUI/Vendor are NOT L2 elements and remain in Host.Vendor.
type L2SignalsInfo struct {
	VLANs []int `json:"vlans,omitempty"` // Observed VLANs (deduplicated)
	EAPOL bool  `json:"eapol,omitempty"` // EAPOL (802.1X) detected
	STP   bool  `json:"stp,omitempty"`   // STP/RSTP detected
	LLDP  bool  `json:"lldp,omitempty"`  // LLDP detected
	CDP   bool  `json:"cdp,omitempty"`   // CDP detected
}

// ServicesInfo represents detected TCP/UDP services
type ServicesInfo struct {
	TCP []int `json:"tcp,omitempty"` // TCP ports (sorted, unique)
	UDP []int `json:"udp,omitempty"` // UDP ports (sorted, unique)
}

// GatewayRedundancyInfo represents HSRP/VRRP gateway redundancy protocol data.
type GatewayRedundancyInfo struct {
	Protocol string            `json:"protocol"`         // hsrp_v1, hsrp_v2, vrrp_v2, vrrp_v3
	Groups   []RedundancyGroup `json:"groups,omitempty"` // Redundancy groups observed
}

// RedundancyGroup represents a single HSRP or VRRP redundancy group.
type RedundancyGroup struct {
	GroupID   int    `json:"group_id"`
	State     string `json:"state"`             // active, standby, listen (HSRP) / master, backup (VRRP)
	Priority  int    `json:"priority"`
	VirtualIP string `json:"virtual_ip"`
	HelloTime int    `json:"hello_time"`
	HoldTime  int    `json:"hold_time"`
	Auth      string `json:"auth,omitempty"`    // Plaintext auth (HSRP v1 — Red Team finding)
	Preempt   bool   `json:"preempt,omitempty"` // VRRP preempt mode
}
