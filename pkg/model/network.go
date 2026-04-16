// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"net"
	"time"

	"github.com/google/gopacket"
)

// IPObservation represents an observed IP with its association strength
type IPObservation struct {
	IP       net.IP `json:"ip"`
	Strength string `json:"strength"` // "high", "medium", "low"
}

// PacketEvent represents a raw packet captured during sniffing.
type PacketEvent struct {
	Timestamp time.Time
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	Payload   []byte
	PacketID  string
	TTL       uint8
	VLANID    int             // VLAN identifier from 802.1Q tag (-1 if not present)
	Packet    gopacket.Packet // Pre-parsed packet (optional, nil = parse from Payload)
}

// Subnet represents a discovered network subnet.
type Subnet struct {
	CIDR       string   `json:"cidr"`
	Source     string   `json:"source"` // "dhcp", "computed", "arp", "ndp", etc.
	Hosts      []string `json:"hosts,omitempty"`
	CountHosts int      `json:"countHosts,omitempty"` // Number of hosts with at least 1 IP in this CIDR
	VLANs      []int    `json:"vlans,omitempty"`      // VLANs associated with this subnet
}

// SubnetEntry represents a VLAN-aware subnet entry for topology export
type SubnetEntry struct {
	CIDR       string    `json:"cidr"`                // CIDR notation (e.g., "192.168.1.0/24")
	Version    string    `json:"version"`             // "ipv4" or "ipv6"
	VLAN       *int      `json:"vlan,omitempty"`      // VLAN ID (null if untagged)
	Source     string    `json:"source"`              // "dhcp", "ra", "computed"
	HostsCount int       `json:"hostsCount"`          // Number of unique hosts in this subnet
	IPSamples  []string  `json:"ipSamples"`           // Max 5 sample IPs, sorted, unique
	FirstSeen  time.Time `json:"firstSeen,omitempty"` // First time this subnet was observed
	LastSeen   time.Time `json:"lastSeen,omitempty"`  // Last time this subnet was observed
}
