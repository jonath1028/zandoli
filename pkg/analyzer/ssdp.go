// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"strings"
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseSSDPPacket analyzes SSDP traffic over UDP/1900.
func ParseSSDPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.SrcMAC) != 6 {
		return nil, nil
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, nil
	}

	udp, _ := udpLayer.(*layers.UDP)
	if udp == nil {
		return nil, nil
	}

	// Verify this is SSDP traffic on port 1900
	if udp.SrcPort != 1900 && udp.DstPort != 1900 {
		return nil, nil
	}

	// Extract source and destination IPs from the packet
	var ipSource, ipDest net.IP
	var l3Proto string

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		ipSource = ipv4.SrcIP
		ipDest = ipv4.DstIP
		l3Proto = "IPv4"
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		ipSource = ipv6.SrcIP
		ipDest = ipv6.DstIP
		l3Proto = "IPv6"
	}

	// Parse the SSDP payload to extract information
	var hostname string
	var service string
	var server string
	var location string
	var usn string

	if len(udp.Payload) > 0 {
		payload := string(udp.Payload)
		lines := strings.Split(payload, "\r\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			upper := strings.ToUpper(line)
			if strings.HasPrefix(upper, "SERVER:") {
				server = strings.TrimSpace(line[7:])
			} else if strings.HasPrefix(upper, "LOCATION:") {
				location = strings.TrimSpace(line[9:])
			} else if strings.HasPrefix(upper, "ST:") {
				service = strings.TrimSpace(line[3:])
			} else if strings.HasPrefix(upper, "USN:") {
				usn = strings.TrimSpace(line[4:])
			}
			// HOST: is intentionally NOT used — in SSDP it contains
			// the multicast address (239.255.255.250:1900), not the device name
		}
	}

	// Extract hostname from USN if available (e.g. "uuid:device-name::...")
	if usn != "" {
		if idx := strings.Index(usn, "::"); idx > 0 {
			hostname = usn[:idx]
		} else {
			hostname = usn
		}
		// Strip "uuid:" prefix if present
		hostname = strings.TrimPrefix(hostname, "uuid:")
	}

	// Guard: never set hostname to a multicast address
	if isMulticastHostname(hostname) {
		hostname = ""
	}

	// Build the information string
	var infoParts []string
	if service != "" {
		infoParts = append(infoParts, "service="+service)
	}
	if server != "" {
		infoParts = append(infoParts, "server="+server)
	}
	if location != "" {
		infoParts = append(infoParts, "location="+location)
	}
	info := strings.Join(infoParts, "; ")

	// Determine the role based on the source port
	role := "client"
	if udp.SrcPort == 1900 {
		role = "server"
	}

	record := &ParsedRecord{
		MAC:       append([]byte(nil), pkt.SrcMAC...),
		IP:        ipSource, // Use the source IP as the primary IP
		Hostname:  hostname,
		Protocols: []string{"SSDP"},
		Role:      role,
		Info:      info,
		Source:    "passive",
		FirstSeen: pkt.Timestamp.UTC(),
		LastSeen:  pkt.Timestamp.UTC(),
		TTL:       int(pkt.TTL),
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  l3Proto,
		AppProto: "SSDP",
		Strength: "low", // SSDP multicast = low
	}

	return record, nil
}

// isMulticastHostname returns true if the hostname looks like a multicast address.
func isMulticastHostname(h string) bool {
	return strings.HasPrefix(h, "239.") || strings.HasPrefix(h, "224.") ||
		strings.Contains(h, "239.255") || strings.Contains(h, "224.0")
}
