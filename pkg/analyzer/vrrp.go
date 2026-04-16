// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"fmt"
	"net"
	"strings"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseVRRPPacket analyses VRRP (Virtual Router Redundancy Protocol) packets.
// VRRP uses IP protocol 112, multicast destination 224.0.0.18.
func ParseVRRPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.SrcMAC) != 6 {
		return nil, nil
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	// VRRP is IP protocol 112
	if ipv4.Protocol != 112 {
		return nil, nil
	}

	// VRRP payload is after the IPv4 header
	payload := ipv4.Payload
	if len(payload) < 8 {
		return nil, nil
	}

	// Parse VRRP header
	versionType := payload[0]
	version := versionType >> 4
	pktType := versionType & 0x0F

	// Only handle advertisement packets (type 1)
	if pktType != 1 {
		return nil, nil
	}

	vrID := int(payload[1])        // Virtual Router ID
	priority := int(payload[2])    // Priority (255 = owner)
	countIPs := int(payload[3])    // Number of virtual IPs
	authType := int(payload[4])    // Auth type (v2 only: 0=none, 1=simple)
	advInterval := int(payload[5]) // Advertisement interval (seconds)

	// Parse virtual IPs (4 bytes each, starting at offset 8)
	var vips []string
	offset := 8
	for i := 0; i < countIPs && offset+4 <= len(payload); i++ {
		vip := net.IP(payload[offset : offset+4]).String()
		vips = append(vips, vip)
		offset += 4
	}

	// Parse auth data (after VIPs, for auth type 1)
	var auth string
	if authType == 1 && offset+8 <= len(payload) {
		auth = strings.TrimRight(string(payload[offset:offset+8]), "\x00")
	}

	// Determine state: VRRP advertisements are only sent by the current master.
	// Priority 0 means the master is releasing its role.
	state := "master"
	if priority == 0 {
		state = "leaving"
	}

	// Determine protocol version string
	protoStr := "vrrp_v2"
	if version == 3 {
		protoStr = "vrrp_v3"
	}

	primaryVIP := ""
	if len(vips) > 0 {
		primaryVIP = vips[0]
	}

	grInfo := &model.GatewayRedundancyInfo{
		Protocol: protoStr,
		Groups: []model.RedundancyGroup{{
			GroupID:   vrID,
			State:     state,
			Priority:  priority,
			VirtualIP: primaryVIP,
			HelloTime: advInterval,
			HoldTime:  advInterval * 3, // VRRP holdtime is typically 3x advertisement
			Auth:      auth,
			Preempt:   priority > 0, // VRRP preempt is default on for non-zero priority
		}},
	}

	// Build info string
	info := fmt.Sprintf("vrrp vrid=%d state=%s pri=%d vip=%s", vrID, state, priority, primaryVIP)
	if auth != "" {
		info += " auth=" + auth
	}
	if len(vips) > 1 {
		info += fmt.Sprintf(" +%d_vips", len(vips)-1)
	}

	return &ParsedRecord{
		MAC:               pkt.SrcMAC,
		IP:                ipv4.SrcIP,
		Protocols:         []string{"VRRP"},
		Role:              "router",
		Info:              info,
		Source:             "passive",
		FirstSeen:         pkt.Timestamp,
		LastSeen:          pkt.Timestamp,
		TTL:               int(pkt.TTL),
		GatewayRedundancy: grInfo,
		IPSource:          ipv4.SrcIP,
		L3Proto:           "IPv4",
		AppProto:          "VRRP",
		Strength:          "high",
	}, nil
}
