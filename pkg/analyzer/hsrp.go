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

// ParseHSRPPacket analyses HSRP (Hot Standby Router Protocol) packets.
// HSRPv1 and HSRPv2 are carried over UDP port 1985.
func ParseHSRPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if len(pkt.SrcMAC) != 6 {
		return nil, nil
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, nil
	}
	udp := udpLayer.(*layers.UDP)
	if udp == nil {
		return nil, nil
	}

	// HSRP uses UDP port 1985
	if udp.DstPort != 1985 && udp.SrcPort != 1985 {
		return nil, nil
	}

	payload := udp.Payload
	if len(payload) < 20 {
		return nil, nil
	}

	version := payload[0]

	var grInfo *model.GatewayRedundancyInfo

	switch version {
	case 0: // HSRPv1
		grInfo = parseHSRPv1(payload)
	case 2: // HSRPv2 (TLV-based)
		grInfo = parseHSRPv2(payload)
	default:
		return nil, nil
	}

	if grInfo == nil || len(grInfo.Groups) == 0 {
		return nil, nil
	}

	// Extract source IP
	var ipSource net.IP
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		ipSource = ipv4.SrcIP
	}

	// Build info string
	g := grInfo.Groups[0]
	info := fmt.Sprintf("hsrp group=%d state=%s pri=%d vip=%s", g.GroupID, g.State, g.Priority, g.VirtualIP)
	if g.Auth != "" {
		info += " auth=" + g.Auth
	}

	return &ParsedRecord{
		MAC:               pkt.SrcMAC,
		IP:                ipSource,
		Protocols:         []string{"HSRP"},
		Role:              "router",
		Info:              info,
		Source:             "passive",
		FirstSeen:         pkt.Timestamp,
		LastSeen:          pkt.Timestamp,
		TTL:               int(pkt.TTL),
		GatewayRedundancy: grInfo,
		IPSource:          ipSource,
		L3Proto:           "IPv4",
		AppProto:          "HSRP",
		Strength:          "high",
	}, nil
}

// parseHSRPv1 parses an HSRPv1 packet payload.
// Format: version(1) opcode(1) state(1) hello(1) hold(1) priority(1) group(1) reserved(1) auth(8) vip(4)
func parseHSRPv1(payload []byte) *model.GatewayRedundancyInfo {
	if len(payload) < 20 {
		return nil
	}

	state := hsrpStateName(payload[2])
	helloTime := int(payload[3])
	holdTime := int(payload[4])
	priority := int(payload[5])
	groupID := int(payload[6])

	// Auth: bytes 8-15 (8 bytes, null-terminated plaintext string)
	auth := strings.TrimRight(string(payload[8:16]), "\x00")

	// Virtual IP: bytes 16-19
	vip := net.IP(payload[16:20]).String()

	return &model.GatewayRedundancyInfo{
		Protocol: "hsrp_v1",
		Groups: []model.RedundancyGroup{{
			GroupID:   groupID,
			State:     state,
			Priority:  priority,
			VirtualIP: vip,
			HelloTime: helloTime,
			HoldTime:  holdTime,
			Auth:      auth,
		}},
	}
}

// parseHSRPv2 parses an HSRPv2 TLV-based payload.
func parseHSRPv2(payload []byte) *model.GatewayRedundancyInfo {
	if len(payload) < 4 {
		return nil
	}

	var groups []model.RedundancyGroup
	var auth string

	// Skip version byte, parse TLVs
	i := 1
	for i+2 <= len(payload) {
		tlvType := payload[i]
		tlvLen := int(payload[i+1])
		i += 2

		if i+tlvLen > len(payload) {
			break
		}
		data := payload[i : i+tlvLen]
		i += tlvLen

		switch tlvType {
		case 1: // Group State TLV
			if len(data) >= 28 {
				// HSRPv2 Group State: version(1) opcode(1) state(1) ipver(1) group(2)
				// identifier(6) priority(4) hello(4) hold(4) vip(4 or 16)
				grpState := hsrpStateName(data[2])
				groupID := int(data[4])<<8 | int(data[5])
				priority := int(data[12])<<24 | int(data[13])<<16 | int(data[14])<<8 | int(data[15])
				if priority > 255 {
					priority = int(data[15]) // Use last byte only for sanity
				}
				helloMs := int(data[16])<<24 | int(data[17])<<16 | int(data[18])<<8 | int(data[19])
				holdMs := int(data[20])<<24 | int(data[21])<<16 | int(data[22])<<8 | int(data[23])

				// VIP at offset 24
				var vip string
				if len(data) >= 28 {
					vip = net.IP(data[24:28]).String()
				}

				groups = append(groups, model.RedundancyGroup{
					GroupID:   groupID,
					State:     grpState,
					Priority:  priority,
					VirtualIP: vip,
					HelloTime: helloMs / 1000, // Convert ms to seconds
					HoldTime:  holdMs / 1000,
				})
			}
		case 3: // Text Auth TLV
			auth = strings.TrimRight(string(data), "\x00")
		}
	}

	// Apply auth to all groups
	for i := range groups {
		groups[i].Auth = auth
	}

	if len(groups) == 0 {
		return nil
	}

	return &model.GatewayRedundancyInfo{
		Protocol: "hsrp_v2",
		Groups:   groups,
	}
}

// hsrpStateName converts an HSRP state byte to a human-readable name.
func hsrpStateName(state byte) string {
	switch state {
	case 0:
		return "initial"
	case 1:
		return "learn"
	case 2:
		return "listen"
	case 4:
		return "speak"
	case 8:
		return "standby"
	case 16:
		return "active"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}
