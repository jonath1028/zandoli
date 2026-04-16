// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"fmt"

	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IGMPParser handles IGMP packet parsing with multi-version support
type IGMPParser struct {
	log *logger.Logger
}

// NewIGMPParser creates a new IGMP parser
func NewIGMPParser(log *logger.Logger) *IGMPParser {
	return &IGMPParser{
		log: log,
	}
}

// ParseIGMPPacket analyzes IGMP traffic with robust multi-version support.
func ParseIGMPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	// Create a temporary parser for this standalone function
	parser := &IGMPParser{}
	return parser.parseIGMPPacket(pkt)
}

// parseIGMPPacket implements IGMP parsing with robust type switch
func (p *IGMPParser) parseIGMPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	// Systematic nil-safety
	if p == nil {
		if p.log != nil {
			p.log.Warn().Msg("IGMP parser is nil; skipping")
		}
		return nil, nil
	}

	if len(pkt.SrcMAC) != 6 {
		return nil, nil
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	// Check the IP layer
	var ipv4Layer *layers.IPv4
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipv4Layer = layer.(*layers.IPv4)
	} else {
		return nil, nil
	}

	if ipv4Layer == nil {
		return nil, nil
	}

	// Extract source and destination IPs
	ipSource := ipv4Layer.SrcIP
	ipDest := ipv4Layer.DstIP

	// Robust type switch to support all IGMP versions
	var version, igmpType, groupAddress string
	var extra map[string]string

	// Use a type switch on the generic IGMP layer
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		// No IGMP layer found
		if p.log != nil {
			p.log.Debug().Msg("IGMP layer not found")
		}
		return nil, nil
	}

	// Type switch on the IGMP layer to handle different versions
	switch igmp := igmpLayer.(type) {
	case *layers.IGMPv1or2:
		if igmp != nil {
			version = "v1v2"
			igmpType, groupAddress = p.mapIGMPv1or2Type(igmp)
			extra = map[string]string{
				"igmp.version": version,
				"igmp.type":    igmpType,
				"igmp.group":   groupAddress,
			}
		}
	case *layers.IGMP:
		if igmp != nil {
			// Determine the version based on the type
			if igmp.Type == 0x22 {
				version = "v3"
			} else {
				version = "v1v2"
			}
			igmpType, groupAddress = p.mapIGMPGenericType(igmp)
			extra = map[string]string{
				"igmp.version": version,
				"igmp.type":    igmpType,
				"igmp.group":   groupAddress,
			}
		}
	default:
		// Unsupported IGMP type
		if p.log != nil {
			p.log.Warn().Msg("IGMP unsupported layer type")
		}
		return nil, nil
	}

	// Build the info string
	info := fmt.Sprintf("type=%s", igmpType)
	if groupAddress != "" && groupAddress != "0.0.0.0" {
		info += "; group=" + groupAddress
	}

	// Debug log
	if p.log != nil {
		if groupAddress != "" && groupAddress != "0.0.0.0" {
			p.log.Debug().
				Str("version", version).
				Str("type", igmpType).
				Str("group", groupAddress).
				Str("src", ipSource.String()).
				Msg("igmp packet parsed")
		} else {
			p.log.Debug().
				Str("version", version).
				Str("type", igmpType).
				Str("src", ipSource.String()).
				Msg("igmp packet parsed")
		}
	}

	record := &ParsedRecord{
		MAC:       append([]byte(nil), pkt.SrcMAC...),
		IP:        ipSource, // Use the source IP as the primary IP
		Protocols: []string{"IGMP"},
		Role:      "client", // IGMP is typically used by clients
		Info:      info,
		Source:    "passive",
		FirstSeen: pkt.Timestamp.UTC(),
		LastSeen:  pkt.Timestamp.UTC(),
		TTL:       int(pkt.TTL),
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  "IPv4", // IGMP is IPv4 only
		AppProto: "IGMP",
		Strength: "low", // IGMP multicast = low
		Extra:    extra,
	}

	return record, nil
}

// mapIGMPv1or2Type maps IGMPv1/v2 types to normalized types
func (p *IGMPParser) mapIGMPv1or2Type(igmp *layers.IGMPv1or2) (igmpType, groupAddress string) {
	if igmp == nil {
		return "unknown", "0.0.0.0"
	}

	groupAddress = "0.0.0.0"
	if igmp.GroupAddress != nil {
		groupAddress = igmp.GroupAddress.String()
	}

	switch igmp.Type {
	case 0x11: // IGMP Membership Query
		igmpType = "membership_query"
	case 0x12: // IGMP Membership Report V1
		igmpType = "membership_report"
	case 0x16: // IGMP Membership Report V2
		igmpType = "membership_report"
	case 0x17: // IGMP Leave Group
		igmpType = "leave_group"
	default:
		igmpType = "other"
	}

	return igmpType, groupAddress
}

// mapIGMPGenericType maps generic IGMP types to normalized types
func (p *IGMPParser) mapIGMPGenericType(igmp *layers.IGMP) (igmpType, groupAddress string) {
	if igmp == nil {
		return "unknown", "0.0.0.0"
	}

	groupAddress = "0.0.0.0"
	if igmp.GroupAddress != nil {
		groupAddress = igmp.GroupAddress.String()
	}

	switch igmp.Type {
	case 0x11: // IGMP Membership Query
		igmpType = "membership_query"
	case 0x12: // IGMP Membership Report V1
		igmpType = "membership_report"
	case 0x16: // IGMP Membership Report V2
		igmpType = "membership_report"
	case 0x17: // IGMP Leave Group
		igmpType = "leave_group"
	case 0x22: // IGMP Membership Report V3
		igmpType = "membership_report"
	default:
		igmpType = "other"
	}

	return igmpType, groupAddress
}
