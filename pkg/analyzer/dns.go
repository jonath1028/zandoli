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

// ParseDNSPacket analyzes standard DNS traffic over UDP/53.
// It extracts hostnames from DNS responses (A/AAAA records) and query names.
func ParseDNSPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
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

	// Check port 53 (standard DNS)
	if udp.SrcPort != 53 && udp.DstPort != 53 {
		return nil, nil
	}

	// Decode the DNS payload
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, nil
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok || dns == nil {
		return nil, nil
	}

	// client = query sender (→53), server = resolver that responds (53→)
	var role string
	var isQuery bool
	if udp.DstPort == 53 {
		role = "client"
		isQuery = true
	} else {
		role = "server"
		isQuery = !dns.QR // QR=1 means response
	}

	var ip net.IP
	var hostname string
	var qName string

	// Extract the queried name
	if len(dns.Questions) > 0 {
		qName = strings.TrimSuffix(string(dns.Questions[0].Name), ".")
	}

	// Extract hostname+IP from A/AAAA answers (only in responses)
	if dns.QR {
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
				ip = answer.IP
				hostname = strings.TrimSuffix(string(answer.Name), ".")
				break
			}
		}
	}

	// Extract source and destination IPs
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

	var info string

	if isQuery {
		// DNS query: do NOT assign hostname from qName (qName is what the client
		// is looking up, not the client's own hostname). Keep protocol for enrichment.
		if qName != "" {
			info = "query=" + qName
		}

		record := &ParsedRecord{
			MAC:       append([]byte(nil), pkt.SrcMAC...),
			Protocols: []string{"DNS"},
			Role:      role,
			Info:      info,
			Source:    "passive",
			FirstSeen: pkt.Timestamp.UTC(),
			LastSeen:  pkt.Timestamp.UTC(),
			TTL:       int(pkt.TTL),
			IsQuery:   isQuery,
			QName:     qName,
			IPSource:  ipSource,
			IPDest:    ipDest,
			L3Proto:   l3Proto,
			AppProto:  "DNS",
			Strength:  "medium",
			Transport: "udp",
			SrcPort:   uint16(udp.SrcPort),
			DstPort:   uint16(udp.DstPort),
		}
		return record, nil
	}

	// DNS response: hostname comes from A/AAAA answer records, associated with
	// the resolved IP (not the source IP of the packet).
	if hostname == "" {
		// Response without usable A/AAAA records — nothing to emit
		return nil, nil
	}

	if hostname != "" {
		info = "hostname=" + hostname
	}

	record := &ParsedRecord{
		MAC:       append([]byte(nil), pkt.SrcMAC...),
		IP:        ip,
		Hostname:  hostname,
		Protocols: []string{"DNS"},
		Role:      role,
		Info:      info,
		Source:    "passive",
		FirstSeen: pkt.Timestamp.UTC(),
		LastSeen:  pkt.Timestamp.UTC(),
		TTL:       int(pkt.TTL),
		IsQuery:   isQuery,
		QName:     qName,
		IPSource:  ipSource,
		IPDest:    ipDest,
		L3Proto:   l3Proto,
		AppProto:  "DNS",
		Strength:  "medium",
		Transport: "udp",
		SrcPort:   uint16(udp.SrcPort),
		DstPort:   uint16(udp.DstPort),
	}

	return record, nil
}
