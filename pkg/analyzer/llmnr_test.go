// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseLLMNRPacket_WithHostnameAndIP(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hostIP := net.IP{192, 168, 1, 100}
	hostname := "test-hostname"

	// Create Ethernet frame
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    hostIP,
		DstIP:    net.IP{224, 0, 0, 252}, // LLMNR multicast
		Protocol: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5355),
		DstPort: layers.UDPPort(5355),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Create DNS response
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           true, // Response
		OpCode:       layers.DNSOpCodeQuery,
		AA:           true, // Authoritative
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(hostname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(hostname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    hostIP,
				TTL:   300,
			},
		},
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp, dns)
	if err != nil {
		t.Fatalf("Failed to serialize LLMNR packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseLLMNRPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Hostname != hostname {
		t.Errorf("Expected Hostname '%s', got '%s'", hostname, record.Hostname)
	}
	if !record.IP.Equal(hostIP) {
		t.Errorf("Expected IP %s, got %s", hostIP.String(), record.IP.String())
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "LLMNR" {
		t.Errorf("Expected Protocols ['LLMNR'], got %v", record.Protocols)
	}
	if record.Role != "client" {
		t.Errorf("Expected Role client, got %s", record.Role)
	}
}

func TestParseLLMNRPacket_IPv6(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hostIP := net.ParseIP("2001:db8::1")
	hostname := "ipv6-hostname"

	// Create Ethernet frame
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// Create IPv6 layer
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      hostIP,
		DstIP:      net.ParseIP("ff02::1:3"), // LLMNR IPv6 multicast
		NextHeader: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5355),
		DstPort: layers.UDPPort(5355),
	}
	_ = udp.SetNetworkLayerForChecksum(ipv6)

	// Create DNS response
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           true, // Response
		OpCode:       layers.DNSOpCodeQuery,
		AA:           true, // Authoritative
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(hostname),
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(hostname),
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    hostIP,
				TTL:   300,
			},
		},
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ipv6, udp, dns)
	if err != nil {
		t.Fatalf("Failed to serialize LLMNR IPv6 packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseLLMNRPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Hostname != hostname {
		t.Errorf("Expected Hostname '%s', got '%s'", hostname, record.Hostname)
	}
	if !record.IP.Equal(hostIP) {
		t.Errorf("Expected IP %s, got %s", hostIP.String(), record.IP.String())
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "LLMNR" {
		t.Errorf("Expected Protocols ['LLMNR'], got %v", record.Protocols)
	}
}
