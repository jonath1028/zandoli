// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"strings"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseMDNSPacket_WithHostnameAndIP(t *testing.T) {
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
		DstIP:    net.IP{224, 0, 0, 251}, // mDNS multicast
		Protocol: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
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
				Name:  []byte(hostname + ".local."),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(hostname + ".local."),
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
		t.Fatalf("Failed to serialize mDNS packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseMDNSPacket(pe)
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
	if len(record.Protocols) != 1 || record.Protocols[0] != "mDNS" {
		t.Errorf("Expected Protocols ['mDNS'], got %v", record.Protocols)
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}
}

func TestParseMDNSPacket_IPv6(t *testing.T) {
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
		DstIP:      net.ParseIP("ff02::fb"), // mDNS IPv6 multicast
		NextHeader: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
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
				Name:  []byte(hostname + ".local."),
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(hostname + ".local."),
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
		t.Fatalf("Failed to serialize mDNS IPv6 packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseMDNSPacket(pe)
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
	if len(record.Protocols) != 1 || record.Protocols[0] != "mDNS" {
		t.Errorf("Expected Protocols ['mDNS'], got %v", record.Protocols)
	}
}

func TestParseMDNSPacket_WithServices(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hostIP := net.IP{192, 168, 1, 101}
	hostname := "printer-host"

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
		DstIP:    net.IP{224, 0, 0, 251}, // mDNS multicast
		Protocol: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Create DNS response with service records
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           true, // Response
		OpCode:       layers.DNSOpCodeQuery,
		AA:           true, // Authoritative
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(hostname + ".local."),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(hostname + ".local."),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    hostIP,
				TTL:   300,
			},
			{
				Name:  []byte("_printer._tcp.local."),
				Type:  layers.DNSTypePTR,
				Class: layers.DNSClassIN,
				PTR:   []byte(hostname + ".local."),
				TTL:   300,
			},
			{
				Name:  []byte("_workstation._tcp.local."),
				Type:  layers.DNSTypePTR,
				Class: layers.DNSClassIN,
				PTR:   []byte(hostname + ".local."),
				TTL:   300,
			},
		},
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp, dns)
	if err != nil {
		t.Fatalf("Failed to serialize mDNS packet with services: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseMDNSPacket(pe)
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
	if len(record.Protocols) != 1 || record.Protocols[0] != "mDNS" {
		t.Errorf("Expected Protocols ['mDNS'], got %v", record.Protocols)
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}

	// Check that service information is extracted
	if record.Info == "" {
		t.Error("Expected Info to contain service information, got empty string")
	}

	// Check for specific services
	if !strings.Contains(record.Info, "service=_printer._tcp") {
		t.Errorf("Expected Info to contain '_printer._tcp' service, got: %s", record.Info)
	}
	if !strings.Contains(record.Info, "service=_workstation._tcp") {
		t.Errorf("Expected Info to contain '_workstation._tcp' service, got: %s", record.Info)
	}
	if !strings.Contains(record.Info, "hostname="+hostname) {
		t.Errorf("Expected Info to contain hostname, got: %s", record.Info)
	}
}
