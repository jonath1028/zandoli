// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseSMBPacket_Client(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x0c, 0x29, 0x44, 0x55, 0x66}
	now := time.Now()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x08},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 1},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 55555,
		DstPort: 445,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	if err != nil {
		t.Fatalf("Failed to serialize SMB client packet: %v", err)
	}

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "SMB" {
		t.Errorf("Expected Protocols ['SMB'], got %v", record.Protocols)
	}
	if record.Role != "client" {
		t.Errorf("Expected Role client, got %s", record.Role)
	}
	if !bytes.Equal(record.MAC, srcMAC) {
		t.Errorf("Expected MAC %v, got %v", srcMAC, record.MAC)
	}
	if !record.FirstSeen.Equal(now) {
		t.Errorf("Expected FirstSeen %v, got %v", now, record.FirstSeen)
	}
}

func TestParseSMBPacket_Server(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x15, 0x5d, 0x00, 0x01, 0x01}
	now := time.Now()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 100},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 445,
		DstPort: 55555,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: now,
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}
}

func TestParseSMBPacket_InvalidPort(t *testing.T) {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x04},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 5678,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

	pe := model.PacketEvent{
		SrcMAC:    eth.SrcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now(),
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record, got %+v", record)
	}
}

func TestParseSMBPacket_Port139(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x0c, 0x29, 0x44, 0x55, 0x66}
	now := time.Now()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x08},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 1},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 139,
		DstPort: 55555,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	if err != nil {
		t.Fatalf("Failed to serialize SMB packet: %v", err)
	}

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}
	if len(record.Ports) != 1 || record.Ports[0] != 139 {
		t.Errorf("Expected Ports [139], got %v", record.Ports)
	}
}

func TestParseSMBPacket_ServerPort139(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x15, 0x5d, 0x00, 0x01, 0x01}
	now := time.Now()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 100},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 139,
		DstPort: 55555,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: now,
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}
	if len(record.Ports) != 1 || record.Ports[0] != 139 {
		t.Errorf("Expected Ports [139], got %v", record.Ports)
	}
}

func TestParseSMBPacket_ClientNoPorts(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x0c, 0x29, 0x44, 0x55, 0x66}
	now := time.Now()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x08},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 1},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 55555,
		DstPort: 445,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	if err != nil {
		t.Fatalf("Failed to serialize SMB packet: %v", err)
	}

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseSMBPacket(pe)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Role != "client" {
		t.Errorf("Expected Role client, got %s", record.Role)
	}
	if record.Ports != nil {
		t.Errorf("Expected nil Ports for client, got %v", record.Ports)
	}
}

func TestParseSMBPacket_WithWindowsOSGuess(t *testing.T) {
	t.Helper()

	// Test the SMB payload parsing directly
	record := &ParsedRecord{
		MAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x44, 0x55, 0x66},
		Protocols: []string{"SMB"},
		Role:      "server",
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Test the parseNullTerminatedStrings function directly
	testData := []byte("Windows 10\x00Windows 10\x00WORKGROUP\x00")
	strings := parseNullTerminatedStrings(testData)

	t.Logf("Test data: %x", testData)
	t.Logf("Parsed strings: %v", strings)

	if len(strings) >= 1 && strings[0] != "" {
		record.OSGuess = strings[0] // NativeOS
	}

	if record.OSGuess == "" {
		t.Error("Expected OSGuess to be set, got empty string")
	}
	if record.OSGuess != "Windows 10" {
		t.Errorf("Expected OSGuess 'Windows 10', got '%s'", record.OSGuess)
	}
}
