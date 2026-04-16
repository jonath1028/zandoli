// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseLLDPPacket_Valid(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e} // LLDP multicast

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: 0x88cc, // LLDP EtherType
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth)
	if err != nil {
		t.Fatalf("Failed to serialize LLDP packet: %v", err)
	}

	payload := buffer.Bytes()
	now := time.Now()

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   payload,
		Timestamp: now,
	}

	record, err := ParseLLDPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "LLDP" {
		t.Errorf("Expected Protocols ['LLDP'], got %v", record.Protocols)
	}
	if record.Role != "reseau" {
		t.Errorf("Expected Role reseau, got %s", record.Role)
	}
	if !bytes.Equal(record.MAC, pe.SrcMAC) {
		t.Errorf("Expected MAC %v, got %v", pe.SrcMAC, record.MAC)
	}
	if !record.FirstSeen.Equal(now) {
		t.Errorf("Expected FirstSeen %v, got %v", now, record.FirstSeen)
	}
}

func TestParseLLDPPacket_InvalidEtherType(t *testing.T) {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: 0x0800, // IPv4
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buffer, opts, eth)

	pe := model.PacketEvent{
		SrcMAC:    eth.SrcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: time.Now(),
	}

	record, err := ParseLLDPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error for non-LLDP packet, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record for non-LLDP packet, got %+v", record)
	}
}

func TestParseLLDPPacket_EmptyPayload(t *testing.T) {
	t.Helper()

	pe := model.PacketEvent{
		SrcMAC:    net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		Payload:   nil,
		Timestamp: time.Now(),
	}

	record, err := ParseLLDPPacket(pe)
	if err == nil {
		t.Fatal("Expected error for empty payload, got nil")
	}
	if record != nil {
		t.Errorf("Expected nil record, got %+v", record)
	}
}

func TestParseLLDPCapabilities_Router(t *testing.T) {
	t.Helper()

	// Simuler un TLV System Capabilities avec capability router
	// TLV Type 7 (System Capabilities), Length 4, System Capabilities = 0x0000, Enabled Capabilities = 0x0001 (router)
	payload := []byte{
		0x0E, 0x04, // Type 7, Length 4
		0x00, 0x00, // System Capabilities
		0x00, 0x01, // Enabled Capabilities (bit 0 = router)
	}

	role, _, _, _, _ := parseLLDPCapabilities(payload)
	if role != "reseau" {
		t.Errorf("Expected role reseau, got %s", role)
	}
}

func TestParseLLDPCapabilities_Switch(t *testing.T) {
	t.Helper()

	// Simuler un TLV System Capabilities sans capability router
	// TLV Type 7 (System Capabilities), Length 4, System Capabilities = 0x0000, Enabled Capabilities = 0x0000 (pas de router)
	payload := []byte{
		0x0E, 0x04, // Type 7, Length 4
		0x00, 0x00, // System Capabilities
		0x00, 0x00, // Enabled Capabilities (pas de router)
	}

	role, _, _, _, _ := parseLLDPCapabilities(payload)
	if role != "reseau" {
		t.Errorf("Expected role reseau, got %s", role)
	}
}

func TestParseLLDPCapabilities_Empty(t *testing.T) {
	t.Helper()

	// Payload vide
	payload := []byte{}

	role, _, _, _, _ := parseLLDPCapabilities(payload)
	if role != "reseau" {
		t.Errorf("Expected role reseau for empty payload, got %s", role)
	}
}

func TestParseLLDPCapabilities_SystemName(t *testing.T) {
	t.Helper()

	// TLV System Name (Type 5) avec le nom "Switch01"
	payload := []byte{
		0x0A, 0x08, // Type 5, Length 8
		'S', 'w', 'i', 't', 'c', 'h', '0', '1',
	}

	_, _, hostname, _, _ := parseLLDPCapabilities(payload)
	if hostname != "Switch01" {
		t.Errorf("Expected hostname 'Switch01', got '%s'", hostname)
	}
}

func TestParseLLDPCapabilities_SystemDescription(t *testing.T) {
	t.Helper()

	// TLV System Description (Type 6) avec la description "Cisco IOS"
	payload := []byte{
		0x0C, 0x0B, // Type 6, Length 11
		'C', 'i', 's', 'c', 'o', ' ', 'I', 'O', 'S', ' ', '1',
	}

	_, info, _, _, _ := parseLLDPCapabilities(payload)
	expected := "model=Cisco IOS 1"
	if info != expected {
		t.Errorf("Expected info '%s', got '%s'", expected, info)
	}
}

func TestParseLLDPCapabilities_ManagementAddress(t *testing.T) {
	t.Helper()

	// TLV Management Address (Type 8) avec l'adresse IP 192.168.1.1
	payload := []byte{
		0x10, 0x04, // Type 8, Length 4
		192, 168, 1, 1, // IP address
	}

	_, info, _, mgmtIP, _ := parseLLDPCapabilities(payload)
	expectedIP := net.IP{192, 168, 1, 1}
	if !mgmtIP.Equal(expectedIP) {
		t.Errorf("Expected management IP %v, got %v", expectedIP, mgmtIP)
	}
	expectedInfo := "MgmtIP:192.168.1.1"
	if info != expectedInfo {
		t.Errorf("Expected info '%s', got '%s'", expectedInfo, info)
	}
}

func TestParseLLDPCapabilities_Complete(t *testing.T) {
	t.Helper()

	// TLV complet avec System Name, System Description, System Capabilities et Management Address
	payload := []byte{
		// System Name TLV (Type 5)
		0x0A, 0x08, // Type 5, Length 8
		'S', 'w', 'i', 't', 'c', 'h', '0', '1',
		// System Description TLV (Type 6)
		0x0C, 0x0B, // Type 6, Length 11
		'C', 'i', 's', 'c', 'o', ' ', 'I', 'O', 'S', ' ', '1',
		// System Capabilities TLV (Type 7) - Router
		0x0E, 0x04, // Type 7, Length 4
		0x00, 0x00, // System Capabilities
		0x00, 0x01, // Enabled Capabilities (bit 0 = router)
		// Management Address TLV (Type 8)
		0x10, 0x04, // Type 8, Length 4
		192, 168, 1, 1, // IP address
		// End of LLDPDU TLV (Type 0)
		0x00, 0x00, // Type 0, Length 0
	}

	role, info, hostname, mgmtIP, lldpInfo := parseLLDPCapabilities(payload)

	if role != "reseau" {
		t.Errorf("Expected role reseau, got %s", role)
	}
	if hostname != "Switch01" {
		t.Errorf("Expected hostname 'Switch01', got '%s'", hostname)
	}
	expectedIP := net.IP{192, 168, 1, 1}
	if !mgmtIP.Equal(expectedIP) {
		t.Errorf("Expected management IP %v, got %v", expectedIP, mgmtIP)
	}
	// L'info devrait contenir à la fois la description et l'IP de gestion
	if !strings.Contains(info, "model=Cisco IOS 1") {
		t.Errorf("Expected info to contain 'model=Cisco IOS 1', got '%s'", info)
	}
	if !strings.Contains(info, "MgmtIP:192.168.1.1") {
		t.Errorf("Expected info to contain 'MgmtIP:192.168.1.1', got '%s'", info)
	}

	// Vérifier la structure LLDPInfo
	if lldpInfo == nil {
		t.Error("Expected lldpInfo to be non-nil")
	} else {
		if lldpInfo.SysName != "Switch01" {
			t.Errorf("Expected LLDPInfo.SysName 'Switch01', got '%s'", lldpInfo.SysName)
		}
		if lldpInfo.SysDescr != "Cisco IOS 1" {
			t.Errorf("Expected LLDPInfo.SysDescr 'Cisco IOS 1', got '%s'", lldpInfo.SysDescr)
		}
		if len(lldpInfo.MgmtAddrs) != 1 || lldpInfo.MgmtAddrs[0] != "192.168.1.1" {
			t.Errorf("Expected LLDPInfo.MgmtAddrs ['192.168.1.1'], got %v", lldpInfo.MgmtAddrs)
		}
		if len(lldpInfo.Capabilities) == 0 {
			t.Error("Expected LLDPInfo.Capabilities to be non-empty")
		}
	}
}
