// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestDecodeNBName(t *testing.T) {
	t.Helper()

	// Test case: "WORKSTATION" encoded as NetBIOS name
	// Each character is split into two 4-bit nibbles, then 0x41 is added to each
	// "WORKSTATION" = 0x57 0x4F 0x52 0x4B 0x53 0x54 0x41 0x54 0x49 0x4F 0x4E
	// Encoded: 0x57 -> 0x57+0x41=0x98, 0x07+0x41=0x48 -> 0x98 0x48
	// This is a simplified test - in reality, NetBIOS names are padded to 16 chars

	// Create a proper 32-byte encoded NetBIOS name for "WORKSTATION"
	// NetBIOS names are padded to 16 characters with spaces, then encoded
	originalName := "WORKSTATION"
	paddedName := make([]byte, 16)
	copy(paddedName, originalName)
	for i := len(originalName); i < 16; i++ {
		paddedName[i] = ' ' // pad with spaces
	}

	// Encode the padded name
	encoded := make([]byte, 32)
	for i := 0; i < 16; i++ {
		highNibble := (paddedName[i] >> 4) + 0x41
		lowNibble := (paddedName[i] & 0x0F) + 0x41
		encoded[i*2] = highNibble
		encoded[i*2+1] = lowNibble
	}

	// Test the decode function
	decoded := decodeNBName(encoded)
	expected := "WORKSTATION"
	if decoded != expected {
		t.Errorf("Expected decoded name '%s', got '%s'", expected, decoded)
	}
}

func TestParseNetBIOSPacket_WithHostname(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hostIP := net.IP{192, 168, 1, 100}

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
		DstIP:    net.IP{192, 168, 1, 255}, // broadcast
		Protocol: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(137),
		DstPort: layers.UDPPort(137),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Create NBNS response packet manually
	// NBNS header: 2 bytes transaction ID, 2 bytes flags, 2 bytes questions, 2 bytes answers, etc.
	nbnsHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(nbnsHeader[0:2], 0x1234) // Transaction ID
	binary.BigEndian.PutUint16(nbnsHeader[2:4], 0x8400) // Flags: Response, Authoritative
	binary.BigEndian.PutUint16(nbnsHeader[4:6], 1)      // Questions
	binary.BigEndian.PutUint16(nbnsHeader[6:8], 1)      // Answers
	binary.BigEndian.PutUint16(nbnsHeader[8:10], 0)     // Authority RRs
	binary.BigEndian.PutUint16(nbnsHeader[10:12], 0)    // Additional RRs

	// Question section: name + type + class
	questionName := []byte{0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00}
	questionType := []byte{0x00, 0x20}  // NB record type
	questionClass := []byte{0x00, 0x01} // IN class

	// Answer section: name + type + class + TTL + data length + data
	answerName := questionName // Same as question
	answerType := questionType
	answerClass := questionClass
	answerTTL := make([]byte, 4)
	binary.BigEndian.PutUint32(answerTTL, 300) // 5 minutes TTL
	answerDataLen := []byte{0x00, 0x06}        // 6 bytes of data
	answerData := make([]byte, 6)
	binary.BigEndian.PutUint16(answerData[0:2], 0x0000) // Flags
	copy(answerData[2:6], hostIP.To4())                 // IP address

	// Combine all parts
	udpPayload := append(nbnsHeader, questionName...)
	udpPayload = append(udpPayload, questionType...)
	udpPayload = append(udpPayload, questionClass...)
	udpPayload = append(udpPayload, answerName...)
	udpPayload = append(udpPayload, answerType...)
	udpPayload = append(udpPayload, answerClass...)
	udpPayload = append(udpPayload, answerTTL...)
	udpPayload = append(udpPayload, answerDataLen...)
	udpPayload = append(udpPayload, answerData...)

	// Set UDP payload
	udp.Payload = udpPayload

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp)
	if err != nil {
		t.Fatalf("Failed to serialize NBNS packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseNetBIOSPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.Hostname == "" {
		t.Error("Expected hostname to be extracted, got empty string")
	}
	if !record.IP.Equal(hostIP) {
		t.Errorf("Expected IP %s, got %s", hostIP.String(), record.IP.String())
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "NBNS" {
		t.Errorf("Expected Protocols ['NBNS'], got %v", record.Protocols)
	}
	if record.Role != "server" {
		t.Errorf("Expected Role server, got %s", record.Role)
	}
}

func TestGetNetBIOSServiceName(t *testing.T) {
	t.Helper()

	testCases := []struct {
		suffix   byte
		expected string
	}{
		{0x00, "workstation"},
		{0x20, "file_server"},
		{0x1C, "domain_controller"},
		{0x03, "messenger"},
		{0x1D, "master_browser"},
		{0x1E, "browser_service"},
		{0x06, "ras_server"},
		{0x21, "ras_client"},
		{0x1B, "domain_master_browser"},
		{0x1F, "netdde"},
		{0x22, "exchange_interchange"},
		{0x23, "exchange_store"},
		{0x24, "exchange_directory"},
		{0x87, "exchange_mta"},
		{0x6A, "exchange_imc"},
		{0xBE, "netmon_agent"},
		{0xBF, "netmon_app"},
		{0xFF, "service_0xFF"}, // Unknown service
	}

	for _, tc := range testCases {
		result := getNetBIOSServiceName(tc.suffix)
		if result != tc.expected {
			t.Errorf("For suffix 0x%02X, expected '%s', got '%s'", tc.suffix, tc.expected, result)
		}
	}
}

func TestExtractNetBIOSServiceInfo(t *testing.T) {
	t.Helper()

	// Test with workstation service (0x00) - create a simple encoded name
	originalName := "WORKSTATION"
	paddedName := make([]byte, 16)
	copy(paddedName, originalName)
	for i := len(originalName); i < 16; i++ {
		paddedName[i] = ' ' // pad with spaces
	}
	// Set the 16th character to workstation service suffix
	paddedName[15] = 0x00

	// Encode the padded name
	encoded := make([]byte, 32)
	for i := 0; i < 16; i++ {
		highNibble := (paddedName[i] >> 4) + 0x41
		lowNibble := (paddedName[i] & 0x0F) + 0x41
		encoded[i*2] = highNibble
		encoded[i*2+1] = lowNibble
	}

	// Test the service extraction
	serviceInfo := extractNetBIOSServiceInfo(encoded)
	expected := "workstation"
	if serviceInfo != expected {
		t.Errorf("Expected service '%s', got '%s'", expected, serviceInfo)
	}

	// Test with file server service (0x20) - create a new encoded name
	paddedName[15] = 0x20 // File server service suffix
	for i := 0; i < 16; i++ {
		highNibble := (paddedName[i] >> 4) + 0x41
		lowNibble := (paddedName[i] & 0x0F) + 0x41
		encoded[i*2] = highNibble
		encoded[i*2+1] = lowNibble
	}

	serviceInfo = extractNetBIOSServiceInfo(encoded)
	expected = "file_server"
	if serviceInfo != expected {
		t.Errorf("Expected service '%s', got '%s'", expected, serviceInfo)
	}
}
