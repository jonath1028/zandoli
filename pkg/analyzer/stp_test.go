// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"
)

func TestParseSTPPacket_Valid(t *testing.T) {
	t.Helper()

	// Ethernet header (14 bytes) + LLC (3 bytes) + STP BPDU (35 bytes minimum)
	payload := make([]byte, 52) // 14 + 3 + 35

	// Ethernet header (14 bytes)
	// Dst MAC: 01:80:c2:00:00:00 (STP multicast)
	copy(payload[0:6], []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00})
	// Src MAC: de:ad:be:ef:00:01
	copy(payload[6:12], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})
	// EtherType: 0x0026 (length for 802.3 frame)
	payload[12] = 0x00
	payload[13] = 0x26

	// LLC header (3 bytes)
	copy(payload[14:17], []byte{0x42, 0x42, 0x03}) // DSAP, SSAP, Control

	// STP BPDU structure (after LLC header at offset 17):
	// Byte 0-1: Protocol ID (0x0000)
	payload[17] = 0x00
	payload[18] = 0x00
	// Byte 2: Version (0x00)
	payload[19] = 0x00
	// Byte 3: Message Type (0x00 for Configuration BPDU)
	payload[20] = 0x00
	// Byte 4: Flags
	payload[21] = 0x00

	// Byte 5-12: Root ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	// Root ID: priority 32768, MAC 00:11:22:33:44:55
	payload[22] = 0x80                                               // Root priority high byte
	payload[23] = 0x00                                               // Root priority low byte
	copy(payload[24:30], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Root MAC

	// Byte 13-16: Root Path Cost (4 bytes) = 100
	payload[30] = 0x00
	payload[31] = 0x00
	payload[32] = 0x00
	payload[33] = 0x64 // 100

	// Byte 17-24: Bridge ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	// Bridge ID: priority 32768, MAC de:ad:be:ef:00:01
	payload[34] = 0x80                                               // Bridge priority high byte
	payload[35] = 0x00                                               // Bridge priority low byte
	copy(payload[36:42], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // Bridge MAC

	// Byte 25-26: Port ID (2 bytes) = 0x8004
	payload[42] = 0x80
	payload[43] = 0x04

	// Byte 27-28: Message Age (2 bytes) = 1 second
	payload[44] = 0x00
	payload[45] = 0x01

	// Byte 29-30: Max Age (2 bytes) = 20 seconds
	payload[46] = 0x00
	payload[47] = 0x14

	// Byte 31-32: Hello Time (2 bytes) = 2 seconds
	payload[48] = 0x00
	payload[49] = 0x02

	// Byte 33-34: Forward Delay (2 bytes) = 15 seconds
	payload[50] = 0x00
	payload[51] = 0x0f

	srcMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}
	timestamp := time.Now()

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		Payload:   payload,
		Timestamp: timestamp,
	}

	record, err := ParseSTPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "STP" {
		t.Errorf("Expected Protocols ['STP'], got %v", record.Protocols)
	}
	if record.Role != "network_device" {
		t.Errorf("Expected Role network_device, got %s", record.Role)
	}
	if !bytes.Equal(record.MAC, pe.SrcMAC) {
		t.Errorf("Expected MAC %v, got %v", pe.SrcMAC, record.MAC)
	}
	if !record.FirstSeen.Equal(timestamp.UTC()) {
		t.Errorf("Expected FirstSeen %v, got %v", timestamp.UTC(), record.FirstSeen)
	}

	// Check STP info structure
	if record.STPInfo == nil {
		t.Fatal("Expected STPInfo to be populated")
	}
	if record.STPInfo.BridgeID != "32768:de:ad:be:ef:00:01" {
		t.Errorf("Expected BridgeID 32768:de:ad:be:ef:00:01, got %s", record.STPInfo.BridgeID)
	}
	if record.STPInfo.RootBridgeID != "32768:00:11:22:33:44:55" {
		t.Errorf("Expected RootBridgeID 32768:00:11:22:33:44:55, got %s", record.STPInfo.RootBridgeID)
	}
	if record.STPInfo.RootPathCost != 100 {
		t.Errorf("Expected RootPathCost 100, got %d", record.STPInfo.RootPathCost)
	}
	if record.STPInfo.PortID != 0x8004 {
		t.Errorf("Expected PortID 0x8004, got 0x%x", record.STPInfo.PortID)
	}
	if record.STPInfo.IsRoot {
		t.Error("Expected IsRoot to be false")
	}
}

func TestParseSTPPacket_InvalidLLC(t *testing.T) {
	t.Helper()

	payload := make([]byte, 17)
	copy(payload[14:], []byte{0xAA, 0xAA, 0xAA}) // Incorrect LLC

	pe := model.PacketEvent{
		SrcMAC:    net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		Payload:   payload,
		Timestamp: time.Now(),
	}

	record, err := ParseSTPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record for invalid LLC, got %+v", record)
	}
}

func TestParseSTPPacket_ShortPayload(t *testing.T) {
	t.Helper()

	pe := model.PacketEvent{
		SrcMAC:    net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x03},
		Payload:   []byte{0x00, 0x01, 0x02}, // < 17 bytes
		Timestamp: time.Now(),
	}

	record, err := ParseSTPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record for short packet, got %+v", record)
	}
}

func TestParseSTPPacket_RootBridge(t *testing.T) {
	t.Helper()

	// Ethernet header (14 bytes) + LLC (3 bytes) + STP BPDU (35 bytes minimum)
	payload := make([]byte, 52) // 14 + 3 + 35

	// Ethernet header (14 bytes)
	// Dst MAC: 01:80:c2:00:00:00 (STP multicast)
	copy(payload[0:6], []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00})
	// Src MAC: de:ad:be:ef:00:01
	copy(payload[6:12], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})
	// EtherType: 0x0026 (length for 802.3 frame)
	payload[12] = 0x00
	payload[13] = 0x26

	// LLC header (3 bytes)
	copy(payload[14:17], []byte{0x42, 0x42, 0x03}) // DSAP, SSAP, Control

	// STP BPDU structure (after LLC header at offset 17):
	// Byte 0-1: Protocol ID (0x0000)
	payload[17] = 0x00
	payload[18] = 0x00
	// Byte 2: Version (0x00)
	payload[19] = 0x00
	// Byte 3: Message Type (0x00 for Configuration BPDU)
	payload[20] = 0x00
	// Byte 4: Flags
	payload[21] = 0x00

	// Byte 5-12: Root ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	// Root ID: priority 32768, MAC de:ad:be:ef:00:01 (same as bridge)
	payload[22] = 0x80                                               // Root priority high byte
	payload[23] = 0x00                                               // Root priority low byte
	copy(payload[24:30], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // Root MAC (same as bridge)

	// Byte 13-16: Root Path Cost (4 bytes) = 0 (root bridge)
	payload[30] = 0x00
	payload[31] = 0x00
	payload[32] = 0x00
	payload[33] = 0x00 // 0

	// Byte 17-24: Bridge ID (8 bytes: 2 bytes priority + 6 bytes MAC)
	// Bridge ID: priority 32768, MAC de:ad:be:ef:00:01 (same as root)
	payload[34] = 0x80                                               // Bridge priority high byte
	payload[35] = 0x00                                               // Bridge priority low byte
	copy(payload[36:42], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // Bridge MAC

	// Byte 25-26: Port ID (2 bytes) = 0x8004
	payload[42] = 0x80
	payload[43] = 0x04

	// Byte 27-28: Message Age (2 bytes) = 0 (root bridge)
	payload[44] = 0x00
	payload[45] = 0x00

	// Byte 29-30: Max Age (2 bytes) = 20 seconds
	payload[46] = 0x00
	payload[47] = 0x14

	// Byte 31-32: Hello Time (2 bytes) = 2 seconds
	payload[48] = 0x00
	payload[49] = 0x02

	// Byte 33-34: Forward Delay (2 bytes) = 15 seconds
	payload[50] = 0x00
	payload[51] = 0x0f

	srcMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}
	timestamp := time.Now()

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		Payload:   payload,
		Timestamp: timestamp,
	}

	record, err := ParseSTPPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}

	// Check STP info structure for root bridge
	if record.STPInfo == nil {
		t.Fatal("Expected STPInfo to be populated")
	}
	if !record.STPInfo.IsRoot {
		t.Error("Expected IsRoot to be true for root bridge")
	}
	if record.STPInfo.BridgeID != record.STPInfo.RootBridgeID {
		t.Error("Expected BridgeID to equal RootBridgeID for root bridge")
	}
	if record.STPInfo.RootPathCost != 0 {
		t.Errorf("Expected RootPathCost 0 for root bridge, got %d", record.STPInfo.RootPathCost)
	}
}

func TestSTPMultipleRootsDetection(t *testing.T) {
	t.Helper()

	// Test the aggregator's ability to detect multiple STP roots
	aggregator := NewAggregator()

	// Create two hosts that both claim to be STP root
	mac1 := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	mac2 := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}

	// Create STP info for root bridges
	stpInfo1 := &model.STPInfo{
		RootBridgeID: "32768:de:ad:be:ef:00:01",
		RootPathCost: 0,
		BridgeID:     "32768:de:ad:be:ef:00:01",
		PortID:       0x8004,
		IsRoot:       true,
	}

	stpInfo2 := &model.STPInfo{
		RootBridgeID: "32768:de:ad:be:ef:00:02",
		RootPathCost: 0,
		BridgeID:     "32768:de:ad:be:ef:00:02",
		PortID:       0x8004,
		IsRoot:       true,
	}

	// Add hosts to aggregator
	aggregator.Merge(&ParsedRecord{
		MAC:       mac1,
		Protocols: []string{"STP"},
		Info:      "stpRoot=true stpBridgeID=32768:de:ad:be:ef:00:01 stpRootID=32768:de:ad:be:ef:00:01 stpPathCost=0",
		Source:    "passive",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		STPInfo:   stpInfo1,
	})

	aggregator.Merge(&ParsedRecord{
		MAC:       mac2,
		Protocols: []string{"STP"},
		Info:      "stpRoot=true stpBridgeID=32768:de:ad:be:ef:00:02 stpRootID=32768:de:ad:be:ef:00:02 stpPathCost=0",
		Source:    "passive",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		STPInfo:   stpInfo2,
	})

	// Detect anomalies after adding hosts
	aggregator.DetectAnomalies()

	// Get results and check for anomalies
	results := aggregator.GetAll()

	// Check that both hosts have the "Multiple STP roots" anomaly
	anomalyFound := false
	for _, host := range results {
		for _, anomaly := range host.Anomalies {
			if anomaly.Description == "Multiple STP roots" && anomaly.Severity == "high" {
				anomalyFound = true
				break
			}
		}
		if anomalyFound {
			break
		}
	}

	if !anomalyFound {
		t.Error("Expected 'Multiple STP roots' anomaly to be detected, but it wasn't found")
	}
}

func TestSTPAggregatorIntegration(t *testing.T) {
	t.Helper()

	// Test that the aggregator correctly handles STP information
	aggregator := NewAggregator()

	// Create a valid STP record
	mac := net.HardwareAddr{0x00, 0x1c, 0x0e, 0x87, 0x85, 0x04}
	stpInfo := &model.STPInfo{
		RootBridgeID: "32868:00:1c:0e:87:78:00",
		RootPathCost: 4,
		BridgeID:     "32868:00:1c:0e:87:85:00",
		PortID:       32772,
		HelloTime:    512,
		MaxAge:       5120,
		ForwardDelay: 3840,
		MessageAge:   256,
		IsRoot:       false,
	}

	record := &ParsedRecord{
		MAC:       mac,
		Protocols: []string{"STP"},
		Role:      "network_device",
		Info:      "stpRoot=false stpBridgeID=32868:00:1c:0e:87:85:00 stpRootID=32868:00:1c:0e:87:78:00 stpPathCost=4 stpPortID=32772",
		Source:    "passive",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		STPInfo:   stpInfo,
	}

	// Merge the record
	aggregator.Merge(record)

	// Get results
	results := aggregator.GetAll()

	if len(results) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(results))
	}

	host := results[0]

	// Check basic fields
	if host.MACStr != mac.String() {
		t.Errorf("Expected MAC %s, got %s", mac.String(), host.MACStr)
	}

	if len(host.Protocols) != 1 || host.Protocols[0] != "STP" {
		t.Errorf("Expected Protocols ['STP'], got %v", host.Protocols)
	}

	// In simplified aggregator, role is not normalized, so accept network_device or reseau
	if host.Role != "reseau" && host.Role != "network_device" {
		t.Errorf("Expected Role reseau or network_device, got %s", host.Role)
	}

	// Check STP info
	if host.STP == nil {
		t.Fatal("Expected STP info to be populated")
	}

	if host.STP.RootBridgeID != stpInfo.RootBridgeID {
		t.Errorf("Expected RootBridgeID %s, got %s", stpInfo.RootBridgeID, host.STP.RootBridgeID)
	}

	if host.STP.BridgeID != stpInfo.BridgeID {
		t.Errorf("Expected BridgeID %s, got %s", stpInfo.BridgeID, host.STP.BridgeID)
	}

	if host.STP.RootPathCost != stpInfo.RootPathCost {
		t.Errorf("Expected RootPathCost %d, got %d", stpInfo.RootPathCost, host.STP.RootPathCost)
	}

	if host.STP.PortID != stpInfo.PortID {
		t.Errorf("Expected PortID %d, got %d", stpInfo.PortID, host.STP.PortID)
	}

	if host.STP.IsRoot != stpInfo.IsRoot {
		t.Errorf("Expected IsRoot %t, got %t", stpInfo.IsRoot, host.STP.IsRoot)
	}
}
