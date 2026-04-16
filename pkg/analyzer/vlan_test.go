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

func TestParseVLANTag_Valid(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	dstMAC := net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}

	vlan := &layers.Dot1Q{
		VLANIdentifier: 42,
		Type:           layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, vlan)
	if err != nil {
		t.Fatalf("Failed to serialize VLAN packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseVLANTag(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "VLAN" {
		t.Errorf("Expected Protocols ['VLAN'], got %v", record.Protocols)
	}
	if record.Role != "" {
		t.Errorf("Expected empty Role, got %s", record.Role)
	}
	if !bytes.Equal(record.MAC, srcMAC) {
		t.Errorf("Expected MAC %v, got %v", srcMAC, record.MAC)
	}
	if !record.FirstSeen.Equal(now) {
		t.Errorf("Expected FirstSeen %v, got %v", now, record.FirstSeen)
	}
}

func TestParseVLANTag_NoVLANLayer(t *testing.T) {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buffer, opts, eth)

	pe := model.PacketEvent{
		SrcMAC:    eth.SrcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: time.Now(),
	}

	record, err := ParseVLANTag(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record for non-VLAN packet, got %+v", record)
	}
}

func TestParseVLANTag_EmptyPayload(t *testing.T) {
	t.Helper()

	pe := model.PacketEvent{
		SrcMAC:    net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		Payload:   nil,
		Timestamp: time.Now(),
	}

	record, err := ParseVLANTag(pe)
	if err == nil {
		t.Fatal("Expected error for empty payload, got nil")
	}
	if record != nil {
		t.Errorf("Expected nil record, got %+v", record)
	}
}

func TestParseVLANTag_VLANIDMapping(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	dstMAC := net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}
	vlanID := 42

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}

	vlan := &layers.Dot1Q{
		VLANIdentifier: uint16(vlanID),
		Type:           layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, vlan)
	if err != nil {
		t.Fatalf("Failed to serialize VLAN packet: %v", err)
	}

	now := time.Now()
	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: now,
	}

	record, err := ParseVLANTag(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if record.VLANID != vlanID {
		t.Errorf("Expected VLANID %d, got %d", vlanID, record.VLANID)
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "VLAN" {
		t.Errorf("Expected Protocols ['VLAN'], got %v", record.Protocols)
	}
	if record.Role != "" {
		t.Errorf("Expected empty Role, got %s", record.Role)
	}
}
