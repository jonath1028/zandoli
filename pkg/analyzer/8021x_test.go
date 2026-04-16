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

func TestParseEAPOLPacket_Valid(t *testing.T) {
	t.Helper()

	srcMAC := net.HardwareAddr{0x00, 0x13, 0x72, 0xAA, 0xBB, 0xCC}
	dstMAC := net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x03} // EAPOL multicast

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: 0x888e, // EAPOL EtherType
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, opts, eth)
	if err != nil {
		t.Fatalf("Failed to serialize EAPOL packet: %v", err)
	}

	payload := buffer.Bytes()
	now := time.Now()

	pe := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   payload,
		Timestamp: now,
	}

	record, err := ParseEAPOLPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record == nil {
		t.Fatal("Expected ParsedRecord, got nil")
	}
	if len(record.Protocols) != 1 || record.Protocols[0] != "802.1X" {
		t.Errorf("Expected Protocols ['802.1X'], got %v", record.Protocols)
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

func TestParseEAPOLPacket_InvalidEtherType(t *testing.T) {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	_ = gopacket.SerializeLayers(buffer, opts, eth)

	pe := model.PacketEvent{
		SrcMAC:    eth.SrcMAC,
		Payload:   buffer.Bytes(),
		Timestamp: time.Now(),
	}

	record, err := ParseEAPOLPacket(pe)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if record != nil {
		t.Errorf("Expected nil record for non-EAPOL packet, got %+v", record)
	}
}

func TestParseEAPOLPacket_EmptyPayload(t *testing.T) {
	t.Helper()

	pe := model.PacketEvent{
		SrcMAC:    net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x03},
		Payload:   nil,
		Timestamp: time.Now(),
	}

	record, err := ParseEAPOLPacket(pe)
	if err == nil {
		t.Fatal("Expected error for empty payload, got nil")
	}
	if record != nil {
		t.Errorf("Expected nil record, got %+v", record)
	}
}
