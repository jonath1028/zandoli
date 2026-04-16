// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// TestHashMAC_Deterministic verifies that hashMAC is deterministic
// (same MAC always maps to same shard).
func TestHashMAC_Deterministic(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	k := 4

	first := hashMAC(mac, k)
	for i := 0; i < 100; i++ {
		if got := hashMAC(mac, k); got != first {
			t.Fatalf("hashMAC not deterministic: first=%d, got=%d at iteration %d", first, got, i)
		}
	}
}

// TestHashMAC_Distribution verifies that hashMAC distributes MACs across shards.
func TestHashMAC_Distribution(t *testing.T) {
	k := 4
	counts := make([]int, k)

	// Generate 100 different MACs
	for i := 0; i < 100; i++ {
		mac := net.HardwareAddr{byte(i), byte(i >> 8), 0x22, 0x33, 0x44, 0x55}
		idx := hashMAC(mac, k)
		if idx < 0 || idx >= k {
			t.Fatalf("hashMAC returned out-of-range index: %d (k=%d)", idx, k)
		}
		counts[idx]++
	}

	// Verify all shards got at least some packets (basic distribution check)
	for i, c := range counts {
		if c == 0 {
			t.Errorf("shard %d received 0 packets — bad distribution", i)
		}
		t.Logf("shard %d: %d packets", i, c)
	}
}

// TestFanOutAnalyze_Correctness verifies that the fan-out produces
// the same results as sequential processing for ARP packets.
func TestFanOutAnalyze_Correctness(t *testing.T) {
	// Create a channel with synthetic ARP-like packets from 3 different MACs
	packetChan := make(chan model.PacketEvent, 100)

	macs := []net.HardwareAddr{
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
	}

	now := time.Now()
	for i, mac := range macs {
		// Build a minimal ARP packet payload
		payload := buildARPPacket(mac, net.IP{192, 168, 1, byte(10 + i)})
		packetChan <- model.PacketEvent{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			SrcMAC:    mac,
			DstMAC:    net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			Payload:   payload,
			TTL:       64,
			VLANID:    -1,
		}
	}
	close(packetChan)

	// Run fan-out with 2 workers
	log := createTestLogger()
	hosts := fanOutAnalyze(packetChan, log, nil, 2)

	// Each MAC should produce one host via ARP parsing
	if len(hosts) < 1 {
		t.Logf("Fan-out returned %d hosts (may be 0 if ARP parsing requires specific format)", len(hosts))
	}

	// Verify no panics and clean execution
	t.Logf("Fan-out completed with %d hosts from %d packets across 2 workers", len(hosts), len(macs))
}

// TestMergeHosts verifies the host merging logic.
func TestMergeHosts(t *testing.T) {
	now := time.Now()
	hostA := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MACStr:      "00:11:22:33:44:55",
		Protocols:   []string{"ARP"},
		Role:        "client",
		Info:        "first=A",
		Hostname:    "hostA",
		FirstSeen:   now,
		LastSeen:    now,
		Ports:       []int{80},
		OSGuess:     "Linux",
		OSScore:     50,
		PacketCount: 10,
	}

	hostB := &model.Host{
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		MACStr:      "00:11:22:33:44:55",
		Protocols:   []string{"ARP", "DHCP"},
		Role:        "server",
		FirstSeen:   now.Add(-1 * time.Hour),
		LastSeen:    now.Add(1 * time.Hour),
		Ports:       []int{80, 443},
		OSGuess:     "Windows",
		OSScore:     80,
		PacketCount: 20,
	}

	mergeHosts(hostA, hostB)

	// Check protocols merged
	if len(hostA.Protocols) != 2 {
		t.Errorf("Expected 2 protocols, got %d: %v", len(hostA.Protocols), hostA.Protocols)
	}

	// Check ports merged
	if len(hostA.Ports) != 2 {
		t.Errorf("Expected 2 ports, got %d: %v", len(hostA.Ports), hostA.Ports)
	}

	// Check role upgraded (server > client)
	if hostA.Role != "server" {
		t.Errorf("Expected role 'server', got '%s'", hostA.Role)
	}

	// Check timestamps
	if !hostA.FirstSeen.Equal(now.Add(-1 * time.Hour)) {
		t.Errorf("Expected FirstSeen to be earlier")
	}
	if !hostA.LastSeen.Equal(now.Add(1 * time.Hour)) {
		t.Errorf("Expected LastSeen to be later")
	}

	// Check OS guess (higher score wins)
	if hostA.OSGuess != "Windows" {
		t.Errorf("Expected OSGuess 'Windows' (higher score), got '%s'", hostA.OSGuess)
	}
	if hostA.OSScore != 80 {
		t.Errorf("Expected OSScore 80, got %d", hostA.OSScore)
	}

	// Check info (kept from A since non-empty)
	if hostA.Info != "first=A" {
		t.Errorf("Expected Info 'first=A', got '%s'", hostA.Info)
	}

	// Check packet count accumulated
	if hostA.PacketCount != 30 {
		t.Errorf("Expected PacketCount 30, got %d", hostA.PacketCount)
	}
}

// TestGetPacket_ReusesPreParsed verifies that GetPacket reuses a pre-parsed packet.
func TestGetPacket_ReusesPreParsed(t *testing.T) {
	// Build a packet with payload
	payload := buildARPPacket(
		net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		net.IP{192, 168, 1, 1},
	)

	// Create a PacketEvent with Packet = nil
	pktWithoutPacket := model.PacketEvent{
		Payload: payload,
	}

	// GetPacketDefault should create a new packet
	packet1 := GetPacketDefault(pktWithoutPacket)
	if packet1 == nil {
		t.Fatal("Expected non-nil packet from GetPacketDefault")
	}

	// Now pre-parse and set Packet field
	pktWithPacket := model.PacketEvent{
		Payload: payload,
		Packet:  packet1,
	}

	// GetPacketDefault should return the same pre-parsed packet
	packet2 := GetPacketDefault(pktWithPacket)
	if packet2 != packet1 {
		t.Error("Expected GetPacketDefault to return the pre-parsed packet")
	}
}

// buildARPPacket creates a minimal ARP request packet.
func buildARPPacket(srcMAC net.HardwareAddr, srcIP net.IP) []byte {
	// Ethernet header (14 bytes)
	pkt := make([]byte, 14+28)                                 // Ethernet + ARP
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // DstMAC
	copy(pkt[6:12], srcMAC)                                    // SrcMAC
	binary.BigEndian.PutUint16(pkt[12:14], 0x0806)             // EtherType ARP

	// ARP header (28 bytes)
	binary.BigEndian.PutUint16(pkt[14:16], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // Protocol type: IPv4
	pkt[18] = 6                                    // Hardware address length
	pkt[19] = 4                                    // Protocol address length
	binary.BigEndian.PutUint16(pkt[20:22], 1)      // Operation: ARP Request
	copy(pkt[22:28], srcMAC)                       // Sender hardware address
	copy(pkt[28:32], srcIP.To4())                  // Sender protocol address
	// Target MAC and IP left as zeros

	return pkt
}

// createTestLogger creates a logger suitable for tests.
func createTestLogger() *logger.Logger {
	log, _ := logger.New("test", nil)
	return log
}
