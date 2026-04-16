// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ARPAnomalyDetector handles real-time ARP anomaly detection
type ARPAnomalyDetector struct {
	packetCounts map[string]int         // MAC -> packets per second count
	ipMacMap     map[string]string      // IP -> MAC (to detect conflicts)
	macIPMap     map[string][]string    // MAC -> IPs (to detect flaps)
	lastSeen     map[string]time.Time   // MAC -> last seen time
	timeWindows  map[string][]time.Time // MAC -> time windows for rate limiting
}

// NewARPAnomalyDetector creates a new ARP anomaly detector
func NewARPAnomalyDetector() *ARPAnomalyDetector {
	return &ARPAnomalyDetector{
		packetCounts: make(map[string]int),
		ipMacMap:     make(map[string]string),
		macIPMap:     make(map[string][]string),
		lastSeen:     make(map[string]time.Time),
		timeWindows:  make(map[string][]time.Time),
	}
}

// Constants for ARP anomaly detection
//
// THRESHOLD CHOICES AND HOW TO ADJUST:
//
// HighRateThreshold (10 pps): Detects ARP storms. Conservative value to avoid false positives.
//   - Normal networks: 1-3 pps per host
//   - Busy networks: 5-8 pps per host
//   - To adjust: increase if too many false positives, decrease if missing storms
//
// IPMacConflictWindow (5s): Window to detect IP-MAC conflicts.
//   - Normal DHCP: 1-2 seconds between changes
//   - To adjust: increase if DHCP is slow, decrease for faster detection
//
// MacIPFlapWindow (10s): Window to detect MAC-IP flaps.
//   - Normal DHCP: 5-10 seconds between changes
//   - To adjust: increase if DHCP is very slow, decrease for faster detection
//
// GratuitousARPSpike (5 pps): Detects gratuitous ARP spikes.
//   - Normal: 0-1 gratuitous ARP per second
//   - To adjust: decrease if missing attacks, increase if too many false positives
//
// RateWindowSize (10s): Size of the rate calculation window.
//   - To adjust: increase for more stability, decrease for faster response
const (
	// Anomaly detection thresholds
	HighRateThreshold   = 10 // ARP packets per second
	IPMacConflictWindow = 5  // seconds to detect IP-MAC conflicts
	MacIPFlapWindow     = 10 // seconds to detect MAC-IP flaps
	GratuitousARPSpike  = 5  // gratuitous ARP per second
	RateWindowSize      = 10 // rate calculation window size
)

// ParseARPPacket analyses an ARP packet and extracts MAC↔IP information
// for all ARP packet types (Request, Reply, Gratuitous ARP).
func ParseARPPacket(pkt model.PacketEvent) *ParsedRecord {
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)

	// Verify this is an ARP packet
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil
	}

	arp := arpLayer.(*layers.ARP)

	// Verify this is IPv4 (AddrType = Ethernet, Protocol = IPv4)
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return nil
	}

	// Accept all ARP types (Request=1, Reply=2)
	if arp.Operation != 1 && arp.Operation != 2 {
		return nil
	}

	// Extract source addresses
	sourceMAC := net.HardwareAddr(arp.SourceHwAddress)
	sourceIP := net.IP(arp.SourceProtAddress)

	// Verify that addresses are valid
	if len(sourceMAC) != 6 || sourceIP == nil || sourceIP.To4() == nil {
		return nil
	}

	// Extract source and destination IPs from the packet
	var ipSource, ipDest net.IP
	var l3Proto string

	// For ARP, the source IP comes from the ARP packet
	ipSource = sourceIP
	// The destination IP can be extracted from the ARP packet
	if arp.Operation == 1 { // ARP Request
		ipDest = net.IP(arp.DstProtAddress)
	} else if arp.Operation == 2 { // ARP Reply
		ipDest = net.IP(arp.DstProtAddress)
	}
	l3Proto = "IPv4" // ARP is IPv4 only

	// Create the record
	record := &ParsedRecord{
		MAC:       sourceMAC,
		IP:        sourceIP,
		Protocols: []string{"ARP"},
		Role:      "", // No specific role for passive ARP
		Info:      "",
		Anomalies: []string{},
		Ports:     []int{},
		TTL:       0,
		OnlyARP:   true, // Mark as OnlyARP since discovered only via ARP
		OSGuess:   "",
		TCPOpts:   []string{},
		OSScore:   0,
		Source:    "passive",
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
		Vendor:    "",
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  l3Proto,
		AppProto: "ARP",
		Strength: "high", // ARP = high strength
	}

	return record
}

// ParseARPPacketWithAnomalyDetection analyses an ARP packet with anomaly detection
func ParseARPPacketWithAnomalyDetection(pkt model.PacketEvent, detector *ARPAnomalyDetector) *ParsedRecord {
	record := ParseARPPacket(pkt)
	if record == nil {
		return nil
	}

	// Detect ARP anomalies
	anomalies := detector.DetectAnomalies(record, pkt.Timestamp)
	record.Anomalies = append(record.Anomalies, anomalies...)

	return record
}

// ParseARPPacketWithAnomalyDetectionAndType analyses an ARP packet with anomaly detection and ARP type
func ParseARPPacketWithAnomalyDetectionAndType(pkt model.PacketEvent, detector *ARPAnomalyDetector) *ParsedRecord {
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)

	// Verify this is an ARP packet
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil
	}

	arp := arpLayer.(*layers.ARP)

	// Verify this is IPv4 (AddrType = Ethernet, Protocol = IPv4)
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return nil
	}

	// Accept all ARP types (Request=1, Reply=2)
	if arp.Operation != 1 && arp.Operation != 2 {
		return nil
	}

	// Extract source addresses
	sourceMAC := net.HardwareAddr(arp.SourceHwAddress)
	sourceIP := net.IP(arp.SourceProtAddress)

	// Verify that addresses are valid
	if len(sourceMAC) != 6 || sourceIP == nil || sourceIP.To4() == nil {
		return nil
	}

	// Determine the ARP type
	arpType := "ARP Request"
	if arp.Operation == 2 {
		arpType = "ARP Reply"
	} else if arp.Operation == 1 {
		// Check if it is a Gratuitous ARP (sender IP = target IP)
		if net.IP(arp.SourceProtAddress).Equal(net.IP(arp.DstProtAddress)) {
			arpType = "Gratuitous ARP"
		}
	}

	// Extract source and destination IPs from the packet
	var ipSource, ipDest net.IP
	var l3Proto string

	// For ARP, the source IP comes from the ARP packet
	ipSource = sourceIP
	// The destination IP can be extracted from the ARP packet
	if arp.Operation == 1 { // ARP Request
		ipDest = net.IP(arp.DstProtAddress)
	} else if arp.Operation == 2 { // ARP Reply
		ipDest = net.IP(arp.DstProtAddress)
	}
	l3Proto = "IPv4" // ARP is IPv4 only

	// Create the record
	record := &ParsedRecord{
		MAC:       sourceMAC,
		IP:        sourceIP,
		Protocols: []string{"ARP"},
		Role:      "", // No specific role for passive ARP
		Info:      arpType,
		Anomalies: []string{},
		Ports:     []int{},
		TTL:       0,
		OnlyARP:   true, // Mark as OnlyARP since discovered only via ARP
		OSGuess:   "",
		TCPOpts:   []string{},
		OSScore:   0,
		Source:    "passive",
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
		Vendor:    "",
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  l3Proto,
		AppProto: "ARP",
		Strength: "high", // ARP = high strength
	}

	// Detect ARP anomalies
	anomalies := detector.DetectAnomalies(record, pkt.Timestamp)
	record.Anomalies = append(record.Anomalies, anomalies...)

	return record
}

// DetectAnomalies detects ARP anomalies for a given packet
func (d *ARPAnomalyDetector) DetectAnomalies(record *ParsedRecord, timestamp time.Time) []string {
	var anomalies []string
	macStr := record.MAC.String()
	ipStr := record.IP.String()

	// Update counters and time windows
	d.updateCounters(macStr, timestamp)

	// 1. Detect high_rate_per_src
	if d.detectHighRate(macStr, timestamp) {
		anomalies = append(anomalies, "high_rate_per_src")
	}

	// 2. Detect ip_mac_conflict
	if d.detectIPMacConflict(ipStr, macStr) {
		anomalies = append(anomalies, "ip_mac_conflict")
	}

	// 3. Detect mac_ip_flap
	if d.detectMacIPFlap(macStr, ipStr, timestamp) {
		anomalies = append(anomalies, "mac_ip_flap")
	}

	// 4. Detect gratuitous_arp_spike (if it is a gratuitous ARP)
	if d.detectGratuitousARPSpike(record, timestamp) {
		anomalies = append(anomalies, "gratuitous_arp_spike")
	}

	return anomalies
}

// updateCounters updates counters and time windows
func (d *ARPAnomalyDetector) updateCounters(macStr string, timestamp time.Time) {
	// Increment the packet counter
	d.packetCounts[macStr]++

	// Update last seen time
	d.lastSeen[macStr] = timestamp

	// Add to the time window
	d.timeWindows[macStr] = append(d.timeWindows[macStr], timestamp)

	// Clean old entries from the window (keep only the last 10 seconds)
	cutoff := timestamp.Add(-time.Duration(RateWindowSize) * time.Second)
	var validTimes []time.Time
	for _, t := range d.timeWindows[macStr] {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}
	d.timeWindows[macStr] = validTimes
}

// detectHighRate detects a high rate of ARP packets per second
func (d *ARPAnomalyDetector) detectHighRate(macStr string, timestamp time.Time) bool {
	times, exists := d.timeWindows[macStr]
	if !exists || len(times) < 2 {
		return false
	}

	// Count packets in the last second
	oneSecondAgo := timestamp.Add(-time.Second)
	count := 0
	for _, t := range times {
		if t.After(oneSecondAgo) {
			count++
		}
	}

	return count > HighRateThreshold
}

// detectIPMacConflict detects IP-MAC conflicts (same IP, different MACs)
func (d *ARPAnomalyDetector) detectIPMacConflict(ipStr, macStr string) bool {
	existingMAC, exists := d.ipMacMap[ipStr]
	if exists && existingMAC != macStr {
		return true
	}

	// Update the mapping
	d.ipMacMap[ipStr] = macStr
	return false
}

// detectMacIPFlap detects MAC-IP flaps (same MAC, different IPs)
func (d *ARPAnomalyDetector) detectMacIPFlap(macStr, ipStr string, timestamp time.Time) bool {
	ips, exists := d.macIPMap[macStr]
	if !exists {
		d.macIPMap[macStr] = []string{ipStr}
		return false
	}

	// Check if this IP is already known for this MAC
	for _, existingIP := range ips {
		if existingIP == ipStr {
			return false
		}
	}

	// New IP for this MAC - check if it is within the time window
	lastSeen, exists := d.lastSeen[macStr]
	if exists && timestamp.Sub(lastSeen) < time.Duration(MacIPFlapWindow)*time.Second {
		// This is a potential flap
		d.macIPMap[macStr] = append(ips, ipStr)
		return true
	}

	// Add the new IP
	d.macIPMap[macStr] = append(ips, ipStr)
	return false
}

// detectGratuitousARPSpike detects gratuitous ARP spikes
func (d *ARPAnomalyDetector) detectGratuitousARPSpike(record *ParsedRecord, timestamp time.Time) bool {
	// Check if it is a Gratuitous ARP based on the info
	if record.Info != "Gratuitous ARP" {
		return false
	}

	macStr := record.MAC.String()
	times, exists := d.timeWindows[macStr]
	if !exists || len(times) < 2 {
		return false
	}

	// Count Gratuitous ARP packets in the last second
	oneSecondAgo := timestamp.Add(-time.Second)
	count := 0
	for _, t := range times {
		if t.After(oneSecondAgo) {
			count++
		}
	}

	return count > GratuitousARPSpike
}

// CleanupOldData cleans old data to avoid memory leaks
func (d *ARPAnomalyDetector) CleanupOldData(cutoff time.Time) {
	// Clean time windows
	for macStr, times := range d.timeWindows {
		var validTimes []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				validTimes = append(validTimes, t)
			}
		}
		if len(validTimes) == 0 {
			delete(d.timeWindows, macStr)
			delete(d.packetCounts, macStr)
			delete(d.lastSeen, macStr)
		} else {
			d.timeWindows[macStr] = validTimes
		}
	}

	// Clean IP-MAC and MAC-IP mappings for removed MACs
	for ipStr, macStr := range d.ipMacMap {
		if _, exists := d.timeWindows[macStr]; !exists {
			delete(d.ipMacMap, ipStr)
		}
	}

	for macStr := range d.macIPMap {
		if _, exists := d.timeWindows[macStr]; !exists {
			delete(d.macIPMap, macStr)
		}
	}
}
