// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package sniffer provides packet sniffing capabilities with traffic statistics.
package sniffer

import (
	"net"
	"sync"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// TrafficStats maintains thread-safe traffic statistics per host
type TrafficStats struct {
	mu        sync.RWMutex
	hostStats map[string]*HostStats
	log       *logger.Logger
}

// HostStats contains traffic statistics for a single host
type HostStats struct {
	PacketCount uint64
	ByteCount   uint64
}

// NewTrafficStats creates a new TrafficStats instance
func NewTrafficStats(log *logger.Logger) *TrafficStats {
	return &TrafficStats{
		hostStats: make(map[string]*HostStats),
		log:       log,
	}
}

// GetHostKey generates a unique key for a host based on MAC and IP
func GetHostKey(mac net.HardwareAddr, ip net.IP) string {
	if len(mac) > 0 {
		return mac.String()
	}
	if len(ip) > 0 {
		return ip.String()
	}
	return ""
}

// RecordPacket records traffic statistics for a host
// Increments packet count by 1 and byte count by the packet size
func (ts *TrafficStats) RecordPacket(mac net.HardwareAddr, ip net.IP, packetSize int) {
	if packetSize < 0 {
		return
	}

	key := GetHostKey(mac, ip)
	if key == "" {
		return
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	stats, exists := ts.hostStats[key]
	if !exists {
		stats = &HostStats{}
		ts.hostStats[key] = stats
	}

	stats.PacketCount++
	stats.ByteCount += uint64(packetSize)
}

// GetStats returns traffic statistics for a specific host
func (ts *TrafficStats) GetStats(mac net.HardwareAddr, ip net.IP) (uint64, uint64) {
	key := GetHostKey(mac, ip)
	if key == "" {
		return 0, 0
	}

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	stats, exists := ts.hostStats[key]
	if !exists {
		return 0, 0
	}

	return stats.PacketCount, stats.ByteCount
}

// GetAllStats returns a copy of all host statistics
func (ts *TrafficStats) GetAllStats() map[string]*HostStats {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make(map[string]*HostStats)
	for key, stats := range ts.hostStats {
		result[key] = &HostStats{
			PacketCount: stats.PacketCount,
			ByteCount:   stats.ByteCount,
		}
	}

	return result
}

// UpdateHostWithStats updates a Host struct with its traffic statistics
func (ts *TrafficStats) UpdateHostWithStats(host *model.Host) {
	packetCount, byteCount := ts.GetStats(host.MAC, host.IP)
	host.PacketCount = packetCount
	host.ByteCount = byteCount
}

// GetTotalStats returns aggregate statistics across all hosts
func (ts *TrafficStats) GetTotalStats() (totalPackets, totalBytes uint64, hostCount int) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, stats := range ts.hostStats {
		totalPackets += stats.PacketCount
		totalBytes += stats.ByteCount
	}

	return totalPackets, totalBytes, len(ts.hostStats)
}

// Clear removes all statistics (useful for testing or reset)
func (ts *TrafficStats) Clear() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.hostStats = make(map[string]*HostStats)
}

// LogStats logs current traffic statistics
func (ts *TrafficStats) LogStats() {
	totalPackets, totalBytes, hostCount := ts.GetTotalStats()

	ts.log.Info().
		Uint64("total_packets", totalPackets).
		Uint64("total_bytes", totalBytes).
		Int("tracked_hosts", hostCount).
		Msg("Traffic statistics summary")
}
