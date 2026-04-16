// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides TCP options consolidation for reliable OS fingerprinting.
// This module groups SYN packets by 5-tuple and consolidates TCP options to avoid
// unrealistic repeated MSS/options and capture a reliable first-SYN view.
package analyzer

import (
	"fmt"
	"net"
	"sync"
	"time"

	"zandoli/pkg/model"
)

// FiveTuple represents a network flow identifier for SYN packet grouping
type FiveTuple struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
	Proto   uint8
}

// String returns a string representation of the FiveTuple for use as map key
func (ft FiveTuple) String() string {
	return ft.SrcIP.String() + ":" + string(rune(ft.SrcPort)) + "->" +
		ft.DstIP.String() + ":" + string(rune(ft.DstPort)) + "/" + string(rune(ft.Proto))
}

// SYNRecord represents a single SYN packet observation
type SYNRecord struct {
	Timestamp  time.Time
	TTL        int
	WindowSize int
	TCPOptions *model.TCPOptions
	Order      []string
}

// TCPConsolidator manages SYN packet grouping and TCP options consolidation
type TCPConsolidator struct {
	mu         sync.RWMutex
	flows      map[string][]SYNRecord
	maxSamples int
}

// NewTCPConsolidator creates a new TCP consolidator instance
func NewTCPConsolidator() *TCPConsolidator {
	return &TCPConsolidator{
		flows:      make(map[string][]SYNRecord),
		maxSamples: 10, // Keep only first 10 samples per flow
	}
}

// AddSYN adds a SYN packet observation to the consolidator
func (tc *TCPConsolidator) AddSYN(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16,
	proto uint8, ttl int, windowSize int, tcpOptions *model.TCPOptions, order []string) {

	// Create a string key for the flow
	key := fmt.Sprintf("%s:%d->%s:%d/%d", srcIP.String(), srcPort, dstIP.String(), dstPort, proto)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Keep only the first observed SYN per flow to build order
	if len(tc.flows[key]) == 0 {
		record := SYNRecord{
			Timestamp:  time.Now(),
			TTL:        ttl,
			WindowSize: windowSize,
			TCPOptions: tcpOptions,
			Order:      order,
		}
		tc.flows[key] = []SYNRecord{record}
	} else {
		// Add additional samples for MSS/wscale analysis (up to maxSamples)
		if len(tc.flows[key]) < tc.maxSamples {
			record := SYNRecord{
				Timestamp:  time.Now(),
				TTL:        ttl,
				WindowSize: windowSize,
				TCPOptions: tcpOptions,
				Order:      order,
			}
			tc.flows[key] = append(tc.flows[key], record)
		}
	}
}

// ConsolidateTCPOptions consolidates TCP options for a given flow
func (tc *TCPConsolidator) ConsolidateTCPOptions(key string) *model.TCPOptions {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	records, exists := tc.flows[key]
	if !exists || len(records) == 0 {
		return nil
	}

	// Use the first SYN for order and basic structure
	firstRecord := records[0]
	consolidated := &model.TCPOptions{
		Order: make([]string, 0, len(firstRecord.Order)),
	}

	// Copy the order from first SYN (most reliable) but limit to realistic length
	realisticOrder := limitOrderLength(firstRecord.Order, 6)
	consolidated.Order = append(consolidated.Order, realisticOrder...)

	// Collect MSS and WScale samples
	var mssSamples []int
	var wscaleSamples []int

	for _, record := range records {
		if record.TCPOptions != nil {
			if record.TCPOptions.MSS > 0 {
				mssSamples = append(mssSamples, record.TCPOptions.MSS)
			}
			if record.TCPOptions.WSCALE > 0 {
				wscaleSamples = append(wscaleSamples, record.TCPOptions.WSCALE)
			}
		}
	}

	// Compute mode for MSS and WScale
	consolidated.MSS = computeMode(mssSamples)
	consolidated.WSCALE = computeMode(wscaleSamples)

	// Store samples (keep small arrays)
	consolidated.MSSSamples = limitSamples(mssSamples, 5)
	consolidated.WScaleSamples = limitSamples(wscaleSamples, 5)

	// Booleans: set true if seen at least once
	for _, record := range records {
		if record.TCPOptions != nil {
			if record.TCPOptions.SACKPermitted {
				consolidated.SACKPermitted = true
			}
			if record.TCPOptions.Timestamp {
				consolidated.Timestamp = true
			}
		}
	}

	// Compute TCP fingerprinting confidence
	consolidated.TCPFPConfidence = computeTCPFPConfidence(len(records), mssSamples, wscaleSamples, consolidated)

	return consolidated
}

// computeMode calculates the mode (most frequent value) from a slice of integers
func computeMode(values []int) int {
	if len(values) == 0 {
		return 0
	}

	// Count frequency of each value
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}

	// Find the most frequent value
	maxFreq := 0
	mode := values[0] // Default to first value
	for value, count := range freq {
		if count > maxFreq {
			maxFreq = count
			mode = value
		}
	}

	return mode
}

// limitSamples limits the number of samples to keep arrays small
func limitSamples(samples []int, max int) []int {
	if len(samples) <= max {
		return samples
	}
	return samples[:max]
}

// limitOrderLength limits the order length to realistic values
func limitOrderLength(order []string, maxLength int) []string {
	if len(order) <= maxLength {
		return order
	}

	// Keep the most important options first, avoiding duplicates
	importantOptions := []string{"MSS", "WSCALE", "SACK_PERMITTED", "TIMESTAMP"}
	var result []string
	added := make(map[string]bool)

	// Add important options first
	for _, opt := range importantOptions {
		if len(result) >= maxLength {
			break
		}
		for _, orderOpt := range order {
			if orderOpt == opt && !added[opt] {
				result = append(result, opt)
				added[opt] = true
				break
			}
		}
	}

	// Add remaining options if space allows, but avoid duplicates
	for _, opt := range order {
		if len(result) >= maxLength {
			break
		}
		if !added[opt] {
			result = append(result, opt)
			added[opt] = true
		}
	}

	return result
}

// computeTCPFPConfidence calculates TCP fingerprinting confidence based on sample count and consistency
func computeTCPFPConfidence(sampleCount int, mssSamples, wscaleSamples []int, consolidated *model.TCPOptions) int {
	confidence := 0

	// Base confidence from sample count (0-40 points)
	switch {
	case sampleCount >= 5:
		confidence += 40
	case sampleCount >= 3:
		confidence += 30
	case sampleCount >= 2:
		confidence += 20
	case sampleCount >= 1:
		confidence += 10
	}

	// MSS consistency bonus (0-30 points)
	if len(mssSamples) > 0 {
		mssConsistency := calculateConsistency(mssSamples)
		confidence += int(mssConsistency * 30)
	}

	// WScale consistency bonus (0-20 points)
	if len(wscaleSamples) > 0 {
		wscaleConsistency := calculateConsistency(wscaleSamples)
		confidence += int(wscaleConsistency * 20)
	}

	// Order length penalty for unrealistic sequences (0-10 points)
	orderLength := len(consolidated.Order)
	if orderLength <= 6 {
		confidence += 10 // Realistic sequence length
	} else if orderLength <= 10 {
		confidence += 5 // Acceptable length
	}
	// No bonus for very long sequences (unrealistic)

	// Cap at 100
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// calculateConsistency calculates how consistent a set of values is (0.0 to 1.0)
func calculateConsistency(values []int) float64 {
	if len(values) <= 1 {
		return 1.0
	}

	// Count frequency of each value
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}

	// Find the most frequent value and its count
	maxCount := 0
	for _, count := range freq {
		if count > maxCount {
			maxCount = count
		}
	}

	// Consistency is the ratio of most frequent value to total samples
	return float64(maxCount) / float64(len(values))
}

// GetConsolidatedOptionsForHost returns consolidated TCP options for a host based on all its flows
func (tc *TCPConsolidator) GetConsolidatedOptionsForHost(hostIP net.IP) *model.TCPOptions {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	var allMSSSamples []int
	var allWScaleSamples []int
	var hasSACKPermitted bool
	var hasTimestamp bool
	var bestOrder []string
	var bestConfidence int

	// Collect data from all flows involving this host
	for _, records := range tc.flows {
		// Use the first record for order and basic structure
		if len(records) > 0 && len(bestOrder) == 0 {
			bestOrder = records[0].Order
		}

		// Collect samples from all records
		for _, record := range records {
			if record.TCPOptions != nil {
				if record.TCPOptions.MSS > 0 {
					allMSSSamples = append(allMSSSamples, record.TCPOptions.MSS)
				}
				if record.TCPOptions.WSCALE > 0 {
					allWScaleSamples = append(allWScaleSamples, record.TCPOptions.WSCALE)
				}
				if record.TCPOptions.SACKPermitted {
					hasSACKPermitted = true
				}
				if record.TCPOptions.Timestamp {
					hasTimestamp = true
				}
			}
		}
	}

	if len(allMSSSamples) == 0 && len(allWScaleSamples) == 0 {
		return nil
	}

	// Create consolidated options
	consolidated := &model.TCPOptions{
		MSS:             computeMode(allMSSSamples),
		WSCALE:          computeMode(allWScaleSamples),
		SACKPermitted:   hasSACKPermitted,
		Timestamp:       hasTimestamp,
		Order:           bestOrder,
		MSSSamples:      limitSamples(allMSSSamples, 5),
		WScaleSamples:   limitSamples(allWScaleSamples, 5),
		TCPFPConfidence: bestConfidence,
	}

	// Calculate final confidence
	consolidated.TCPFPConfidence = computeTCPFPConfidence(
		len(allMSSSamples)+len(allWScaleSamples),
		allMSSSamples,
		allWScaleSamples,
		consolidated,
	)

	return consolidated
}

// Cleanup removes old flows to prevent memory growth
func (tc *TCPConsolidator) Cleanup(maxAge time.Duration) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for tuple, records := range tc.flows {
		// Keep only recent records
		var recentRecords []SYNRecord
		for _, record := range records {
			if record.Timestamp.After(cutoff) {
				recentRecords = append(recentRecords, record)
			}
		}

		if len(recentRecords) == 0 {
			delete(tc.flows, tuple)
		} else {
			tc.flows[tuple] = recentRecords
		}
	}
}

// GetFlowCount returns the number of active flows
func (tc *TCPConsolidator) GetFlowCount() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.flows)
}

// Public functions for external access to the global consolidator

// AddSYNToConsolidator adds a SYN packet to the global consolidator
func AddSYNToConsolidator(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16,
	proto uint8, ttl int, windowSize int, tcpOptions *model.TCPOptions, order []string) {
	tcpConsolidator.AddSYN(srcIP, srcPort, dstIP, dstPort, proto, ttl, windowSize, tcpOptions, order)
}

// GetConsolidatedTCPOptions returns consolidated TCP options for a host
func GetConsolidatedTCPOptions(hostIP net.IP) *model.TCPOptions {
	return tcpConsolidator.GetConsolidatedOptionsForHost(hostIP)
}

// CleanupTCPConsolidator cleans up old flows
func CleanupTCPConsolidator(maxAge time.Duration) {
	tcpConsolidator.Cleanup(maxAge)
}

// GetTCPConsolidatorFlowCount returns the number of active flows
func GetTCPConsolidatorFlowCount() int {
	return tcpConsolidator.GetFlowCount()
}
