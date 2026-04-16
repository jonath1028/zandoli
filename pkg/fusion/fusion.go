// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package fusion

import (
	"strings"

	"zandoli/internal/logger"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// chooseBetterString returns the non-empty value or prefers longer string
func chooseBetterString(a, b string) string {
	if b != "" && (a == "" || len(b) > len(a)) {
		return b
	}
	return a
}

// mergeRole merges roles with priority (network > server > client)
func mergeRole(oldRole, newRole string) string {
	// D) Merge & tie-breaker (security)
	oldRole = analyzer.NormalizeRole(oldRole)
	newRole = analyzer.NormalizeRole(newRole)
	prio := map[string]int{"": 0, "client": 1, "server": 2, "reseau": 3}
	if prio[newRole] >= prio[oldRole] {
		return newRole
	}
	return oldRole
}

// mergeAnomalies merges and deduplicates two anomaly slices
func mergeAnomalies(a, b []model.Anomaly) []model.Anomaly {
	seen := make(map[string]struct{})
	result := []model.Anomaly{}
	for _, v := range a {
		key := v.Description + "|" + v.Severity
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, v)
		}
	}
	for _, v := range b {
		key := v.Description + "|" + v.Severity
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// MergeResults merges passive and active hosts based on IP + MAC deduplication.
func MergeResults(passive, active []*model.Host, log ...*logger.Logger) []*model.Host {
	mergedMap := make(map[string]*model.Host)

	addOrMerge := func(h *model.Host) {
		if h == nil || len(h.MACStr) == 0 {
			return
		}
		// Include hosts with IP or MAC (L2 hosts)
		hasIP := len(h.IP) > 0
		hasMAC := len(h.MACStr) > 0
		if !hasIP && !hasMAC {
			return
		}

		// Create a unique key based on MAC (and IP if available)
		key := h.MACStr
		if hasIP {
			key = h.IP.String() + "-" + h.MACStr
		}
		if existing, found := mergedMap[key]; found {
			if h.FirstSeen.IsZero() == false && (existing.FirstSeen.IsZero() || h.FirstSeen.Before(existing.FirstSeen)) {
				existing.FirstSeen = h.FirstSeen
			}
			if h.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = h.LastSeen
			}
			existing.OSGuess = chooseBetterString(existing.OSGuess, h.OSGuess)
			existing.Protocols = utils.MergeStrUnique(existing.Protocols, h.Protocols)
			existing.Ports = utils.MergeIntUnique(existing.Ports, h.Ports)
			existing.Anomalies = mergeAnomalies(existing.Anomalies, h.Anomalies)
			existing.Source = "combined"
			// Prioritize OnlyARP from active scan: if active.OnlyARP == true, keep true
			if h.OnlyARP {
				existing.OnlyARP = true
			} else {
				// Otherwise, recalculate OnlyARP after merging protocols
				existing.OnlyARP = calculateOnlyARP(existing.Protocols)
			}
			// Merge role with priority
			existing.Role = mergeRole(existing.Role, h.Role)
			// Merge host information
			existing.Info = mergeHostInfoString(existing.Info, h.Info)
			if h.TTL > 0 {
				existing.TTL = h.TTL
			}
			if h.TTLAvg > 0 {
				existing.TTLAvg = h.TTLAvg
			}
		} else {
			mergedMap[key] = h
		}
	}

	for _, h := range passive {
		addOrMerge(h)
	}
	for _, h := range active {
		addOrMerge(h)
	}

	merged := make([]*model.Host, 0, len(mergedMap))
	for _, h := range mergedMap {
		// OnlyARP is already calculated in addOrMerge, no need to recalculate here
		merged = append(merged, h)
	}

	if len(log) > 0 && log[0] != nil {
		log[0].Debug().Int("passive", len(passive)).Int("active", len(active)).Int("merged", len(merged)).Msg("[fusion] merge complete")
	}
	return merged
}

// mergeHostInfoString merges host information strings without overwriting existing services
func mergeHostInfoString(existing, new string) string {
	if existing == "" {
		return new
	}
	if new == "" {
		return existing
	}

	// Parse existing info into parts
	existingParts := utils.ParseInfoParts(existing)
	newParts := utils.ParseInfoParts(new)

	// Merge parts, avoiding duplicates
	mergedParts := make(map[string]string)

	// Add existing parts
	for key, value := range existingParts {
		mergedParts[key] = value
	}

	// Add new parts, but don't overwrite existing ones for certain keys
	for key, value := range newParts {
		if key == "hostname" {
			// Keep existing hostname, don't overwrite
			if _, exists := mergedParts[key]; !exists {
				mergedParts[key] = value
			}
		} else if key == "service" {
			// For services, we need to append multiple services
			if existingService, exists := mergedParts[key]; exists {
				// Check if this service is already listed
				if !utils.ContainsString(strings.Split(existingService, ","), value) {
					mergedParts[key] = existingService + "," + value
				}
			} else {
				mergedParts[key] = value
			}
		} else {
			// For other keys, don't overwrite existing values
			if _, exists := mergedParts[key]; !exists {
				mergedParts[key] = value
			}
		}
	}

	// Rebuild info string
	var parts []string
	for key, value := range mergedParts {
		parts = append(parts, key+"="+value)
	}

	return strings.Join(parts, "; ")
}

// calculateOnlyARP determines whether a host only has the ARP protocol
// Rule: onlyArp = (len(protocols) == 1 && protocols[0] == "ARP")
func calculateOnlyARP(protocols []string) bool {
	return len(protocols) == 1 && protocols[0] == "ARP"
}
