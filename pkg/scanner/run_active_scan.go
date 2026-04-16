// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package scanner coordinates the active scanning pipeline.
package scanner

import (
	"context"
	"net"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
)

// RunActiveScan runs both ARP and SYN scanning and merges results.
func RunActiveScan(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host {
	if cfg.Mode.PcapFile != "" {
		log.Error().Msg("Active scan requested while in PCAP mode — this is not allowed.")
		return []*model.Host{}
	}
	log.Info().Msg("→ RunActiveScan() invoked")
	if cfg.Logging.Paranoid {
		var err error
		log, err = logger.New("", cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create paranoid logger")
		}
	}

	arpResults := ScanARP(ctx, cfg, log)

	if cfg.Mode.SYN {
		synResults := ScanSYNFromActive(ctx, cfg, log, arpResults)
		return mergeHostData(arpResults, synResults)
	}

	return arpResults
}

// RunActiveScanWithTargets runs ARP scanning with targeted mode and fallback logic.
// If targeted mode is enabled, it scans only the provided targets from passive phase.
// If no targets are provided, it falls back to scanning the entire /24 subnet.
func RunActiveScanWithTargets(ctx context.Context, cfg *config.Config, log *logger.Logger, passiveHosts []*model.Host) []*model.Host {
	if cfg.Mode.PcapFile != "" {
		log.Error().Msg("Active scan requested while in PCAP mode — this is not allowed.")
		return []*model.Host{}
	}
	log.Info().Msg("→ RunActiveScanWithTargets() invoked")
	if cfg.Logging.Paranoid {
		var err error
		log, err = logger.New("", cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create paranoid logger")
		}
	}

	var arpResults []*model.Host

	if cfg.Scan.Targeted {
		// Targeted mode: extract IPs from passive hosts
		targets := extractIPsFromHosts(passiveHosts)

		// Filter blacklisted targets
		filteredTargets := filterBlacklistedIPs(targets, cfg.Scan.Blacklist)
		if len(targets) != len(filteredTargets) {
			log.Info().Int("original", len(targets)).Int("filtered", len(filteredTargets)).Msg("→ Filtered blacklisted targets from passive phase")
		}

		if len(filteredTargets) > 0 {
			log.Info().Int("targets", len(filteredTargets)).Msg("→ Targeted ARP scan: N targets from passive phase")
			arpResults = ScanARPWithTargets(ctx, cfg, log, filteredTargets)
		} else {
			log.Info().Msg("→ Targeted ARP scan: no valid targets found after filtering, falling back to full /24 scan")
			arpResults = ScanARP(ctx, cfg, log)
		}
	} else {
		// Mode normal : scanner tout le /24
		log.Info().Msg("→ Standard ARP scan: scanning full /24 subnet")
		arpResults = ScanARP(ctx, cfg, log)
	}

	if cfg.Mode.SYN {
		synResults := ScanSYNFromActive(ctx, cfg, log, arpResults)
		return mergeHostData(arpResults, synResults)
	}

	return arpResults
}

// extractIPsFromHosts extracts unique IP addresses from a list of hosts.
func extractIPsFromHosts(hosts []*model.Host) []net.IP {
	seen := make(map[string]bool)
	var ips []net.IP

	for _, host := range hosts {
		if host.IP != nil {
			ipStr := host.IP.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				ips = append(ips, host.IP)
			}
		}
	}

	return ips
}

// filterBlacklistedIPs removes blacklisted IPs from the target list.
func filterBlacklistedIPs(ips []net.IP, blacklist []string) []net.IP {
	var filtered []net.IP
	for _, ip := range ips {
		if !IsBlacklisted(ip, blacklist) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

// mergeHostData combines active and passive scan results by host identity.
func mergeHostData(base, enriched []*model.Host) []*model.Host {
	hostMap := make(map[string]*model.Host)

	for _, h := range base {
		key := h.IP.String() + "-" + h.MAC.String()
		hostMap[key] = h
	}

	for _, h := range enriched {
		key := h.IP.String() + "-" + h.MAC.String()
		if existing, ok := hostMap[key]; ok {
			// Merge ports without overwriting
			for _, port := range h.Ports {
				existing.AddPort(port)
			}

			if h.OSGuess != "" {
				existing.OSGuess = h.OSGuess
			}

			if h.Source != "" {
				existing.Source = h.Source
			}

			if h.TTL != 0 {
				existing.TTL = h.TTL
			}

		} else {
			hostMap[key] = h
		}
	}

	merged := make([]*model.Host, 0, len(hostMap))
	for _, h := range hostMap {
		merged = append(merged, h)
	}

	return merged
}
