// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// IPSet represents a set of IPs with their counter
type IPSet struct {
	Count int      `json:"count"`
	IPs   []string `json:"ips"`
}

// ExportIPSets generates the private_ips.json and public_ips.json files
func ExportIPSets(hosts []*model.Host, outputDir string, log *logger.Logger) error {
	privSet := make(map[string]struct{})
	pubSet := make(map[string]struct{})

	for _, h := range hosts {
		// Traiter l'IP principale IPv4
		if h.IP != nil && h.IP.To4() != nil {
			ipStr := h.IP.String()
			if utils.IsPrivateIPv4(h.IP) {
				privSet[ipStr] = struct{}{}
			} else {
				// Exclure loopback, multicast, etc.
				if !h.IP.IsLoopback() && !h.IP.IsMulticast() && !h.IP.IsUnspecified() {
					pubSet[ipStr] = struct{}{}
				}
			}
		}

		// Process all observed IPs
		for _, ip := range h.IPs {
			if ip == nil || ip.To4() == nil {
				continue // ignorer les non-IPv4
			}
			ipStr := ip.String()
			if utils.IsPrivateIPv4(ip) {
				privSet[ipStr] = struct{}{}
			} else {
				// Exclure loopback, multicast, etc.
				if !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified() {
					pubSet[ipStr] = struct{}{}
				}
			}
		}
	}

	toSortedSlice := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	priv := IPSet{Count: len(privSet), IPs: toSortedSlice(privSet)}
	pub := IPSet{Count: len(pubSet), IPs: toSortedSlice(pubSet)}

	if err := writeJSON(filepath.Join(outputDir, "private_ips.json"), priv); err != nil {
		return fmt.Errorf("write private_ips.json: %w", err)
	}
	if err := writeJSON(filepath.Join(outputDir, "public_ips.json"), pub); err != nil {
		return fmt.Errorf("write public_ips.json: %w", err)
	}

	log.Info().
		Int("private_count", priv.Count).
		Int("public_count", pub.Count).
		Msg("Exported private_ips.json and public_ips.json")
	return nil
}

// writeJSON writes a structure as indented JSON
func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
