// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package exporter handles structured export of discovered Hosts to Markdown.
package exporter

import (
	"fmt"
	"os"
	"strings"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// ExportMarkdown exports the hosts as a Markdown report.
func ExportMarkdown(hosts []*model.Host, subnets []model.Subnet, mdFile string, log *logger.Logger) error {
	filtered := make([]*model.Host, 0, len(hosts))
	anomalySet := map[string]struct{}{}

	for _, h := range hosts {
		// Include hosts with IP or MAC (L2 hosts)
		hasIP := len(h.IP) > 0
		hasMAC := h.MACStr != ""

		if !hasIP && !hasMAC {
			continue
		}

		// Validation des timestamps comme dans JSON exporter
		if !utils.IsSafeTime(h.FirstSeen) || !utils.IsSafeTime(h.LastSeen) {
			continue
		}

		filtered = append(filtered, h)
		for _, a := range h.Anomalies {
			anomalyKey := a.Description + " (" + a.Severity + ")"
			anomalySet[anomalyKey] = struct{}{}
		}
	}

	uniqueAnomalies := make([]string, 0, len(anomalySet))
	for a := range anomalySet {
		uniqueAnomalies = append(uniqueAnomalies, a)
	}

	f, err := os.Create(mdFile)
	if err != nil {
		log.Error().Err(err).Str("file", mdFile).Msg("Failed to create Markdown report file")
		return err
	}
	defer f.Close()

	// Write the header
	fmt.Fprintf(f, "# Rapport de Reconnaissance Réseau - Zandoli\n\n")
	fmt.Fprintf(f, "**Date de génération :** %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "**Version :** v0.94\n\n")

	// Filter subnets to keep only /24
	filteredSubnets := utils.FilterSubnets24(subnets)

	// Summary
	fmt.Fprintf(f, "## 📊 Résumé\n\n")
	fmt.Fprintf(f, "- **Total des hôtes :** %d\n", len(filtered))
	fmt.Fprintf(f, "- **Sous-réseaux détectés :** %d\n", len(filteredSubnets))
	fmt.Fprintf(f, "- **Anomalies détectées :** %d\n", len(uniqueAnomalies))
	fmt.Fprintf(f, "- **Mode de scan :** PCAP (analyse offline)\n\n")

	// Statistics by category
	categories := make(map[string]int)
	vendors := make(map[string]int)
	roles := make(map[string]int)
	for _, h := range filtered {
		if h.Category != "" {
			categories[h.Category]++
		}
		if h.Vendor != "" && h.Vendor != "Unknown" {
			vendors[h.Vendor]++
		}
		if h.Role != "" {
			roles[h.Role]++
		}
	}

	if len(categories) > 0 {
		fmt.Fprintf(f, "### Catégories d'équipements\n\n")
		for category, count := range categories {
			fmt.Fprintf(f, "- **%s :** %d\n", category, count)
		}
		fmt.Fprintf(f, "\n")
	}

	if len(vendors) > 0 {
		fmt.Fprintf(f, "### Top 10 Constructeurs\n\n")
		count := 0
		for vendor, vendorCount := range vendors {
			if count >= 10 {
				break
			}
			fmt.Fprintf(f, "- **%s :** %d\n", vendor, vendorCount)
			count++
		}
		fmt.Fprintf(f, "\n")
	}

	if len(roles) > 0 {
		fmt.Fprintf(f, "### Rôles détectés\n\n")
		for role, count := range roles {
			fmt.Fprintf(f, "- **%s :** %d\n", role, count)
		}
		fmt.Fprintf(f, "\n")
	}

	// Discovered hosts
	fmt.Fprintf(f, "## 🖥️ Hôtes Découverts\n\n")
	fmt.Fprintf(f, "| IP | MAC | Constructeur | Rôle | Catégorie | OS | Ports | VLANs | Protocoles | Anomalies |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|---|---|---|---|---|\n")

	for _, h := range filtered {
		ipStr := ""
		if h.IP != nil {
			ipStr = h.IP.String()
		}

		portsStr := ""
		if len(h.Ports) > 0 {
			portStrs := make([]string, len(h.Ports))
			for i, port := range h.Ports {
				portStrs[i] = fmt.Sprintf("%d", port)
			}
			portsStr = strings.Join(portStrs, ", ")
		}

		vlansStr := ""
		if len(h.VLANs) > 0 {
			vlanStrs := make([]string, len(h.VLANs))
			for i, vlan := range h.VLANs {
				vlanStrs[i] = fmt.Sprintf("%d", vlan)
			}
			vlansStr = strings.Join(vlanStrs, ", ")
		}

		// Convert anomalies to string with severity
		anomaliesStr := ""
		if len(h.Anomalies) > 0 {
			anomalyStrs := make([]string, len(h.Anomalies))
			for i, anomaly := range h.Anomalies {
				anomalyStrs[i] = fmt.Sprintf("%s (%s)", anomaly.Description, anomaly.Severity)
			}
			anomaliesStr = strings.Join(anomalyStrs, ", ")
		} else {
			anomaliesStr = "-"
		}

		fmt.Fprintf(f, "| %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			ipStr,
			h.MACStr,
			h.Vendor,
			h.Role,
			h.Category,
			h.OSGuess,
			portsStr,
			vlansStr,
			strings.Join(h.Protocols, ", "),
			anomaliesStr,
		)
	}

	// Subnets
	fmt.Fprintf(f, "\n## 🌐 Sous-réseaux Détectés\n\n")
	fmt.Fprintf(f, "| CIDR | Source | Hôtes |\n")
	fmt.Fprintf(f, "|---|---|---|\n")

	for _, s := range filteredSubnets {
		hostsStr := strings.Join(s.Hosts, ", ")
		if hostsStr == "" {
			hostsStr = "-"
		}
		fmt.Fprintf(f, "| `%s` | %s | %s |\n", s.CIDR, s.Source, hostsStr)
	}

	// Anomalies
	if len(uniqueAnomalies) > 0 {
		fmt.Fprintf(f, "\n## ⚠️ Anomalies Détectées\n\n")
		for _, anomaly := range uniqueAnomalies {
			fmt.Fprintf(f, "- %s\n", anomaly)
		}
	}

	// Host details
	fmt.Fprintf(f, "\n## 🔍 Détails des Hôtes\n\n")
	for i, h := range filtered {
		fmt.Fprintf(f, "### Hôte %d\n\n", i+1)

		if h.IP != nil {
			fmt.Fprintf(f, "- **IP :** %s\n", h.IP.String())
		}
		fmt.Fprintf(f, "- **MAC :** `%s`\n", h.MACStr)
		if h.Vendor != "" {
			fmt.Fprintf(f, "- **Constructeur :** %s\n", h.Vendor)
		}
		if h.Role != "" {
			fmt.Fprintf(f, "- **Rôle :** %s\n", h.Role)
		}
		if h.Category != "" {
			fmt.Fprintf(f, "- **Catégorie :** %s\n", h.Category)
		}
		if h.Hostname != "" {
			fmt.Fprintf(f, "- **Nom d'hôte :** %s\n", h.Hostname)
		}
		if h.OSGuess != "" {
			fmt.Fprintf(f, "- **OS détecté :** %s\n", h.OSGuess)
		}
		if len(h.Protocols) > 0 {
			fmt.Fprintf(f, "- **Protocoles :** %s\n", strings.Join(h.Protocols, ", "))
		}
		if len(h.Ports) > 0 {
			portStrs := make([]string, len(h.Ports))
			for i, port := range h.Ports {
				portStrs[i] = fmt.Sprintf("%d", port)
			}
			fmt.Fprintf(f, "- **Ports :** %s\n", strings.Join(portStrs, ", "))
		}
		if len(h.VLANs) > 0 {
			vlanStrs := make([]string, len(h.VLANs))
			for i, vlan := range h.VLANs {
				vlanStrs[i] = fmt.Sprintf("%d", vlan)
			}
			fmt.Fprintf(f, "- **VLANs :** %s\n", strings.Join(vlanStrs, ", "))
		}
		if h.Info != "" {
			fmt.Fprintf(f, "- **Informations :** %s\n", h.Info)
		}
		fmt.Fprintf(f, "- **Première détection :** %s\n", h.FirstSeen.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(f, "- **Dernière détection :** %s\n", h.LastSeen.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(f, "- **Source :** %s\n", h.Source)
		if len(h.Anomalies) > 0 {
			anomalyStrs := make([]string, len(h.Anomalies))
			for i, anomaly := range h.Anomalies {
				anomalyStrs[i] = fmt.Sprintf("%s (%s)", anomaly.Description, anomaly.Severity)
			}
			fmt.Fprintf(f, "- **Anomalies :** %s\n", strings.Join(anomalyStrs, ", "))
		}
		fmt.Fprintf(f, "\n")
	}

	// Pied de page
	fmt.Fprintf(f, "---\n\n")
	fmt.Fprintf(f, "*Rapport généré par Zandoli v0.94 le %s*\n", time.Now().Format("2006-01-02 15:04:05"))

	log.Info().Str("file", mdFile).Msg("Markdown export complete")
	return nil
}
