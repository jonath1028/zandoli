// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package exporter handles structured export of discovered Hosts to XML.
package exporter

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// XMLAnomaly represents an anomaly in XML format
type XMLAnomaly struct {
	XMLName     xml.Name `xml:"anomaly"`
	Description string   `xml:"description,attr"`
	Severity    string   `xml:"severity,attr"`
}

// XMLHost represents a host in XML format
type XMLHost struct {
	XMLName   xml.Name     `xml:"host"`
	IP        string       `xml:"ip,attr,omitempty"`
	MAC       string       `xml:"mac,attr"`
	Vendor    string       `xml:"vendor,attr,omitempty"`
	Role      string       `xml:"role,attr,omitempty"`
	Category  string       `xml:"category,attr,omitempty"`
	Hostname  string       `xml:"hostname,attr,omitempty"`
	OSGuess   string       `xml:"os,attr,omitempty"`
	TTLAvg    uint8        `xml:"ttl_avg,attr,omitempty"`
	Source    string       `xml:"source,attr,omitempty"`
	OnlyARP   bool         `xml:"only_arp,attr,omitempty"`
	FirstSeen string       `xml:"first_seen,attr,omitempty"`
	LastSeen  string       `xml:"last_seen,attr,omitempty"`
	Protocols []string     `xml:"protocols>protocol,omitempty"`
	Ports     []int        `xml:"ports>port,omitempty"`
	VLANs     []int        `xml:"vlans>vlan,omitempty"`
	Anomalies []XMLAnomaly `xml:"anomalies>anomaly,omitempty"`
	Info      string       `xml:"info,omitempty"`
}

// XMLSubnet represents a subnet in XML format
type XMLSubnet struct {
	XMLName xml.Name `xml:"subnet"`
	CIDR    string   `xml:"cidr,attr"`
	Source  string   `xml:"source,attr"`
	Hosts   []string `xml:"hosts>host,omitempty"`
}

// XMLReport represents the complete XML report
type XMLReport struct {
	XMLName        xml.Name    `xml:"zandoli_report"`
	Version        string      `xml:"version,attr"`
	GeneratedAt    string      `xml:"generated_at,attr"`
	ScanTime       string      `xml:"scan_time,attr"`
	TotalHosts     int         `xml:"total_hosts,attr"`
	TotalSubnets   int         `xml:"total_subnets,attr"`
	TotalAnomalies int         `xml:"total_anomalies,attr"`
	Summary        XMLSummary  `xml:"summary"`
	Hosts          []XMLHost   `xml:"hosts>host"`
	Subnets        []XMLSubnet `xml:"subnets>subnet"`
	Anomalies      []string    `xml:"anomalies>anomaly,omitempty"`
}

// XMLStat represents a statistic entry
type XMLStat struct {
	XMLName xml.Name `xml:"stat"`
	Name    string   `xml:"name,attr"`
	Value   int      `xml:"value,attr"`
}

// XMLSummary represents summary statistics
type XMLSummary struct {
	XMLName    xml.Name  `xml:"summary"`
	Categories []XMLStat `xml:"categories>stat"`
	Vendors    []XMLStat `xml:"vendors>stat"`
	Roles      []XMLStat `xml:"roles>stat"`
}

// ExportXML exports the hosts as an XML report.
func ExportXML(hosts []*model.Host, subnets []model.Subnet, xmlFile string, log *logger.Logger) error {
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

	// Calculate statistics
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

	// Convert hosts to XML format
	xmlHosts := make([]XMLHost, len(filtered))
	for i, h := range filtered {
		ipStr := ""
		if h.IP != nil {
			ipStr = h.IP.String()
		}

		// Convert anomalies
		xmlAnomalies := make([]XMLAnomaly, len(h.Anomalies))
		for j, anomaly := range h.Anomalies {
			xmlAnomalies[j] = XMLAnomaly{
				Description: anomaly.Description,
				Severity:    anomaly.Severity,
			}
		}

		xmlHosts[i] = XMLHost{
			IP:        ipStr,
			MAC:       h.MACStr,
			Vendor:    h.Vendor,
			Role:      h.Role,
			Category:  h.Category,
			Hostname:  h.Hostname,
			OSGuess:   h.OSGuess,
			TTLAvg:    h.TTLAvg,
			Source:    h.Source,
			OnlyARP:   h.OnlyARP,
			FirstSeen: h.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
			LastSeen:  h.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
			Protocols: h.Protocols,
			Ports:     h.Ports,
			VLANs:     h.VLANs,
			Anomalies: xmlAnomalies,
			Info:      h.Info,
		}
	}

	// Filter subnets to keep only /24
	filteredSubnets := utils.FilterSubnets24(subnets)

	// Convert subnets to XML format
	xmlSubnets := make([]XMLSubnet, len(filteredSubnets))
	for i, s := range filteredSubnets {
		xmlSubnets[i] = XMLSubnet{
			CIDR:   s.CIDR,
			Source: s.Source,
			Hosts:  s.Hosts,
		}
	}

	// Convert maps to slices for XML
	categoryStats := make([]XMLStat, 0, len(categories))
	for name, value := range categories {
		categoryStats = append(categoryStats, XMLStat{Name: name, Value: value})
	}

	vendorStats := make([]XMLStat, 0, len(vendors))
	for name, value := range vendors {
		vendorStats = append(vendorStats, XMLStat{Name: name, Value: value})
	}

	roleStats := make([]XMLStat, 0, len(roles))
	for name, value := range roles {
		roleStats = append(roleStats, XMLStat{Name: name, Value: value})
	}

	// Create the XML report
	report := XMLReport{
		Version:        "0.94",
		GeneratedAt:    time.Now().Format("2006-01-02T15:04:05Z07:00"),
		ScanTime:       time.Now().Format("2006-01-02T15:04:05Z07:00"),
		TotalHosts:     len(filtered),
		TotalSubnets:   len(filteredSubnets),
		TotalAnomalies: len(uniqueAnomalies),
		Summary: XMLSummary{
			Categories: categoryStats,
			Vendors:    vendorStats,
			Roles:      roleStats,
		},
		Hosts:     xmlHosts,
		Subnets:   xmlSubnets,
		Anomalies: uniqueAnomalies,
	}

	f, err := os.Create(xmlFile)
	if err != nil {
		log.Error().Err(err).Str("file", xmlFile).Msg("Failed to create XML report file")
		return err
	}
	defer f.Close()

	// Write the XML header
	fmt.Fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

	// Encoder le rapport XML
	encoder := xml.NewEncoder(f)
	encoder.Indent("", "  ")

	if err := encoder.Encode(report); err != nil {
		log.Error().Err(err).Msg("Failed to encode XML report")
		return err
	}

	log.Info().Str("file", xmlFile).Msg("XML export complete")
	return nil
}
