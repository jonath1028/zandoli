// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package exporter handles structured export of discovered Hosts to CSV.
package exporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

func ExportCSV(hosts []*model.Host, path string, log *logger.Logger) error {
	file, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to create CSV file")
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Comma = ';' // Use ';' as delimiter instead of ','
	defer writer.Flush()

	headers := []string{
		"MAC", "Vendor", "Hostname", "Role", "RoleConfidence", "Category",
		"IP", "IPv6", "VLANs", "L2Flags",
		"UDP_Services", "TCP_Services", "Protocols",
		"OS", "OSScore", "TTL", "TTLAvg",
		"Source", "FirstSeen", "LastSeen", "PacketCount",
		"Anomalies", "CDP_DeviceID", "LLDP_SysName", "Info",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

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

		// MAC
		macStr := "—"
		if h.MAC != nil {
			macStr = h.MAC.String()
		}

		// Vendor
		vendorStr := valOrDash(h.Vendor)

		// Hostname
		hostnameStr := valOrDash(h.Hostname)

		// Role
		roleStr := valOrDash(h.Role)

		// RoleConfidence
		roleConfStr := intOrDash(h.RoleConfidence)

		// Category
		categoryStr := valOrDash(h.Category)

		// IP (principale IPv4)
		ipStr := "—"
		if h.IP != nil {
			ipStr = h.IP.String()
		}

		// IPv6 (principale IPv6)
		ipv6Str := "—"
		if h.IPv6Primary != nil {
			ipv6Str = h.IPv6Primary.String()
		}

		// VLANs (sorted, comma-separated)
		vlansStr := "—"
		if len(h.L2Signals.VLANs) > 0 {
			vlanStrs := make([]string, len(h.L2Signals.VLANs))
			for i, vlan := range h.L2Signals.VLANs {
				vlanStrs[i] = fmt.Sprintf("%d", vlan)
			}
			vlansStr = strings.Join(vlanStrs, ",")
		}

		// L2Flags (eapol, stp, lldp, cdp)
		var l2Flags []string
		if h.L2Signals.EAPOL {
			l2Flags = append(l2Flags, "EAPOL")
		}
		if h.L2Signals.STP {
			l2Flags = append(l2Flags, "STP")
		}
		if h.L2Signals.LLDP {
			l2Flags = append(l2Flags, "LLDP")
		}
		if h.L2Signals.CDP {
			l2Flags = append(l2Flags, "CDP")
		}
		l2FlagsStr := "—"
		if len(l2Flags) > 0 {
			l2FlagsStr = strings.Join(l2Flags, ",")
		}

		// UDP_Services (sorted, comma-separated)
		udpServicesStr := "—"
		if len(h.Services.UDP) > 0 {
			udpStrs := make([]string, len(h.Services.UDP))
			for i, port := range h.Services.UDP {
				udpStrs[i] = fmt.Sprintf("%d", port)
			}
			udpServicesStr = strings.Join(udpStrs, ",")
		}

		// TCP_Services (sorted, comma-separated)
		tcpServicesStr := "—"
		if len(h.Services.TCP) > 0 {
			tcpStrs := make([]string, len(h.Services.TCP))
			for i, port := range h.Services.TCP {
				tcpStrs[i] = fmt.Sprintf("%d", port)
			}
			tcpServicesStr = strings.Join(tcpStrs, ",")
		}

		// Protocols (sorted, comma-separated)
		protocolsStr := "—"
		if len(h.Protocols) > 0 {
			protocolsStr = strings.Join(h.Protocols, ",")
		}

		// OS
		osStr := valOrDash(h.OSGuess)

		// OSScore
		osScoreStr := uint8OrDash(h.OSScore)

		// TTL
		ttlStr := intOrDash(h.TTL)

		// TTLAvg
		ttlAvgStr := uint8OrDash(h.TTLAvg)

		// Source
		sourceStr := valOrDash(h.Source)

		// FirstSeen / LastSeen
		firstSeenStr := timeOrDash(h.FirstSeen)
		lastSeenStr := timeOrDash(h.LastSeen)

		// PacketCount
		packetCountStr := "—"
		if h.PacketCount > 0 {
			packetCountStr = strconv.FormatUint(h.PacketCount, 10)
		}

		// Anomalies (count)
		anomaliesStr := strconv.Itoa(len(h.Anomalies))

		// CDP_DeviceID
		cdpDeviceID := "—"
		if h.CDP != nil && h.CDP.DeviceID != "" {
			cdpDeviceID = h.CDP.DeviceID
		}

		// LLDP_SysName
		lldpSysName := "—"
		if h.LLDP != nil && h.LLDP.SysName != "" {
			lldpSysName = h.LLDP.SysName
		}

		// Info
		infoStr := valOrDash(h.Info)

		row := []string{
			macStr,
			vendorStr,
			hostnameStr,
			roleStr,
			roleConfStr,
			categoryStr,
			ipStr,
			ipv6Str,
			vlansStr,
			l2FlagsStr,
			udpServicesStr,
			tcpServicesStr,
			protocolsStr,
			osStr,
			osScoreStr,
			ttlStr,
			ttlAvgStr,
			sourceStr,
			firstSeenStr,
			lastSeenStr,
			packetCountStr,
			anomaliesStr,
			cdpDeviceID,
			lldpSysName,
			infoStr,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	log.Info().Str("file", path).Msg("CSV export complete")
	return nil
}

// valOrDash returns the string value or "—" if empty.
func valOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// intOrDash returns the int as string, or "—" if 0.
func intOrDash(v int) string {
	if v == 0 {
		return "—"
	}
	return strconv.Itoa(v)
}

// uint8OrDash returns the uint8 as string, or "—" if 0.
func uint8OrDash(v uint8) string {
	if v == 0 {
		return "—"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// timeOrDash returns the time in ISO 8601 format, or "—" if zero.
func timeOrDash(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format(time.RFC3339)
}
