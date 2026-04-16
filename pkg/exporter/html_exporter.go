// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package exporter handles structured export of discovered Hosts to HTML.
package exporter

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

//go:embed templates/report.html.tmpl
var reportTemplate string

// isPrivateSubnet checks if a CIDR corresponds to a private subnet
func isPrivateSubnet(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	ip := ipNet.IP.To4()
	if ip == nil {
		return false
	}

	// Check RFC 1918 + CGNAT private ranges
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	// CGNAT 100.64.0.0/10
	if ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 {
		return true
	}

	return false
}

// findLogo looks for a logo file in the HTML file directory
func findLogo(htmlFile string) string {
	relDir := filepath.Dir(htmlFile)
	try := []string{"zandoli_logo.svg", "zandoli_logo.png"}
	for _, name := range try {
		if _, err := os.Stat(filepath.Join(relDir, name)); err == nil {
			return name // relative reference from the HTML file directory
		}
	}
	return ""
}

// sortMapByValue sorts a map by descending value and returns key-value pairs
func sortMapByValue(m map[string]int) []struct {
	Key   string
	Value int
} {
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range m {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	result := make([]struct {
		Key   string
		Value int
	}, len(ss))
	for i, kv := range ss {
		result[i].Key = kv.Key
		result[i].Value = kv.Value
	}
	return result
}

// IPSelectionResult represents the result of IP selection for a host
type IPSelectionResult struct {
	IPv4Primary string   // IP principale IPv4
	IPv6Primary string   // IP principale IPv6
	IPv4All     []string // All IPv4 addresses
	IPv6All     []string // All IPv6 addresses
	IPv4Others  []string // Autres IPv4 (sans la principale)
	IPv6Others  []string // Autres IPv6 (sans la principale)
}

// SelectIPs selects the primary IPv4 and IPv6 IPs according to priority rules
func SelectIPs(ips []net.IP) IPSelectionResult {
	result := IPSelectionResult{
		IPv4All: make([]string, 0),
		IPv6All: make([]string, 0),
	}

	// Separate IPv4 and IPv6
	for _, ip := range ips {
		if ip == nil {
			continue
		}

		ipStr := ip.String()

		if ip.To4() != nil {
			// IPv4
			if !utils.IsExcludedIPv4Str(ipStr) {
				result.IPv4All = append(result.IPv4All, ipStr)
			}
		} else if ip.To16() != nil {
			// IPv6
			if !utils.IsExcludedIPv6Str(ipStr) {
				result.IPv6All = append(result.IPv6All, ipStr)
			}
		}
	}

	// Select the primary IPv4
	result.IPv4Primary = selectPrimaryIPv4(result.IPv4All)
	if result.IPv4Primary != "" {
		result.IPv4Others = removeFromSlice(result.IPv4All, result.IPv4Primary)
	}

	// Select the primary IPv6
	result.IPv6Primary = selectPrimaryIPv6(result.IPv6All)
	if result.IPv6Primary != "" {
		result.IPv6Others = removeFromSlice(result.IPv6All, result.IPv6Primary)
	}

	return result
}

// selectPrimaryIPv4 selects the primary IPv4 according to priority rules
func selectPrimaryIPv4(ips []string) string {
	if len(ips) == 0 {
		return ""
	}

	// Priority 1: RFC1918 private (192.168/16, then 172.16/12, then 10/8)
	for _, ip := range ips {
		if strings.HasPrefix(ip, "192.168.") {
			return ip
		}
	}
	for _, ip := range ips {
		if strings.HasPrefix(ip, "172.") {
			// Check 172.16.0.0/12
			parts := strings.Split(ip, ".")
			if len(parts) >= 2 {
				if second, err := strconv.Atoi(parts[1]); err == nil && second >= 16 && second <= 31 {
					return ip
				}
			}
		}
	}
	for _, ip := range ips {
		if strings.HasPrefix(ip, "10.") {
			return ip
		}
	}

	// Priority 2: APIPA 169.254/16
	for _, ip := range ips {
		if strings.HasPrefix(ip, "169.254.") {
			return ip
		}
	}

	// Priority 3: Public (first found)
	for _, ip := range ips {
		return ip
	}

	return ""
}

// selectPrimaryIPv6 selects the primary IPv6 according to priority rules
func selectPrimaryIPv6(ips []string) string {
	if len(ips) == 0 {
		return ""
	}

	// Priority 1: Global/ULA non-link-local (first found)
	for _, ip := range ips {
		return ip
	}

	return ""
}

// removeFromSlice removes an element from a slice
func removeFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// SelectPrivateIPs selects only private IPs according to priority rules
func SelectPrivateIPs(ips []net.IP) IPSelectionResult {
	result := IPSelectionResult{
		IPv4All: make([]string, 0),
		IPv6All: make([]string, 0),
	}

	// Separate IPv4 and IPv6, keeping only private ones
	for _, ip := range ips {
		if ip == nil {
			continue
		}

		ipStr := ip.String()

		if ip.To4() != nil {
			// IPv4 - keep only private
			if !utils.IsExcludedIPv4Str(ipStr) && utils.IsPrivateIPv4(ip) {
				result.IPv4All = append(result.IPv4All, ipStr)
			}
		} else if ip.To16() != nil {
			// IPv6 - keep all non-excluded (no private/public distinction in IPv6)
			if !utils.IsExcludedIPv6Str(ipStr) {
				result.IPv6All = append(result.IPv6All, ipStr)
			}
		}
	}

	// Select the primary IPv4 (private)
	result.IPv4Primary = selectPrimaryIPv4(result.IPv4All)
	if result.IPv4Primary != "" {
		result.IPv4Others = removeFromSlice(result.IPv4All, result.IPv4Primary)
	}

	// Select the primary IPv6
	result.IPv6Primary = selectPrimaryIPv6(result.IPv6All)
	if result.IPv6Primary != "" {
		result.IPv6Others = removeFromSlice(result.IPv6All, result.IPv6Primary)
	}

	return result
}

// hasPrivateIPv4 checks if a host has at least one private IP
func hasPrivateIPv4(host *model.Host) bool {
	// Check the primary IP
	if host.IP != nil && utils.IsPrivateIPv4(host.IP) {
		return true
	}
	// Check all observed IPs
	for _, ip := range host.IPs {
		if ip != nil && utils.IsPrivateIPv4(ip) {
			return true
		}
	}
	return false
}

// RFC1918Class represents an RFC1918 private range class
type RFC1918Class string

const (
	// RFC1918ClassA represents the 10.0.0.0/8 range
	RFC1918ClassA RFC1918Class = "A"
	// RFC1918ClassB represents the 172.16.0.0/12 range
	RFC1918ClassB RFC1918Class = "B"
	// RFC1918ClassC represents the 192.168.0.0/16 range
	RFC1918ClassC RFC1918Class = "C"
)

// GetRFC1918Class determines the RFC1918 class of a private IPv4 address
// Returns "A" for 10.0.0.0/8, "B" for 172.16.0.0/12, "C" for 192.168.0.0/16
// Returns "" if the IP is not in an RFC1918 range
func GetRFC1918Class(ip net.IP) RFC1918Class {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "" // Pas IPv4
	}

	// 10.0.0.0/8
	if ipv4[0] == 10 {
		return RFC1918ClassA
	}

	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return RFC1918ClassB
	}

	// 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return RFC1918ClassC
	}

	return "" // Not in an RFC1918 range
}

// SubnetClassInfo contains information for a subnet class
type SubnetClassInfo struct {
	Class   string   `json:"class"`
	Subnets []string `json:"subnets"`
	IPs     []string `json:"ips"`
}

// subnetRow represents a subnet row with its specific IPs
type subnetRow struct {
	CIDR    *net.IPNet
	CIDRStr string
	IPs     []string
	Class   string // "A" | "B" | "C"
}

// ipNetContains checks if network a strictly contains network b
func ipNetContains(a, b *net.IPNet) bool {
	onesA, bitsA := a.Mask.Size()
	onesB, bitsB := b.Mask.Size()

	// Same IP family and a has a smaller (wider) mask
	if bitsA != bitsB || onesA >= onesB {
		return false
	}

	// Verify that b.IP is within network a
	return a.Contains(b.IP)
}

// dedupeCoveredSupernets removes supernets that are entirely covered by their subnets
func dedupeCoveredSupernets(rows []subnetRow) []subnetRow {
	if len(rows) <= 1 {
		return rows
	}

	// Build the children map for each subnet
	children := make(map[int][]int)
	for i := range rows {
		for j := range rows {
			if i == j {
				continue
			}
			if ipNetContains(rows[i].CIDR, rows[j].CIDR) {
				children[i] = append(children[i], j)
			}
		}
	}

	// Determine which subnets to keep
	keep := make([]bool, len(rows))
	for i := range keep {
		keep[i] = true
	}

	for i := range rows {
		if len(children[i]) == 0 {
			continue // No children, keep
		}

		// Calculate direct IPs (IPs in the supernet that are not in children)
		directIPs := make(map[string]struct{})
		for _, ip := range rows[i].IPs {
			directIPs[ip] = struct{}{}
		}

		// Remove IPs that appear in child subnets
		for _, childIdx := range children[i] {
			for _, ip := range rows[childIdx].IPs {
				delete(directIPs, ip)
			}
		}

		// If no direct IPs, the supernet is entirely covered
		if len(directIPs) == 0 {
			keep[i] = false
		}
	}

	// Build the final result
	result := make([]subnetRow, 0, len(rows))
	for i, shouldKeep := range keep {
		if shouldKeep {
			result = append(result, rows[i])
		}
	}

	return result
}

// limitIPsDisplay displays ALL IPs, deduplicated and sorted (ignores the limit parameter)
func limitIPsDisplay(ips []string, _ int) string {
	if len(ips) == 0 {
		return ""
	}

	// Deduplicate
	m := make(map[string]struct{}, len(ips))
	uniq := make([]string, 0, len(ips))
	for _, s := range ips {
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		// Keep only valid IPv4 (optional safety check)
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			m[s] = struct{}{}
			uniq = append(uniq, s)
		}
	}

	// Numeric IPv4 sort
	sort.Slice(uniq, func(i, j int) bool {
		a := net.ParseIP(uniq[i]).To4()
		b := net.ParseIP(uniq[j]).To4()
		return bytes.Compare(a, b) < 0
	})

	// Join with <br> and wrap in <code>
	var parts []string
	for _, ip := range uniq {
		parts = append(parts, "<code>"+ip+"</code>")
	}
	return strings.Join(parts, "<br>")
}

// uniqSortedIPv4 deduplicates and sorts a list of IPv4 IPs
func uniqSortedIPv4(list []string) []string {
	m := make(map[string]struct{}, len(list))
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a := net.ParseIP(out[i]).To4()
		b := net.ParseIP(out[j]).To4()
		return bytes.Compare(a, b) < 0
	})
	return out
}

// buildSubnetRows builds subnet rows with their specific IPs
func buildSubnetRows(subnets []model.SubnetEntry, hosts []*model.Host) []subnetRow {
	// Create a map to collect IPs by subnet
	subnetIPs := make(map[string][]string)

	// Process the provided subnets
	for _, subnet := range subnets {
		if subnet.Version != "ipv4" {
			continue
		}

		// Verify this is an RFC1918 private subnet
		_, ipNet, err := net.ParseCIDR(subnet.CIDR)
		if err != nil {
			continue
		}

		if GetRFC1918Class(ipNet.IP) == "" {
			continue // Ignore non-RFC1918 subnets
		}

		// Keep only /24
		ones, _ := ipNet.Mask.Size()
		if ones != 24 {
			continue
		}

		// Initialize the IP list for this subnet
		if subnetIPs[subnet.CIDR] == nil {
			subnetIPs[subnet.CIDR] = make([]string, 0)
		}

		// Add IP samples from the subnet
		for _, ipStr := range subnet.IPSamples {
			if net.ParseIP(ipStr) != nil {
				// Verify the IP belongs to the subnet
				if ipNet.Contains(net.ParseIP(ipStr)) {
					subnetIPs[subnet.CIDR] = append(subnetIPs[subnet.CIDR], ipStr)
				}
			}
		}
	}

	// Process hosts to add their IPs to corresponding subnets
	for _, host := range hosts {
		for _, ip := range host.IPs {
			if ip.To4() == nil {
				continue // Seulement IPv4
			}

			ipStr := ip.String()

			// Filter only RFC1918 private IPs
			if GetRFC1918Class(ip) == "" {
				continue
			}

			// Trouver le subnet correspondant
			for cidr, ips := range subnetIPs {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}

				if ipNet.Contains(ip) {
					// Verify the IP is not already in the list
					found := false
					for _, existingIP := range ips {
						if existingIP == ipStr {
							found = true
							break
						}
					}
					if !found {
						subnetIPs[cidr] = append(subnetIPs[cidr], ipStr)
					}
					break // An IP can only belong to one subnet in our logic
				}
			}
		}
	}

	// Build the subnet rows
	var rows []subnetRow
	for cidr, ips := range subnetIPs {
		if len(ips) == 0 {
			continue // Ignore subnets without IPs
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// Determine the class
		var class string
		switch GetRFC1918Class(ipNet.IP) {
		case RFC1918ClassA:
			class = "A"
		case RFC1918ClassB:
			class = "B"
		case RFC1918ClassC:
			class = "C"
		default:
			continue
		}

		// Deduplicate and sort the IPs
		ips = uniqSortedIPv4(ips)

		rows = append(rows, subnetRow{
			CIDR:    ipNet,
			CIDRStr: cidr,
			IPs:     ips,
			Class:   class,
		})
	}

	return rows
}

// classifySubnetsByClass classifies subnets and IPs by RFC1918 private range
// Removes covered supernets and displays IPs per subnet
func classifySubnetsByClass(subnets []model.SubnetEntry, hosts []*model.Host) []SubnetClassInfo {
	// Build subnet rows with their specific IPs
	rows := buildSubnetRows(subnets, hosts)

	// Remove entirely covered supernets
	rows = dedupeCoveredSupernets(rows)

	// Sort by descending prefix length, then by network address
	sort.Slice(rows, func(i, j int) bool {
		oi, _ := rows[i].CIDR.Mask.Size()
		oj, _ := rows[j].CIDR.Mask.Size()
		if oi != oj {
			return oi > oj // Prefixlen descendant
		}
		return bytes.Compare(rows[i].CIDR.IP, rows[j].CIDR.IP) < 0 // Ascending network address
	})

	// Grouper par classe
	classData := map[RFC1918Class]*SubnetClassInfo{
		RFC1918ClassA: {Class: "Classe A (10.0.0.0/8)", Subnets: []string{}, IPs: []string{}},
		RFC1918ClassB: {Class: "Classe B (172.16.0.0/12)", Subnets: []string{}, IPs: []string{}},
		RFC1918ClassC: {Class: "Classe C (192.168.0.0/16)", Subnets: []string{}, IPs: []string{}},
	}

	// Add each subnet with its specific IPs
	for _, row := range rows {
		var class RFC1918Class
		switch row.Class {
		case "A":
			class = RFC1918ClassA
		case "B":
			class = RFC1918ClassB
		case "C":
			class = RFC1918ClassC
		default:
			continue
		}

		// Add the subnet with IP count
		subnetWithCount := fmt.Sprintf("%s (%d IPs)", row.CIDRStr, len(row.IPs))
		classData[class].Subnets = append(classData[class].Subnets, subnetWithCount)

		// Add the specific IPs to this subnet
		classData[class].IPs = append(classData[class].IPs, row.IPs...)
	}

	// Return classes in A, B, C order
	result := []SubnetClassInfo{
		*classData[RFC1918ClassA],
		*classData[RFC1918ClassB],
		*classData[RFC1918ClassC],
	}

	return result
}


// RenderL2Summary generates the enriched L2 summary with protocol details
func RenderL2Summary(h model.Host) string {
	// Displays only real Layer-2 elements: CDP, LLDP, STP, 802.1X, VLAN
	// OUI/Vendor are NOT L2 elements and appear in the "Vendor" column
	// Format: detailed display with Platform, Version, SystemDescription, etc.
	var sections []string

	// CDP - detect via CDPInfo presence OR CDP protocol
	hasCDP := h.CDP != nil || utils.ContainsString(h.Protocols, "CDP")
	if hasCDP {
		cdpSection := "🟡 <strong>CDP</strong>"
		if h.CDP != nil {
			var cdpDetails []string
			if h.CDP.DeviceID != "" {
				cdpDetails = append(cdpDetails, "<code>"+h.CDP.DeviceID+"</code>")
			}
			if h.CDP.Platform != "" {
				cdpDetails = append(cdpDetails, h.CDP.Platform)
			}
			if h.CDP.Version != "" {
				// Truncate Version if too long
				version := h.CDP.Version
				if len(version) > 35 {
					version = version[:32] + "..."
				}
				cdpDetails = append(cdpDetails, version)
			}
			if h.CDP.PortID != "" {
				cdpDetails = append(cdpDetails, "Port: <code>"+h.CDP.PortID+"</code>")
			}
			if h.CDP.NativeVLAN > 0 {
				cdpDetails = append(cdpDetails, "Native VLAN: "+strconv.Itoa(h.CDP.NativeVLAN))
			}
			if len(cdpDetails) > 0 {
				cdpSection += "<br>└─ " + strings.Join(cdpDetails, "<br>└─ ")
			}
		}
		sections = append(sections, cdpSection)
	}

	// LLDP - detect via LLDPInfo presence OR LLDP protocol
	hasLLDP := h.LLDP != nil || utils.ContainsString(h.Protocols, "LLDP")
	if hasLLDP {
		lldpSection := "🔵 <strong>LLDP</strong>"
		if h.LLDP != nil {
			var lldpDetails []string
			if h.LLDP.ChassisID != "" {
				lldpDetails = append(lldpDetails, "Chassis: <code>"+h.LLDP.ChassisID+"</code>")
			}
			if h.LLDP.SysName != "" {
				lldpDetails = append(lldpDetails, h.LLDP.SysName)
			}
			if h.LLDP.SysDescr != "" {
				// Truncate SystemDescription if too long
				descr := h.LLDP.SysDescr
				if len(descr) > 35 {
					descr = descr[:32] + "..."
				}
				lldpDetails = append(lldpDetails, descr)
			}
			if h.LLDP.PortID != "" {
				lldpDetails = append(lldpDetails, "Port: <code>"+h.LLDP.PortID+"</code>")
			}
			if len(h.LLDP.Capabilities) > 0 {
				lldpDetails = append(lldpDetails, "Caps: "+strings.Join(h.LLDP.Capabilities, ", "))
			}
			if len(lldpDetails) > 0 {
				lldpSection += "<br>└─ " + strings.Join(lldpDetails, "<br>└─ ")
			}
		}
		sections = append(sections, lldpSection)
	}

	// STP - detect via STPInfo presence OR STP protocol
	hasSTP := h.STP != nil || utils.ContainsString(h.Protocols, "STP")
	if hasSTP {
		stpSection := "🔴 <strong>STP</strong>"
		if h.STP != nil {
			var stpDetails []string
			if h.STP.BridgeID != "" {
				stpDetails = append(stpDetails, "Bridge: <code>"+h.STP.BridgeID+"</code>")
			}
			if h.STP.RootBridgeID != "" {
				if h.STP.IsRoot {
					stpDetails = append(stpDetails, "Root Bridge: <code>"+h.STP.RootBridgeID+"</code> <em>(this device)</em>")
				} else {
					stpDetails = append(stpDetails, "Root: <code>"+h.STP.RootBridgeID+"</code>")
				}
			}
			if h.STP.PortID > 0 {
				stpDetails = append(stpDetails, "Port: "+strconv.Itoa(int(h.STP.PortID)))
			}
			if h.STP.RootPathCost > 0 {
				stpDetails = append(stpDetails, "Cost: "+strconv.Itoa(int(h.STP.RootPathCost)))
			}
			if h.STP.HelloTime > 0 {
				helloSec := float64(h.STP.HelloTime) / 256.0
				stpDetails = append(stpDetails, fmt.Sprintf("Hello: %.1fs", helloSec))
			}
			if len(stpDetails) > 0 {
				stpSection += "<br>└─ " + strings.Join(stpDetails, "<br>└─ ")
			}
		}
		sections = append(sections, stpSection)
	}

	// 802.1X (EAPOL) - detect via EAPOL or 802.1X protocol
	hasEAPOL := utils.ContainsString(h.Protocols, "EAPOL") || utils.ContainsString(h.Protocols, "802.1X")
	if hasEAPOL {
		sections = append(sections, "🟢 <strong>802.1X</strong> (EAPOL)")
	}

	// VLANs - use h.VLANs (which is populated) instead of h.L2Signals.VLANs
	if len(h.VLANs) > 0 {
		vlanSection := "⚪ <strong>VLANs</strong>"
		var vlanDetails []string

		// Display the primary VLAN if not 0
		if h.PrimaryVLAN > 0 {
			vlanDetails = append(vlanDetails, "Primary: <code>"+strconv.Itoa(h.PrimaryVLAN)+"</code>")
		}

		// Display all observed VLANs
		vlanStrs := make([]string, 0, len(h.VLANs))
		for _, vlan := range h.VLANs {
			vlanStrs = append(vlanStrs, strconv.Itoa(vlan))
		}
		if len(vlanStrs) > 0 {
			if len(vlanStrs) <= 5 {
				vlanDetails = append(vlanDetails, "All: "+strings.Join(vlanStrs, ", "))
			} else {
				vlanDetails = append(vlanDetails, fmt.Sprintf("All: %s,… (+%d)", strings.Join(vlanStrs[:5], ", "), len(vlanStrs)-5))
			}
		}

		if len(vlanDetails) > 0 {
			vlanSection += "<br>└─ " + strings.Join(vlanDetails, "<br>└─ ")
		}
		sections = append(sections, vlanSection)
	}

	// Return "—" if no L2 element detected
	if len(sections) == 0 {
		return "—"
	}

	return strings.Join(sections, "<br><br>")
}

// RenderVLANCell generates the VLAN display without using ContainsString
func RenderVLANCell(h model.Host) string {
	// Check if VLANStats is empty
	if len(h.VLANStats) == 0 {
		return "—"
	}

	// Create a sorted list of VLANs
	type kv struct {
		id string
		n  int
	}
	items := make([]kv, 0, len(h.VLANStats))

	for vlanID, count := range h.VLANStats {
		items = append(items, kv{fmt.Sprint(vlanID), count})
	}

	// Trier par ID de VLAN
	sort.Slice(items, func(i, j int) bool {
		return items[i].id < items[j].id
	})

	// Build the result string
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(it.id)
		b.WriteString(": ")
		b.WriteString(strconv.Itoa(it.n))
		b.WriteString(" frames")
	}

	return b.String()
}

// l2DetailsTemplate has been removed and replaced with l2DetailsHTML function

// vlanDetailsTemplate has been removed and replaced with vlanDetailsHTML function


// deduplicatedAnomaliesTemplate has been removed and replaced with deduplicatedAnomaliesHTML function

// HTMLSummary represents the summary statistics for HTML export
type HTMLSummary struct {
	Categories []struct {
		Key   string
		Value int
	}
	Vendors []struct {
		Key   string
		Value int
	}
	Roles []struct {
		Key   string
		Value int
	}
	Protocols []struct {
		Key   string
		Value int
	}
	Sources []struct {
		Key   string
		Value int
	}
}

type htmlData struct {
	TotalHosts         int
	ScanTime           string
	ProfileName        string
	Version            string
	GeneratedAt        string
	Hosts              []*model.Host
	HostsPrivateOnly   []*model.Host // Hosts with at least one private IP (for the "Discovered Hosts" section)
	Subnets            []model.Subnet
	TopologySubnets    []model.SubnetEntry
	IPv4SubnetsCount   int
	IPv6SubnetsCount   int
	IPv4PrivateSubnets []model.SubnetEntry
	IPv4PublicSubnets  []model.SubnetEntry
	IPv6Subnets        []model.SubnetEntry
	SubnetClassInfo    []SubnetClassInfo
	LogoPath           string
	Summary            HTMLSummary
}

// ExportHTML exports the hosts as a styled HTML report.
func ExportHTML(hosts []*model.Host, subnets []model.Subnet, htmlFile string, log *logger.Logger) error {
	return ExportHTMLWithOptions(hosts, subnets, htmlFile, log, false)
}

// ExportHTMLWithOptions exports the hosts as a styled HTML report with additional options.
func ExportHTMLWithOptions(hosts []*model.Host, subnets []model.Subnet, htmlFile string, log *logger.Logger, allowPublicSubnets bool) error {
	filtered := make([]*model.Host, 0, len(hosts))

	// Maps to collect statistics
	categories := make(map[string]int)
	vendors := make(map[string]int)
	roles := make(map[string]int)
	protocols := make(map[string]int)
	sources := make(map[string]int)

	for _, h := range hosts {
		// Include only hosts with at least one IPv4 or IPv6 IP
		hasIPv4 := false
		hasIPv6 := false

		// Check the primary IP
		if h.IP != nil {
			if h.IP.To4() != nil {
				hasIPv4 = true
			} else if h.IP.To16() != nil {
				hasIPv6 = true
			}
		}

		// Check all observed IPs
		for _, ip := range h.IPs {
			if ip != nil {
				if ip.To4() != nil {
					hasIPv4 = true
				} else if ip.To16() != nil {
					hasIPv6 = true
				}
			}
		}

		// Keep only hosts with at least one IPv4 or IPv6 IP
		if !hasIPv4 && !hasIPv6 {
			continue
		}

		// Validate timestamps as in JSON exporter
		if !utils.IsSafeTime(h.FirstSeen) || !utils.IsSafeTime(h.LastSeen) {
			continue
		}

		filtered = append(filtered, h)

		// Collect statistics
		if h.Category != "" {
			categories[h.Category]++
		}
		if h.Vendor != "" && h.Vendor != "Unknown" {
			vendors[h.Vendor]++
		}
		if h.Role != "" {
			roles[h.Role]++
		}
		if h.Source != "" {
			sources[h.Source]++
		}
		for _, protocol := range h.Protocols {
			protocols[protocol]++
		}
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"join": strings.Join,
		"appendIPs": func(ips []net.IP, ip net.IP) []net.IP {
			if ip == nil {
				return ips
			}
			return append(ips, ip)
		},
		"selectIPs":        SelectIPs,
		"selectPrivateIPs": SelectPrivateIPs,
		"renderL2Summary":  RenderL2Summary,
		"renderVLANCell":   RenderVLANCell,
		"limitIPsDisplay":  limitIPsDisplay,
		"roleLabel": func(r string) string {
			switch strings.ToLower(r) {
			case "client":
				return "Client"
			case "server":
				return "Serveur"
			case "reseau", "réseau", "router", "switch", "network_device", "repeater", "access_point":
				return "Réseau"
			default:
				return r
			}
		},
		"normalizeRole": func(r string) string {
			return analyzer.NormalizeRole(r)
		},
		"formatTTL": func(ttlAvg uint8) string {
			if ttlAvg == 0 {
				return "—"
			}
			return fmt.Sprintf("%d", ttlAvg)
		},
		"formatInt": func(v int) string {
			if v == 0 {
				return "—"
			}
			return strconv.Itoa(v)
		},
		"formatUint8": func(v uint8) string {
			if v == 0 {
				return "—"
			}
			return strconv.FormatUint(uint64(v), 10)
		},
		"formatUint64": func(v uint64) string {
			if v == 0 {
				return "—"
			}
			return strconv.FormatUint(v, 10)
		},
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"anomalyCount": func(a []model.Anomaly) int {
			return len(a)
		},
		"formatServices": func(ports []int) string {
			if len(ports) == 0 {
				return "—"
			}
			strs := make([]string, len(ports))
			for i, p := range ports {
				strs[i] = strconv.Itoa(p)
			}
			return strings.Join(strs, ",")
		},
		"cdpDeviceIDOrDash": func(h model.Host) string {
			if h.CDP != nil && h.CDP.DeviceID != "" {
				return h.CDP.DeviceID
			}
			return "—"
		},
		"lldpSysNameOrDash": func(h model.Host) string {
			if h.LLDP != nil && h.LLDP.SysName != "" {
				return h.LLDP.SysName
			}
			return "—"
		},
		"substr": func(s string, start, end int) string {
			if start >= len(s) {
				return ""
			}
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"printf": fmt.Sprintf,
		"or": func(a, b string) string {
			if a != "" {
				return a
			}
			return b
		},
		"dict": func(values ...interface{}) map[string]interface{} {
			dict := make(map[string]interface{})
			for i := 0; i < len(values); i += 2 {
				if i+1 < len(values) {
					dict[values[i].(string)] = values[i+1]
				}
			}
			return dict
		},
		"set": func(dict map[string]interface{}, key string, value interface{}) map[string]interface{} {
			dict[key] = value
			return dict
		},
		"index": func(dict map[string]interface{}, key string) interface{} {
			return dict[key]
		},
		"hasCDP": func(h *model.Host) bool {
			return h.CDP != nil
		},
		"hasSTP": func(h *model.Host) bool {
			return h.STP != nil
		},
		"cdpDeviceID": func(h *model.Host) string {
			if h.CDP != nil && h.CDP.DeviceID != "" {
				return h.CDP.DeviceID
			}
			return "Unknown"
		},
		"cdpPortID": func(h *model.Host) string {
			if h.CDP != nil {
				return h.CDP.PortID
			}
			return ""
		},
		"cdpPlatform": func(h *model.Host) string {
			if h.CDP != nil {
				return h.CDP.Platform
			}
			return ""
		},
		"cdpVersion": func(h *model.Host) string {
			if h.CDP != nil {
				return h.CDP.Version
			}
			return ""
		},
		"cdpDecodedCaps": func(h *model.Host) []string {
			if h.CDP != nil {
				return h.CDP.DecodedCaps
			}
			return []string{}
		},
		"stpBridgeID": func(h *model.Host) string {
			if h.STP != nil && h.STP.BridgeID != "" {
				return h.STP.BridgeID
			}
			return "Unknown"
		},
		"stpRootBridgeID": func(h *model.Host) string {
			if h.STP != nil {
				return h.STP.RootBridgeID
			}
			return ""
		},
	}).Parse(reportTemplate)
	if err != nil {
		log.Error().Err(err).Msg("Template parsing failed")
		return err
	}

	// Create the sorted summary
	summary := HTMLSummary{
		Categories: sortMapByValue(categories),
		Vendors:    sortMapByValue(vendors),
		Roles:      sortMapByValue(roles),
		Protocols:  sortMapByValue(protocols),
		Sources:    sortMapByValue(sources),
	}

	// Compute subnets from filtered hosts
	// Use ComputeActiveSubnets to get all detected subnets (/24, /16, DHCP, CDP, etc.)
	allSubnets := analyzer.ComputeActiveSubnets(filtered)

	// Filter public subnets if needed
	var recomputedSubnets []model.Subnet
	if allowPublicSubnets {
		recomputedSubnets = allSubnets
	} else {
		for _, subnet := range allSubnets {
			// Check if the subnet is private
			if isPrivateSubnet(subnet.CIDR) {
				recomputedSubnets = append(recomputedSubnets, subnet)
			}
		}
	}

	// Retrieve VLAN-aware topology subnets
	topologySubnets := analyzer.GetTopologySubnets()

	// Convert subnets provided as parameter to SubnetEntry and add them
	for _, subnet := range subnets {
		// Determine the IP version
		version := "ipv4"
		if strings.Contains(subnet.CIDR, ":") {
			version = "ipv6"
		}

		// Create a SubnetEntry
		subnetEntry := model.SubnetEntry{
			CIDR:       subnet.CIDR,
			Version:    version,
			Source:     subnet.Source,
			HostsCount: subnet.CountHosts,
		}

		// Add IP samples if available
		if len(subnet.Hosts) > 0 {
			// Take the first 5 hosts as samples
			maxSamples := 5
			if len(subnet.Hosts) < maxSamples {
				maxSamples = len(subnet.Hosts)
			}
			subnetEntry.IPSamples = subnet.Hosts[:maxSamples]
		}

		// Check if this subnet does not already exist in topologySubnets
		exists := false
		for _, existing := range topologySubnets {
			if existing.CIDR == subnetEntry.CIDR {
				exists = true
				break
			}
		}
		if !exists {
			topologySubnets = append(topologySubnets, subnetEntry)
		}
	}

	// Classify subnets by type for display
	var ipv4Private, ipv4Public, ipv6 []model.SubnetEntry
	ipv4Count := 0
	ipv6Count := 0

	for _, subnet := range topologySubnets {
		if subnet.Version == "ipv4" {
			ipv4Count++
			if isPrivateSubnet(subnet.CIDR) {
				ipv4Private = append(ipv4Private, subnet)
			} else {
				ipv4Public = append(ipv4Public, subnet)
			}
		} else if subnet.Version == "ipv6" {
			ipv6Count++
			ipv6 = append(ipv6, subnet)
		}
	}

	// Filter hosts with at least one RFC1918 private IP for the "Discovered Hosts" section
	hostsPrivateOnly := make([]*model.Host, 0, len(filtered))
	for _, h := range filtered {
		// Include only hosts with at least one RFC1918 private IP
		if hasPrivateIPv4(h) {
			hostsPrivateOnly = append(hostsPrivateOnly, h)
		}
	}

	// Classify subnets by class A, B, C
	subnetClassInfo := classifySubnetsByClass(topologySubnets, filtered)

	data := htmlData{
		TotalHosts:         len(filtered),
		ScanTime:           time.Now().Format("2006-01-02 15:04:05"),
		ProfileName:        "default",
		Version:            "Alpha",
		GeneratedAt:        time.Now().Format(time.RFC3339),
		Hosts:              filtered,
		HostsPrivateOnly:   hostsPrivateOnly,
		Subnets:            recomputedSubnets,
		TopologySubnets:    topologySubnets,
		IPv4SubnetsCount:   ipv4Count,
		IPv6SubnetsCount:   ipv6Count,
		IPv4PrivateSubnets: ipv4Private,
		IPv4PublicSubnets:  ipv4Public,
		IPv6Subnets:        ipv6,
		SubnetClassInfo:    subnetClassInfo,
		LogoPath:           findLogo(htmlFile),
		Summary:            summary,
	}

	f, err := os.Create(htmlFile)
	if err != nil {
		log.Error().Err(err).Str("file", htmlFile).Msg("Failed to create HTML report file")
		return err
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		log.Error().Err(err).Msg("Template execution failed")
		return err
	}

	log.Info().Str("file", htmlFile).Msg("HTML export complete")
	return nil
}
