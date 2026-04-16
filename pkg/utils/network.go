// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"zandoli/pkg/model"
)

// FilterSubnets24 filters subnets to keep only /24
func FilterSubnets24(subnets []model.Subnet) []model.Subnet {
	filtered := make([]model.Subnet, 0, len(subnets))

	for _, subnet := range subnets {
		// Check if the CIDR ends with /24
		if strings.HasSuffix(subnet.CIDR, "/24") {
			filtered = append(filtered, subnet)
		} else {
			// Check if it is a /24 subnet by parsing the CIDR
			_, ipNet, err := net.ParseCIDR(subnet.CIDR)
			if err == nil {
				// Check if the mask is /24 (255.255.255.0)
				ones, bits := ipNet.Mask.Size()
				if ones == 24 && bits == 32 {
					filtered = append(filtered, subnet)
				}
			}
		}
	}

	return filtered
}

// FilterSubnets filters subnets to keep only IPv4 /24
func FilterSubnets(subnets []model.Subnet) []model.Subnet {
	filtered := make([]model.Subnet, 0, len(subnets))

	for _, subnet := range subnets {
		_, ipNet, err := net.ParseCIDR(subnet.CIDR)
		if err != nil {
			continue
		}

		ones, bits := ipNet.Mask.Size()

		// Keep only IPv4 /24 (24 network bits out of 32)
		if ones == 24 && bits == 32 {
			filtered = append(filtered, subnet)
		}
	}

	return filtered
}

// isPublicSubnet checks if a /24 subnet is in a public range
func isPublicSubnet(ip net.IP) bool {
	// Check first if it is a private range
	if isPrivateIP(ip) {
		return false
	}

	// Check special ranges (multicast, reserved)
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	// Note: 127.0.0.0/8 (loopback) is now treated as public

	// Multicast (224.0.0.0/4)
	if ipv4[0] >= 224 && ipv4[0] <= 239 {
		return false
	}

	// Reserved (240.0.0.0/4)
	if ipv4[0] >= 240 {
		return false
	}

	// Link-local (169.254.0.0/16) - already handled by isPrivateIP but double-checking
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return false
	}

	// Everything else is considered public
	return true
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local
	}

	for _, rangeStr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// RecomputeSubnetsFromHosts recomputes /24 subnets from filtered hosts
func RecomputeSubnetsFromHosts(hosts []*model.Host, allowPublicSubnets bool) []model.Subnet {
	subnetMap := make(map[string]model.Subnet)

	for _, host := range hosts {
		// Only process hosts with a valid IPv4 IP
		if host.IP == nil || host.IP.To4() == nil {
			continue
		}

		ipv4 := host.IP.To4()

		// Create the /24 subnet
		subnet24 := fmt.Sprintf("%s/24", ipv4.Mask(net.CIDRMask(24, 32)).String())

		// Check if public ranges should be excluded
		if !allowPublicSubnets && isPublicSubnet(ipv4) {
			continue
		}

		// Create or update the subnet
		if existing, exists := subnetMap[subnet24]; exists {
			// Add the IP if not already present
			ipStr := host.IP.String()
			found := false
			for _, existingIP := range existing.Hosts {
				if existingIP == ipStr {
					found = true
					break
				}
			}
			if !found {
				existing.Hosts = append(existing.Hosts, ipStr)
			}

			// Add VLANs from this host if they exist
			if host.PrimaryVLAN > 0 {
				vlanFound := false
				for _, existingVLAN := range existing.VLANs {
					if existingVLAN == host.PrimaryVLAN {
						vlanFound = true
						break
					}
				}
				if !vlanFound {
					existing.VLANs = append(existing.VLANs, host.PrimaryVLAN)
				}
			}

			subnetMap[subnet24] = existing
		} else {
			// Create a new subnet
			vlans := []int{}
			if host.PrimaryVLAN > 0 {
				vlans = append(vlans, host.PrimaryVLAN)
			}

			subnetMap[subnet24] = model.Subnet{
				CIDR:   subnet24,
				Source: "computed",
				Hosts:  []string{host.IP.String()},
				VLANs:  vlans,
			}
		}
	}

	// Convertir la map en slice et trier par CIDR
	result := make([]model.Subnet, 0, len(subnetMap))
	for _, subnet := range subnetMap {
		// Sort hosts within each subnet
		sort.Strings(subnet.Hosts)
		// Trier les VLANs
		sort.Ints(subnet.VLANs)
		result = append(result, subnet)
	}

	// Sort subnets by CIDR
	sort.Slice(result, func(i, j int) bool {
		return result[i].CIDR < result[j].CIDR
	})

	return result
}
