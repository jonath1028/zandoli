package sniffer

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

var DiscoveredNetworks = map[string]bool{}

// UpdateHostDNS enrichit un hôte avec des infos DNS/mDNS/LLMNR/NetBIOS
func UpdateHostDNS(ipRaw []byte, domain string) {
	for i := range DiscoveredHosts {
		if bytes.Equal(DiscoveredHosts[i].IP, ipRaw) {
			if DiscoveredHosts[i].DomainName == "" {
				DiscoveredHosts[i].DomainName = domain
			}
			if DiscoveredHosts[i].Hostname == "" {
				parts := strings.Split(domain, ".")
				if len(parts) > 0 {
					DiscoveredHosts[i].Hostname = parts[0]
				}
			}
			DiscoveredHosts[i].ProtocolsSeen["dns"] = true
			RegisterIP(ipRaw)
			break
		}
	}
}

// RegisterIP ajoute une IP au suivi des sous-réseaux détectés (privés uniquement)
func RegisterIP(ipRaw []byte) {
	ip := net.IP(ipRaw)
	if ip.To4() == nil || !isPrivateIP(ip) {
		return
	}
	network := ip.Mask(net.CIDRMask(24, 32))
	key := fmt.Sprintf("%s/24", network.String())

	if _, exists := DiscoveredNetworks[key]; !exists {
		DiscoveredNetworks[key] = true
	}
}

// isPrivateIP vérifie si une IP est dans les plages RFC1918 (privées)
func isPrivateIP(ip net.IP) bool {
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateCIDRs {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

