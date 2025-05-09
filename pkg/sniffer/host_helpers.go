package sniffer

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
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

// GetOrCreateHostByMAC retourne un pointeur vers l’hôte correspondant au MAC, ou le crée s’il n’existe pas
func GetOrCreateHostByMAC(mac string) *Host {
	for i := range DiscoveredHosts {
		if DiscoveredHosts[i].MACStr == mac {
			return &DiscoveredHosts[i]
		}
	}

	newHost := Host{
		MACStr:         mac,
		Timestamp:      time.Now(),
		ProtocolsSeen:  make(map[string]bool),
		Protocols:      make(map[string]bool),
		Metadata:       make(map[string]string),
	}

	DiscoveredHosts = append(DiscoveredHosts, newHost)
	return &DiscoveredHosts[len(DiscoveredHosts)-1]
}

// GetOrCreateHostByIP retourne un pointeur vers l’hôte correspondant à l’IP, ou le crée s’il n’existe pas
func GetOrCreateHostByIP(ip net.IP) *Host {
	for i := range DiscoveredHosts {
		if DiscoveredHosts[i].IP.Equal(ip) {
			return &DiscoveredHosts[i]
		}
	}

	newHost := Host{
		IP:             ip,
		Timestamp:      time.Now(),
		ProtocolsSeen:  make(map[string]bool),
		Protocols:      make(map[string]bool),
		Metadata:       make(map[string]string),
	}

	DiscoveredHosts = append(DiscoveredHosts, newHost)
	return &DiscoveredHosts[len(DiscoveredHosts)-1]
}

