package sniffer

import "net"

var DiscoveredHosts []Host

// IsAlreadyKnown retourne true si l'IP donnée correspond à un hôte déjà découvert
func IsAlreadyKnown(ip net.IP) bool {
	return FindHostByIP(ip) != nil
}

// IsMACKnown retourne true si l'adresse MAC donnée est déjà présente parmi les hôtes découverts
func IsMACKnown(mac net.HardwareAddr) bool {
	macStr := mac.String()
	for _, h := range DiscoveredHosts {
		if h.MACStr == macStr {
			return true
		}
	}
	return false
}
