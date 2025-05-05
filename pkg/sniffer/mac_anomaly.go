package sniffer

import (
	"net"
	"zandoli/pkg/logger"
	"zandoli/pkg/security"
)

var macToIPs = map[string][]net.IP{}
var ipToMACs = map[string][]net.HardwareAddr{}

func DetectMACMultipleIPs(mac net.HardwareAddr, ip net.IP) {
	macStr := mac.String()
	ips := macToIPs[macStr]

	for _, known := range ips {
		if known.Equal(ip) {
			return
		}
	}

	macToIPs[macStr] = append(ips, ip)

	if len(macToIPs[macStr]) > 1 {
		security.SecuritySummary.MACWithMultipleIPs[macStr] = macToIPs[macStr]
		logger.Logger.Warn().Msgf("[ANOMALY] MAC %s seen with multiple IPs: %v", macStr, macToIPs[macStr])
	}
}

func DetectIPWithMultipleMACs(ip net.IP, mac net.HardwareAddr) {
	ipStr := ip.String()
	macs := ipToMACs[ipStr]

	for _, known := range macs {
		if known.String() == mac.String() {
			return
		}
	}

	ipToMACs[ipStr] = append(macs, mac)

	if len(ipToMACs[ipStr]) > 1 {
		security.SecuritySummary.IPWithMultipleMACs[ipStr] = ipToMACs[ipStr]
		logger.Logger.Warn().Msgf("[ANOMALY] IP %s seen with multiple MACs: %v", ipStr, ipToMACs[ipStr])
	}
}
