package analyzer

import (
	"net"

	"zandoli/pkg/logger"
	"zandoli/pkg/security"
)

// Internal tracking
var macToIPs = map[string][]net.IP{}

func detectMACMultipleIPs(mac net.HardwareAddr, ip net.IP) {
	macStr := mac.String()
	ips := macToIPs[macStr]

	for _, known := range ips {
		if known.Equal(ip) {
			return // déjà vu
		}
	}

	macToIPs[macStr] = append(ips, ip)

	if len(macToIPs[macStr]) > 1 {
		security.SecuritySummary.MACWithMultipleIPs[macStr] = macToIPs[macStr]
		logger.Logger.Warn().Msgf("[ANOMALY] MAC %s seen with multiple IPs: %v", macStr, macToIPs[macStr])
	}
}
