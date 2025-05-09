package meta

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// === Données internes
var macToIPs = map[string][]net.IP{}

// === Détection d'anomalies IP/MAC
func detectMACMultipleIPs(mac net.HardwareAddr, ip net.IP) {
	macStr := mac.String()
	ips := macToIPs[macStr]

	for _, known := range ips {
		if known.Equal(ip) {
			return
		}
	}

	macToIPs[macStr] = append(ips, ip)

	if len(macToIPs[macStr]) > 1 {
		// Ici tu peux réactiver logger ou security si nécessaire
		// logger.Logger.Warn().Msgf("[ANOMALY] MAC %s seen with multiple IPs: %v", macStr, macToIPs[macStr])
		// security.SecuritySummary.MACWithMultipleIPs[macStr] = macToIPs[macStr]
	}
}

// === Point d’entrée utilisé par le dispatcher
func AnalyzeAnomalies(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.NetworkLayer()

	if ethLayer == nil || ipLayer == nil {
		return
	}

	eth := ethLayer.(*layers.Ethernet)
	ip := ipLayer.NetworkFlow().Src().Raw()

	detectMACMultipleIPs(eth.SrcMAC, net.IP(ip))
}

