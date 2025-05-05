package analyzer

import (
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeLLMNR analyse les requêtes LLMNR (UDP 5355)
func AnalyzeLLMNR(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Vérifie le port 5355 (LLMNR)
	if udp.DstPort != 5355 && udp.SrcPort != 5355 {
		return
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// On traite uniquement les requêtes
	if dns.QR {
		return
	}

	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	for _, q := range dns.Questions {
		domain := strings.ToLower(string(q.Name))
		sniffer.UpdateHostDNS(srcIP, domain)
		sniffer.RegisterIP(srcIP)

		// Marque le protocole comme observé
		host := sniffer.FindHostByIP(net.IP(srcIP))
		if host != nil {
			host.ProtocolsSeen["LLMNR"] = true
			sniffer.ClassifyHost(host)
		}

		logger.Logger.Debug().Msgf("[LLMNR] Request for %s from %v", domain, srcIP)
	}
}

