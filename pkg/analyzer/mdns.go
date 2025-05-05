package analyzer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeMDNS traite les réponses mDNS pour enrichir les hôtes
func AnalyzeMDNS(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Port 5353 utilisé par mDNS
	if udp.DstPort != 5353 && udp.SrcPort != 5353 {
		return
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	if dns.QR { // Réponse mDNS
		for _, ans := range dns.Answers {
			if ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA {
				domain := string(ans.Name)
				ipLayer := packet.NetworkLayer()
				if ipLayer == nil {
					return
				}
				srcIP := ipLayer.NetworkFlow().Src().Raw()
				sniffer.UpdateHostDNS(srcIP, domain)
				sniffer.RegisterIP(srcIP)

				// Ajout du protocole mDNS
				host := sniffer.FindHostByIP(net.IP(srcIP))
				if host != nil {
					host.ProtocolsSeen["mDNS"] = true
					sniffer.ClassifyHost(host)
				}

				logger.Logger.Debug().Msgf("[mDNS] Response for %s from %v", domain, srcIP)
			}
		}
	}
}

