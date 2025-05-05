package analyzer

import (
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeDNS enrichit les hôtes en observant les requêtes DNS classiques
func AnalyzeDNS(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Ports typiques DNS
	if udp.DstPort != 53 && udp.SrcPort != 53 {
		return
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// On ne traite que les requêtes
	if dns.QR {
		return
	}

	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	for _, q := range dns.Questions {
		name := strings.ToLower(string(q.Name))
		sniffer.UpdateHostDNS(srcIP, name)
		sniffer.RegisterIP(srcIP)

		host := sniffer.FindHostByIP(net.IP(srcIP))
		if host != nil {
			host.ProtocolsSeen["DNS"] = true
			sniffer.ClassifyHost(host)
		}

		logger.Logger.Debug().Msgf("[DNS] Request for %s from %v", name, srcIP)
	}
}

