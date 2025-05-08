package analyzer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

func AnalyzeLLMNR(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	if udp.SrcPort != 5355 && udp.DstPort != 5355 {
		return
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)

	if !dns.QR {
		return
	}

	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		logger.Logger.Debug().Msg("[LLMNR] No IP layer found")
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	host := sniffer.FindHostByIP(net.IP(srcIP))
	if host == nil {
		logger.Logger.Debug().Msg("[LLMNR] Host not found")
		return
	}

	host.ProtocolsSeen["LLMNR"] = true
	sniffer.ClassifyHost(host)
	logger.Logger.Debug().Msgf("[LLMNR] Protocol detected for host %s", host.IP)
}

