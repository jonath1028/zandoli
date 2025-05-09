package service

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeLLMNR détecte passivement le protocole LLMNR via le port UDP 5355
func AnalyzeLLMNR(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	if udp.SrcPort != 5355 && udp.DstPort != 5355 {
		return
	}

	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		logger.Logger.Debug().Msg("[LLMNR] No IP layer found")
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	host := sniffer.GetOrCreateHostByIP(net.IP(srcIP))
	if host == nil {
		logger.Logger.Warn().Msg("[LLMNR] Unable to create host")
		return
	}

	host.ProtocolsSeen["LLMNR"] = true
	sniffer.ClassifyHost(host)

	logger.Logger.Debug().Msgf("[LLMNR] Protocol passively detected for host %s", host.IP)
}

