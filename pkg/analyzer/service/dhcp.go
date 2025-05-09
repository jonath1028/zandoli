package service

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeDHCP détecte les paquets DHCP (BOOTP) et marque les hôtes actifs
func AnalyzeDHCP(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	if udp.SrcPort != 67 && udp.SrcPort != 68 && udp.DstPort != 67 && udp.DstPort != 68 {
		return
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	host := sniffer.GetOrCreateHostByMAC(eth.SrcMAC.String())
	host.ProtocolsSeen["dhcp"] = true

	logger.Logger.Debug().
		Str("mac", eth.SrcMAC.String()).
		Msg("[DHCP] Detected DHCP traffic")
}

