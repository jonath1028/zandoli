package service

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

func AnalyzeMDNS(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	if udp.SrcPort != 5353 && udp.DstPort != 5353 {
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
		logger.Logger.Debug().Msg("[mDNS] No IP layer found")
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	host := sniffer.FindHostByIP(net.IP(srcIP))
	if host == nil {
		logger.Logger.Debug().Msg("[mDNS] Host not found")
		return
	}

	host.ProtocolsSeen["mDNS"] = true
	sniffer.ClassifyHost(host)
	logger.Logger.Debug().Msgf("[mDNS] Protocol detected for host %s", host.IP)
}
