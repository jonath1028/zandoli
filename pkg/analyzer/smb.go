package analyzer

import (
	"bytes"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeSMB marque simplement un hôte comme utilisant SMB si un paquet TCP 445 est vu
func AnalyzeSMB(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp.DstPort != 445 && tcp.SrcPort != 445 {
		return
	}

	payload := tcp.Payload
	if len(payload) < 4 {
		return
	}

	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()
	sniffer.RegisterIP(srcIP)

	host := sniffer.FindHostByIP(net.IP(srcIP))
	if host == nil {
		return
	}

	// SMBv1 signature
	if bytes.HasPrefix(payload, []byte("\xFFSMB")) {
		host.ProtocolsSeen["SMB"] = true
		sniffer.ClassifyHost(host)
		logger.Logger.Debug().Msgf("[SMB] Detected SMBv1 from %s", srcIP)
		return
	}

	// SMBv2/3 signature
	if bytes.HasPrefix(payload, []byte("\xFE\x53\x4D\x42")) {
		host.ProtocolsSeen["SMB"] = true
		sniffer.ClassifyHost(host)
		logger.Logger.Debug().Msgf("[SMB] Detected SMBv2/v3 from %s", srcIP)
	}
}

