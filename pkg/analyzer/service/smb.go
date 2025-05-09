package service

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeSMB détecte le trafic SMB (v1/v2/v3) même sans parsing explicite TCP
func AnalyzeSMB(packet gopacket.Packet) {
	// Utilise la couche transport pour récupérer les ports
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		// fallback : couche transport présente mais pas typée
		tport := packet.TransportLayer()
		if tport == nil {
			return
		}
		srcPort, dstPort := tport.TransportFlow().Endpoints()
		if dstPort.String() != "445" && srcPort.String() != "445" {
			return
		}

		logger.Logger.Debug().
			Str("src", srcPort.String()).
			Str("dst", dstPort.String()).
			Msg("[SMB] Detected TCP/445 (fallback path) — attempting MAC extraction")
	} else {
		if tcp.SrcPort != 445 && tcp.DstPort != 445 {
			return
		}
		logger.Logger.Debug().
			Uint16("src", uint16(tcp.SrcPort)).
			Uint16("dst", uint16(tcp.DstPort)).
			Msg("[SMB] Detected TCP/445 (standard path) — attempting MAC extraction")
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		logger.Logger.Warn().Msg("[SMB] Ethernet layer missing — skipping packet")
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	if eth.SrcMAC.String() == "" {
		logger.Logger.Warn().Msg("[SMB] MAC address empty — skipping packet")
		return
	}

	host := sniffer.GetOrCreateHostByMAC(eth.SrcMAC.String())
	if host == nil {
		logger.Logger.Warn().Str("mac", eth.SrcMAC.String()).Msg("[SMB] Failed to associate host")
		return
	}

	host.ProtocolsSeen["smb"] = true

	logger.Logger.Debug().
		Str("mac", eth.SrcMAC.String()).
		Msg("[SMB] SMB traffic tagged to host")
}

