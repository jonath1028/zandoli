package layer2

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeSTP détecte passivement les trames STP/BPDU via la destination MAC multicast STP
func AnalyzeSTP(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Adresse multicast réservée STP
	if eth.DstMAC.String() != "01:80:c2:00:00:00" {
		return
	}

	// Vérifie la présence d'une couche LLC (LLC + SNAP encapsulent souvent BPDU)
	llcLayer := packet.Layer(layers.LayerTypeLLC)
	if llcLayer == nil {
		return
	}

	host := sniffer.GetOrCreateHostByMAC(eth.SrcMAC.String())
	if host == nil {
		return
	}

	host.ProtocolsSeen["stp"] = true

	logger.Logger.Debug().
		Str("mac", eth.SrcMAC.String()).
		Msg("[STP] Spanning Tree Protocol detected via LLC + multicast MAC")
}

