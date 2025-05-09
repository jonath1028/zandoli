package layer2

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

func AnalyzeLLDP(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Vérifie l'ethertype LLDP
	if eth.EthernetType != 0x88cc {
		return
	}

	// Création ou récupération de l'hôte
	host := sniffer.GetOrCreateHostByMAC(eth.SrcMAC.String())
	if host == nil {
		return
	}

	host.ProtocolsSeen["lldp"] = true
	logger.Logger.Debug().Str("mac", eth.SrcMAC.String()).Msg("[LLDP] Protocol detected")
}

