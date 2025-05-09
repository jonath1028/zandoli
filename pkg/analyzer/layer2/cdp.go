package layer2

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

func AnalyzeCDP(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// On ne vérifie plus EthernetType
	if eth.DstMAC.String() != "01:00:0c:cc:cc:cc" {
		return
	}

	host := sniffer.GetOrCreateHostByMAC(eth.SrcMAC.String())
	if host == nil {
		return
	}

	host.ProtocolsSeen["cdp"] = true

	logger.Logger.Debug().
		Str("mac", eth.SrcMAC.String()).
		Msg("[CDP] Cisco Discovery Protocol detected (MAC match only)")
}

