package layer2

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// Analyze8021X détecte les trames EAPOL (802.1X) sur le réseau
func Analyze8021X(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	eth := ethLayer.(*layers.Ethernet)
	if eth.EthernetType != layers.EthernetTypeEAPOL {
		return
	}

	srcMAC := eth.SrcMAC.String()
	host := sniffer.GetOrCreateHostByMAC(srcMAC)
	host.ProtocolsSeen["eapol"] = true

	logger.Logger.Debug().
		Str("src_mac", srcMAC).
		Msg("[802.1X] Detected EAPOL traffic")
}

