package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/security"
)

var eapolDetected = false

// Handle8021X inspecte les trames Ethernet pour détecter 802.1X (EAPOL)
func Handle8021X(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	if eth.EthernetType == 0x888E {
		if !eapolDetected {
			eapolDetected = true
			security.SecuritySummary.PassiveSecurity8021X = true
			logger.Logger.Info().Msg("[SECURITY] 802.1X (EAPOL) detected on this network")
		} else {
			logger.Logger.Debug().Msg("[802.1X] Additional EAPOL frame detected")
		}
	}
}

