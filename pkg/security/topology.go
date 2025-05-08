package security

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
)

// TopologyProtocols stocke les détections passives de protocoles de topologie
type TopologyProtocols struct {
	LLDP bool `json:"lldp"`
	CDP  bool `json:"cdp"`
	STP  bool `json:"stp"`
}

// Exporté globalement pour être accessible
var Topology = TopologyProtocols{}

// AnalyzeTopology inspecte les trames Ethernet pour LLDP, CDP, STP
func AnalyzeTopology(pkt gopacket.Packet) {
	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		ether := eth.(*layers.Ethernet)

		switch ether.EthernetType {
		case 0x88cc: // LLDP
			if !Topology.LLDP {
				Topology.LLDP = true
				logger.Logger.Info().Msg("[TOPO] LLDP detected on the wire")
			}
		case 0x2000: // CDP
			if !Topology.CDP {
				Topology.CDP = true
				logger.Logger.Info().Msg("[TOPO] CDP detected on the wire")
			}
		default:
			// STP: destination MAC 01:80:c2:00:00:00, LLC header (DSAP=0x42)
			if ether.DstMAC.String() == "01:80:c2:00:00:00" {
				if !Topology.STP {
					Topology.STP = true
					logger.Logger.Info().Msg("[TOPO] STP detected on the wire")
				}
			}
		}
	}
}
