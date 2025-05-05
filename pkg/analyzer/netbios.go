package analyzer

import (
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeNetBIOS extrait les noms NetBIOS des requêtes/réponses UDP 137
func AnalyzeNetBIOS(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.SrcPort != 137 && udp.DstPort != 137 {
		return
	}

	payload := udp.Payload
	if len(payload) < 57 {
		return
	}

	// Nom NetBIOS : commence à l'octet 13 sur 32 octets
	nameBytes := payload[13 : 13+32]
	name := decodeNetBIOSName(nameBytes)

	// Adresse IP source
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}
	srcIP := ipLayer.NetworkFlow().Src().Raw()

	sniffer.UpdateHostDNS(srcIP, name)
	sniffer.RegisterIP(srcIP)

	// Ajout du protocole NetBIOS et classification
	host := sniffer.FindHostByIP(net.IP(srcIP))
	if host != nil {
		host.ProtocolsSeen["NetBIOS"] = true
		sniffer.ClassifyHost(host)
	}

	logger.Logger.Debug().Msgf("[NetBIOS] Passive hostname: %s from %v", name, srcIP)
}

// decodeNetBIOSName convertit un nom encodé NetBIOS vers une chaîne lisible
func decodeNetBIOSName(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	decoded := make([]byte, 16)
	for i := 0; i < 16; i++ {
		c1 := data[2*i] - 'A'
		c2 := data[2*i+1] - 'A'
		decoded[i] = (c1 << 4) | c2
	}
	trimmed := strings.TrimRight(string(decoded), "\x00 ")
	return trimmed
}

