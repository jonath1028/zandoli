package analyzer

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

// AnalyzeSMB tente d'extraire des noms via le protocole SMB (TCP 445)
func AnalyzeSMB(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Port SMB direct
	if tcp.DstPort != 445 && tcp.SrcPort != 445 {
		return
	}

	// Analyse du payload brut
	payload := tcp.Payload
	if len(payload) < 100 {
		return
	}

	// Recherche d'une chaîne Unicode potentielle
	if name := extractSMBHostname(payload); name != "" {
		ipLayer := packet.NetworkLayer()
		if ipLayer == nil {
			return
		}
		srcIP := ipLayer.NetworkFlow().Src().Raw()
		sniffer.UpdateHostDNS(srcIP, name)
		sniffer.RegisterIP(srcIP)

		// Ajout du protocole SMB
		host := sniffer.FindHostByIP(net.IP(srcIP))
		if host != nil {
			host.ProtocolsSeen["SMB"] = true
			sniffer.ClassifyHost(host)
		}

		logger.Logger.Debug().Msgf("[SMB] Hostname from SMB: %s (%v)", name, srcIP)
	}
}

// extractSMBHostname tente d’extraire une chaîne Unicode plausible
func extractSMBHostname(data []byte) string {
	// Recherche naïve d’un pattern Unicode (UCS2)
	for i := 0; i < len(data)-32; i++ {
		sub := data[i : i+32]
		utf16 := make([]uint16, 16)
		for j := 0; j < 16; j++ {
			utf16[j] = binary.LittleEndian.Uint16(sub[j*2 : j*2+2])
		}
		str := decodeUTF16(utf16)
		if isValidSMBName(str) {
			return str
		}
	}
	return ""
}

// decodeUTF16 décode une suite UCS2 vers string
func decodeUTF16(utf16 []uint16) string {
	var buf bytes.Buffer
	for _, r := range utf16 {
		if r == 0 {
			break
		}
		buf.WriteRune(rune(r))
	}
	return buf.String()
}

// isValidSMBName applique des heuristiques simples (longueur, printable, etc.)
func isValidSMBName(s string) bool {
	if len(s) < 3 || len(s) > 15 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return r < 32 || r > 126
	}) == -1
}

