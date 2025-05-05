package analyzer

import (
	"github.com/google/gopacket"

	"zandoli/pkg/security"
)

// Liste des fonctions analyzers à appeler
var activeAnalyzers = []func(gopacket.Packet){
	security.AnalyzeTopology,
	AnalyzeDNS,
	AnalyzeMDNS,
	AnalyzeDHCP,
	AnalyzeSMB,
	AnalyzeEAPOL,
	Handle8021X,
}


// HandlePacket appelle tous les analyzers sur le paquet
func HandlePacket(packet gopacket.Packet) {
	for _, analyzer := range activeAnalyzers {
		analyzer(packet)
	}
}

