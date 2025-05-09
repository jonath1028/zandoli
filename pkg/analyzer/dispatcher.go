package analyzer

import (
	"github.com/google/gopacket"
	"zandoli/pkg/security"

	l2 "zandoli/pkg/analyzer/layer2"
	svc "zandoli/pkg/analyzer/service"
	meta "zandoli/pkg/analyzer/meta"
)

// Liste des fonctions analyzers à appeler
var activeAnalyzers = []func(gopacket.Packet){
	security.AnalyzeTopology,

	// Layer 2
	l2.Analyze8021X,
	l2.AnalyzeEAPOL,
	l2.AnalyzeLLDP,
	l2.AnalyzeCDP,
	l2.AnalyzeSTP, // si implémenté

	// Services IP
	svc.AnalyzeDNS,
	svc.AnalyzeMDNS,
	svc.AnalyzeDHCP,
	svc.AnalyzeLLMNR,
	svc.AnalyzeNetBIOS,
	svc.AnalyzeSMB,

	// Anomalies
	meta.AnalyzeAnomalies,
}

var ActiveAnalyzers = activeAnalyzers

func HandlePacket(packet gopacket.Packet) {
	for _, analyzer := range ActiveAnalyzers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Pas de log ici pour la furtivité, ou log interne silencieux si en mode debug
				}
			}()
			analyzer(packet)
		}()
	}
}

