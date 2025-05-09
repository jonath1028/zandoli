package offline

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/analyzer"
	"zandoli/pkg/logger"
)

// AnalyzeFromPCAP lit un fichier PCAP et transmet les paquets à analyzer.HandlePacket()
func AnalyzeFromPCAP(pcapPath string) {
	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		logger.Logger.Fatal().Err(err).Msg("Failed to open pcap file")
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	logger.Logger.Info().Msgf("Starting offline analysis on %s", pcapPath)
	start := time.Now()

	for packet := range packetSource.Packets() {
		analyzer.HandlePacket(packet)
	}

	logger.Logger.Info().Msgf("PCAP analysis completed in %v", time.Since(start))
}

