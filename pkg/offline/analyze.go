package offline

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/logger"
)

// AnalyzeFromPCAP analyse un fichier .pcap en appelant les analyzers sur chaque paquet
func AnalyzePCAPWithDiagnostics(path string) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		logger.Logger.Fatal().Err(err).Msgf("Failed to open PCAP file: %s", path)
	}

	logger.Logger.Info().Msgf("Starting offline analysis on %s", path)
	logger.Logger.Debug().Msgf("PCAP snaplen: %d bytes", handle.SnapLen())

	if handle.SnapLen() < 200 {
		logger.Logger.Warn().
			Int("snaplen", handle.SnapLen()).
			Msg("⚠️ PCAP file was likely captured with a too-small snaplen. Some protocols may not be detected correctly.")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	start := time.Now()

	for packet := range packetSource.Packets() {
		analyzer.HandlePacket(packet)
	}

	duration := time.Since(start)
	logger.Logger.Info().Msgf("PCAP analysis completed in %s", duration)
}

