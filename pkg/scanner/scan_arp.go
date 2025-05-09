package scanner

import (
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/config"
	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
	"zandoli/pkg/sniffer"
	"zandoli/pkg/utils"
)

// ScanARP performs a standard ARP scan on the given interface
func ScanARP(ifaceName string) {
	// Retrieve interface info and local subnet
	_, localIP, localMAC := utils.GetInterfaceInfo(ifaceName)
	subnet := utils.GetLocalSubnet(localIP, ifaceName)

	logger.Logger.Info().Msgf("Starting active ARP scan on %s [%s]", ifaceName, subnet.String())

	// Start capturing ARP replies in background
	stop := make(chan struct{})
	go sniffer.CaptureARPReplies(ifaceName, stop)

	// Open interface for sending ARP requests
	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to open interface for active scan")
		return
	}
	defer handle.Close()

	// Prepare list of target IPs (exclude local and already known)
	targets := gatherTargets(subnet, localIP)

	// Initialize progress bar
	bar := pb.New(len(targets))
	bar.SetMaxWidth(60)
	bar.SetTemplate(pb.Simple)
	bar.Set("prefix", "🔍 Active Scan: ")
	bar.Start()

	// Send ARP requests to each target
	for _, ip := range targets {
		if config.IsExcludedIP(ip) {
			logger.Logger.Debug().Msgf("[EXCLUDED] Skipping IP %s (blacklisted subnet)", ip)
			bar.Increment()
			continue
		}

		mac := utils.GetMACFromARP(ip, handle, localMAC, localIP)
		if mac == nil || sniffer.IsMACKnown(mac) {
			logger.Logger.Debug().Msgf("[SKIP] MAC already seen passively or nil: %s (IP %s)", mac, ip)
			bar.Increment()
			continue
		}
		if oui.IsFiltered(mac.String()) {
			logger.Logger.Debug().Msgf("[FILTER] Skipping IP %s (MAC: %s)", ip, mac)
			bar.Increment()
			continue
		}

		sendARP(handle, ip, localMAC, localIP)
		bar.Increment()
		time.Sleep(10 * time.Millisecond)
	}

	bar.Finish()
	logger.Logger.Info().Msg("[ARP] Waiting briefly for final responses...")
	time.Sleep(1 * time.Second)
	close(stop)
	logger.Logger.Info().Msg("Active ARP scan complete")
}
