package sniffer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/logger"
)

// CaptureARPReplies capture en arrière-plan les réponses ARP sur l'interface spécifiée.
// Ce goroutine s'arrête lorsque le canal stop est fermé.
func CaptureARPReplies(iface string, stop chan struct{}) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to open interface for ARP reply capture")
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-stop:
			logger.Logger.Debug().Msg("[ARP] Stop signal received, stopping ARP capture.")
			return

		case packet, ok := <-packets:
			if !ok {
				logger.Logger.Warn().Msg("[ARP] Packet source closed unexpectedly.")
				return
			}

			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				ip := net.IP(arp.SourceProtAddress)
				mac := net.HardwareAddr(arp.SourceHwAddress)

				if ip.String() == "0.0.0.0" || IsAlreadyKnown(ip) {
					continue
				}

				host := NewHost(ip, mac, "active")
				ClassifyHost(&host)

				logger.Logger.Debug().Msgf("[DEBUG] Active NewHost => IP=%s MAC=%s Vendor=%s Category=%s",
					host.IP, host.MACStr, host.Vendor, host.Category)

				DiscoveredHosts = append(DiscoveredHosts, host)

				go DetectMACMultipleIPs(mac, ip)

				logger.Logger.Info().Msgf("[HOST] Active response: IP=%s MAC=%s Category=%s",
					ip.String(), mac.String(), host.Category)
			}

		case <-time.After(15 * time.Second):
			logger.Logger.Warn().Msg("[ARP] Timeout: No packets received for 3s. Stopping capture.")
			return
		}
	}
}
