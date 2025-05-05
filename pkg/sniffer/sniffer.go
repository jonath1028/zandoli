package sniffer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	pb "github.com/cheggaaa/pb/v3"

	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
	"zandoli/pkg/security"
)

var DiscoveredHosts []Host

// ==================== Passive Sniffing ====================

func StartPassiveSniff(iface string, duration int) <-chan gopacket.Packet {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		logger.Logger.Fatal().Err(err).Msg("Failed to open interface for sniffing")
	}

	logger.Logger.Info().Msgf("Starting passive ARP sniffing on %s (%d seconds)", iface, duration)

	packetChan := make(chan gopacket.Packet)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	rawPackets := packetSource.Packets()

	// Progress bar over time
	bar := pb.New(duration).SetTemplate(pb.Simple)
	bar.SetMaxWidth(60)
	bar.Set("prefix", "⏳ Passive Capture: ")
	bar.Start()

	go func() {
		defer close(packetChan)
		defer handle.Close()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		timeout := time.After(time.Duration(duration) * time.Second)

	loop:
		for {
			select {
			case <-timeout:
				logger.Logger.Info().Msg("Passive sniffing complete")
				break loop

			case <-ticker.C:
				bar.Increment()

			case packet, ok := <-rawPackets:
				if !ok {
					break loop
				}

				// 1. Analyse topologie réseau (LLDP, CDP, STP)
				go security.AnalyzeTopology(packet)

				// 2. Découverte ARP
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					ip := net.IP(arp.SourceProtAddress)
					mac := net.HardwareAddr(arp.SourceHwAddress)

					if ip.String() == "0.0.0.0" || oui.IsFiltered(mac.String()) || IsAlreadyKnown(ip) {
						continue
					}

					host := NewHost(ip, mac, "passive")
					ClassifyHost(&host)
					DiscoveredHosts = append(DiscoveredHosts, host)

					go DetectMACMultipleIPs(mac, ip)
					logger.Logger.Info().Msgf("[HOST] New device detected: IP=%s MAC=%s Category=%s", ip.String(), mac.String(), host.Category)
				}

				// 3. Analyse passive des protocoles
				packetChan <- packet
			}
		}

		bar.Finish()
	}()

	return packetChan
}

// ==================== Active ARP Capture ====================

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

// ==================== Shared ====================

func IsAlreadyKnown(ip net.IP) bool {
	for _, h := range DiscoveredHosts {
		if h.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func IsMACKnown(mac net.HardwareAddr) bool {
	for _, h := range DiscoveredHosts {
		if h.MAC.String() == mac.String() {
			return true
		}
	}
	return false
}

