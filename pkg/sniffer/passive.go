package sniffer

import (
	"net"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
	"zandoli/pkg/security"
)

// StartPassiveSniff démarre une capture passive sur l'interface donnée pendant la durée spécifiée (en secondes).
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

				// 3. Enregistrement de l'IP source pour les paquets non ARP
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					srcIP := netLayer.NetworkFlow().Src().Raw()
					RegisterIP(srcIP)
				}

				// 4. Analyse passive des protocoles
				packetChan <- packet
			}
		}

		bar.Finish()
	}()

	return packetChan
}
