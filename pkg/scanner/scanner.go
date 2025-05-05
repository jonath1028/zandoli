package scanner

import (
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	pb "github.com/cheggaaa/pb/v3"

	"zandoli/pkg/config"
	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
	"zandoli/pkg/sniffer"
	"zandoli/pkg/utils"
)

// ==========================
// 🔍 Standard ARP Scan
// ==========================

func ScanARP(ifaceName string) {
	_, localIP, localMAC := utils.GetInterfaceInfo(ifaceName)
	subnet := utils.GetLocalSubnet(localIP, ifaceName)

	logger.Logger.Info().Msgf("Starting active ARP scan on %s [%s]", ifaceName, subnet.String())

	stop := make(chan struct{})
	go sniffer.CaptureARPReplies(ifaceName, stop)

	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to open interface for active scan")
		return
	}
	defer handle.Close()

	total := 0
	for ip := range iterateIPs(subnet) {
		if !ip.Equal(localIP) && !sniffer.IsAlreadyKnown(ip) {
			total++
		}
	}

	bar := pb.New(total)
	bar.SetMaxWidth(60)
	bar.SetTemplate(pb.Simple)
	bar.Set("prefix", "🔍 Active Scan: ")
	bar.Start()

	for ip := range iterateIPs(subnet) {
		if ip.Equal(localIP) || sniffer.IsAlreadyKnown(ip) {
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

// ==========================
// 🕵 Stealth ARP Scan
// ==========================

func ScanARPStealth(ifaceName string) {
	logger.Logger.Info().Msg("[STEALTH] Starting stealth ARP scan...")

	// Chargement de la config
	cfg := config.StealthARP

	// Interface
	_, localIP, localMAC := utils.GetInterfaceInfo(ifaceName)
	subnet := utils.GetLocalSubnet(localIP, ifaceName)

	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to open interface for stealth scan")
		return
	}
	defer handle.Close()

	stop := make(chan struct{})
	go sniffer.CaptureARPReplies(ifaceName, stop)

	// Générer les IPs à scanner
	var allIPs []net.IP
	for ip := range iterateIPs(subnet) {
		if !ip.Equal(localIP) && !sniffer.IsAlreadyKnown(ip) {
			allIPs = append(allIPs, ip)
		}
	}
	rand.Shuffle(len(allIPs), func(i, j int) {
		allIPs[i], allIPs[j] = allIPs[j], allIPs[i]
	})

	bar := pb.New(len(allIPs))
	bar.SetMaxWidth(60)
	bar.SetTemplate(pb.Simple)
	bar.Set("prefix", "🕵 Stealth Scan: ")
	bar.Start()

	var (
		i          = 0
		timestamps []time.Time
	)

	for i < len(allIPs) {
		now := time.Now()

		// Purge des timestamps hors de la fenêtre de burst
		filtered := timestamps[:0]
		for _, t := range timestamps {
			if now.Sub(t) <= cfg.BurstWindow {
				filtered = append(filtered, t)
			}
		}
		timestamps = filtered

		// Si on dépasse la limite globale, on attend
		if len(timestamps) >= cfg.MaxPerBurst {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Burst aléatoire
		burstSize := rand.Intn(cfg.MaxPerBurst-cfg.MinPerBurst+1) + cfg.MinPerBurst
		sentInBurst := 0

		for sentInBurst < burstSize && i < len(allIPs) {
			now := time.Now()

			// Limite par seconde
			count := 0
			for _, t := range timestamps {
				if now.Sub(t) <= time.Second {
					count++
				}
			}
			if count >= cfg.MaxPerSecond {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Envoi ARP
			ip := allIPs[i]
			sendARP(handle, ip, localMAC, localIP)
			timestamps = append(timestamps, time.Now())
			bar.Increment()
			i++
			sentInBurst++

			// Jitter exponentiel
			jitter := time.Duration(rand.ExpFloat64()) * cfg.JitterMean
			time.Sleep(jitter)
		}

		if i < len(allIPs) {
			pause := cfg.BurstPauseMin + time.Duration(rand.Int63n(int64(cfg.BurstPauseMax-cfg.BurstPauseMin)))
			time.Sleep(pause)
		}
	}

	bar.Finish()
	time.Sleep(500 * time.Millisecond)
	close(stop)
	logger.Logger.Info().Msg("[STEALTH] Stealth ARP scan complete.")
}

// ==========================
// 🔧 Internal
// ==========================

func sendARP(handle *pcap.Handle, ip net.IP, mac net.HardwareAddr, localIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   mac,
		SourceProtAddress: localIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    ip.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	_ = handle.WritePacketData(buf.Bytes())
}

func iterateIPs(subnet *net.IPNet) <-chan net.IP {
	ch := make(chan net.IP)
	go func() {
		defer close(ch)
		for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); incIP(ip) {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			ch <- tmp
		}
	}()
	return ch
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

