// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/ui"
)

func ScanARPWithTargets(ctx context.Context, cfg *config.Config, log *logger.Logger, targets []net.IP) []*model.Host {
	log.Info().Int("targets", len(targets)).Msg("→ ScanARPWithTargets() started")

	var (
		hosts    []*model.Host
		mu       sync.Mutex
		seen     = make(map[string]bool)
		progress func(int)
	)

	var wg sync.WaitGroup
	var progressCount int32

	if len(targets) == 0 {
		log.Warn().Msg("No targets provided for targeted ARP scan")
		return hosts
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network interface")
		return hosts
	}

	handle, err := pcap.OpenLive(cfg.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open PCAP handle")
		return hosts
	}
	defer handle.Close()

	// Use the provided targets instead of generating all IPs in the /24
	// Filter blacklisted IPs
	var filteredTargets []net.IP
	for _, target := range targets {
		if !IsBlacklisted(target, cfg.Scan.Blacklist) {
			filteredTargets = append(filteredTargets, target)
		} else {
			log.Debug().Str("ip", target.String()).Msg("Target IP is blacklisted, skipping")
		}
	}

	ips := make([]net.IP, len(filteredTargets))
	copy(ips, filteredTargets)
	shuffleIPs(ips)

	if cfg.Mode.ActiveLike() && !cfg.Logging.Paranoid && !cfg.Logging.Quiet {
		progress = ui.PrintProgressBar("Targeted ARP Scan", len(ips), "progress", "?", 50*time.Millisecond)
	}

	maxPerSecond := safeRandInRange(cfg.Scan.Stealth.MaxPerSecondMin, cfg.Scan.Stealth.MaxPerSecondMax)
	// Apply the arp_max_per_sec cap if set
	if cfg.Scan.ARP.MaxPerSec > 0 && maxPerSecond > cfg.Scan.ARP.MaxPerSec {
		maxPerSecond = cfg.Scan.ARP.MaxPerSec
	}
	maxBurst := safeRandInRange(cfg.Scan.Stealth.MaxBurstPerWindowMin, cfg.Scan.Stealth.MaxBurstPerWindowMax)
	windowSecs := safeRandInRange(cfg.Scan.Stealth.BurstWindowSecondsMin, cfg.Scan.Stealth.BurstWindowSecondsMax)
	microburstMin := cfg.Scan.Stealth.MicroburstMin
	microburstMax := cfg.Scan.Stealth.MicroburstMax
	pauseMin := cfg.Scan.Stealth.PauseMinMs
	pauseMax := cfg.Scan.Stealth.PauseMaxMs

	if maxPerSecond <= 0 || maxBurst <= 0 || windowSecs <= 0 {
		log.Error().Msg("Invalid stealth config: maxPerSecond, maxBurst and windowSecs must be > 0")
		return hosts
	}

	tokens := make(chan struct{}, maxBurst)
	burstWindow := time.Duration(windowSecs) * time.Second

	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(maxPerSecond))
		defer ticker.Stop()
		for range ticker.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(burstWindow)
		defer ticker.Stop()
		for range ticker.C {
			drainChannel(tokens)
			// Apply the inter-burst delay from config
			if cfg.Scan.ARP.BurstMinDelayMs > 0 || cfg.Scan.ARP.BurstMaxDelayMs > 0 {
				delay := safeRandInRange(cfg.Scan.ARP.BurstMinDelayMs, cfg.Scan.ARP.BurstMaxDelayMs)
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
		}
	}()

	results := make(chan ARPResult, 256)
	ctxListen, cancel := context.WithCancel(ctx)
	defer cancel()
	go StartARPListener(ctxListen, handle, results)

	sem := make(chan struct{}, cfg.Scan.ARP.Burst)

	i := 0
	for i < len(ips) {
		burstSize := rand.Intn(microburstMax-microburstMin+1) + microburstMin
		end := i + burstSize
		if end > len(ips) {
			end = len(ips)
		}

		for j := i; j < end; j++ {
			ip := ips[j]

			select {
			case <-ctx.Done():
				log.Warn().Msg("Targeted ARP scan interrupted")
				return hosts
			case <-tokens:
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(ip net.IP) {
				defer func() {
					if r := recover(); r != nil {
						log.Error().Str("ip", ip.String()).Msgf("PANIC recovered in ARP scan: %v", r)
					}
					wg.Done()
					<-sem
				}()

				sendARPRequest(handle, iface, ip)

				if progress != nil {
					current := atomic.AddInt32(&progressCount, 1)
					progress(int(current))
				}
			}(ip)
		}

		pause := safeRandInRange(pauseMin, pauseMax)
		time.Sleep(time.Duration(pause) * time.Millisecond)
		i = end
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	cancel()

	for r := range results {
		// Check if the response IP is blacklisted
		if IsBlacklisted(r.IP, cfg.Scan.Blacklist) {
			log.Debug().Str("ip", r.IP.String()).Msg("ARP response from blacklisted IP, ignoring")
			continue
		}

		mu.Lock()
		ipStr := r.IP.String()
		if !seen[ipStr] {
			seen[ipStr] = true
			now := time.Now()
			host := &model.Host{
				IP:        r.IP,
				MAC:       r.MAC,
				MACStr:    r.MAC.String(),
				FirstSeen: now,
				LastSeen:  now,
				Source:    "active",
				OnlyARP:   true,
			}
			hosts = append(hosts, host)
		}
		mu.Unlock()
	}

	log.Info().Int("discovered", len(hosts)).Msg("→ Targeted ARP scan completed")
	return hosts
}

func ScanARP(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host {
	log.Info().Msg("→ ScanARP() started")

	var (
		hosts    []*model.Host
		mu       sync.Mutex
		seen     = make(map[string]bool)
		progress func(int)
	)

	var wg sync.WaitGroup
	var progressCount int32

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network interface")
		return hosts
	}

	handle, err := pcap.OpenLive(cfg.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open PCAP handle")
		return hosts
	}
	defer handle.Close()

	_, ipnet, err := getInterfaceIPNet(cfg.Interface)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get IP and subnet")
		return hosts
	}

	allIPs := getAllIPsInSubnet(ipnet)

	// Filter blacklisted IPs
	var filteredIPs []net.IP
	for _, ip := range allIPs {
		if !IsBlacklisted(ip, cfg.Scan.Blacklist) {
			filteredIPs = append(filteredIPs, ip)
		} else {
			log.Debug().Str("ip", ip.String()).Msg("IP is blacklisted, skipping")
		}
	}

	ips := make([]net.IP, len(filteredIPs))
	copy(ips, filteredIPs)
	shuffleIPs(ips)

	if cfg.Mode.ActiveLike() && !cfg.Logging.Paranoid && !cfg.Logging.Quiet {
		progress = ui.PrintProgressBar("ARP Scan", len(ips), "progress", "?", 50*time.Millisecond)
	}

	maxPerSecond := safeRandInRange(cfg.Scan.Stealth.MaxPerSecondMin, cfg.Scan.Stealth.MaxPerSecondMax)
	// Apply the arp_max_per_sec cap if set
	if cfg.Scan.ARP.MaxPerSec > 0 && maxPerSecond > cfg.Scan.ARP.MaxPerSec {
		maxPerSecond = cfg.Scan.ARP.MaxPerSec
	}
	maxBurst := safeRandInRange(cfg.Scan.Stealth.MaxBurstPerWindowMin, cfg.Scan.Stealth.MaxBurstPerWindowMax)
	windowSecs := safeRandInRange(cfg.Scan.Stealth.BurstWindowSecondsMin, cfg.Scan.Stealth.BurstWindowSecondsMax)
	microburstMin := cfg.Scan.Stealth.MicroburstMin
	microburstMax := cfg.Scan.Stealth.MicroburstMax
	pauseMin := cfg.Scan.Stealth.PauseMinMs
	pauseMax := cfg.Scan.Stealth.PauseMaxMs

	if maxPerSecond <= 0 || maxBurst <= 0 || windowSecs <= 0 {
		log.Error().Msg("Invalid stealth config: maxPerSecond, maxBurst and windowSecs must be > 0")
		return hosts
	}

	tokens := make(chan struct{}, maxBurst)
	burstWindow := time.Duration(windowSecs) * time.Second

	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(maxPerSecond))
		defer ticker.Stop()
		for range ticker.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(burstWindow)
		defer ticker.Stop()
		for range ticker.C {
			drainChannel(tokens)
			// Apply the inter-burst delay from config
			if cfg.Scan.ARP.BurstMinDelayMs > 0 || cfg.Scan.ARP.BurstMaxDelayMs > 0 {
				delay := safeRandInRange(cfg.Scan.ARP.BurstMinDelayMs, cfg.Scan.ARP.BurstMaxDelayMs)
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
		}
	}()

	results := make(chan ARPResult, 256)
	ctxListen, cancel := context.WithCancel(ctx)
	defer cancel()
	go StartARPListener(ctxListen, handle, results)

	sem := make(chan struct{}, cfg.Scan.ARP.Burst)

	i := 0
	for i < len(ips) {
		burstSize := rand.Intn(microburstMax-microburstMin+1) + microburstMin
		end := i + burstSize
		if end > len(ips) {
			end = len(ips)
		}

		for j := i; j < end; j++ {
			ip := ips[j]

			select {
			case <-ctx.Done():
				log.Warn().Msg("Scan interrupted")
				return hosts
			case <-tokens:
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(ip net.IP) {
				defer func() {
					if r := recover(); r != nil {
						log.Error().Str("ip", ip.String()).Msgf("PANIC recovered in ARP scan: %v", r)
					}
					wg.Done()
					<-sem
				}()

				sendARPRequest(handle, iface, ip)

				if progress != nil {
					current := atomic.AddInt32(&progressCount, 1)
					progress(int(current))
				}
			}(ip)
		}

		pause := safeRandInRange(pauseMin, pauseMax)
		time.Sleep(time.Duration(pause) * time.Millisecond)
		i = end
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	cancel()

	for r := range results {
		// Check if the response IP is blacklisted
		if IsBlacklisted(r.IP, cfg.Scan.Blacklist) {
			log.Debug().Str("ip", r.IP.String()).Msg("ARP response from blacklisted IP, ignoring")
			continue
		}

		mu.Lock()
		ipStr := r.IP.String()
		if !seen[ipStr] {
			seen[ipStr] = true
			now := time.Now()
			host := &model.Host{
				IP:        r.IP,
				MAC:       r.MAC,
				MACStr:    r.MAC.String(),
				FirstSeen: now,
				LastSeen:  now,
				Source:    "active",
				OnlyARP:   true,
			}
			hosts = append(hosts, host)
		}
		mu.Unlock()
	}

	return hosts
}

func drainChannel(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func getInterfaceIPNet(name string) (net.IP, *net.IPNet, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, ipnet, nil
		}
	}

	return nil, nil, err
}

func getAllIPsInSubnet(ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	ip := ipnet.IP.Mask(ipnet.Mask)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return []net.IP{}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func shuffleIPs(ips []net.IP) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ips), func(i, j int) {
		ips[i], ips[j] = ips[j], ips[i]
	})
}

func sendARPRequest(handle *pcap.Handle, iface *net.Interface, dstIP net.IP) {
	srcIP, _, err := getInterfaceIPNet(iface.Name)
	if err != nil {
		return
	}

	ether := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, ether, arp); err != nil {
		return
	}

	_ = handle.WritePacketData(buf.Bytes())
}

func safeRandInRange(min, max int) int {
	if max <= min {
		return min
	}
	return rand.Intn(max-min+1) + min
}
