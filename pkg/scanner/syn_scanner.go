// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/model"
	"zandoli/pkg/ui"
)

// ScanSYNFromPipeline is used in the combined mode after filtering
func ScanSYNFromPipeline(ctx context.Context, cfg *config.Config, targets []*model.Host, log *logger.Logger) []*model.Host {
	return scanSYNInternal(ctx, cfg, targets, log)
}

// ScanSYNFromActive is used after ARP discovery in active mode
func ScanSYNFromActive(ctx context.Context, cfg *config.Config, log *logger.Logger, targets []*model.Host) []*model.Host {
	return scanSYNInternal(ctx, cfg, targets, log)
}

// scanSYNInternal performs a SYN scan on the given targets.
func scanSYNInternal(ctx context.Context, cfg *config.Config, hosts []*model.Host, log *logger.Logger) []*model.Host {
	if len(cfg.Scan.SYNPorts) == 0 {
		log.Warn().Msg("No SYN ports defined. Skipping SYN scan.")
		return hosts
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get interface")
		return hosts
	}

	srcIP := getInterfaceIPv4(cfg.Interface)
	if srcIP == nil {
		log.Error().Msg("Could not determine source IP")
		return hosts
	}

	log.Info().Int("hosts", len(hosts)).Int("ports", len(cfg.Scan.SYNPorts)).Msg("Starting SYN scan")
	var wg sync.WaitGroup
	var counter int64 = 0
	sem := make(chan struct{}, cfg.Scan.ARP.Burst)

	// Build the complete list of (host, port) targets
	type synTarget struct {
		host *model.Host
		port int
	}
	var targets []synTarget
	for _, h := range hosts {
		if isBlacklisted(h.IP.String(), cfg.Scan.Blacklist) {
			log.Debug().Str("ip", h.IP.String()).Msg("IP is blacklisted, skipping")
			continue
		}
		for _, port := range cfg.Scan.SYNPorts {
			targets = append(targets, synTarget{host: h, port: port})
		}
	}

	// Burst system configuration
	// TODO: Replace with generic stealth analyzer system
	microburstMin := cfg.Scan.SYN.MicroburstMin
	microburstMax := cfg.Scan.SYN.MicroburstMax
	pauseMin := cfg.Scan.SYN.PauseMinMs
	pauseMax := cfg.Scan.SYN.PauseMaxMs
	if microburstMin <= 0 {
		microburstMin = 1
	}
	if microburstMax < microburstMin {
		microburstMax = microburstMin
	}

	// Randomization pattern (anti-sequential)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})

	// Progress bar initialization
	var progress func(int)
	var progressCount int32
	if !cfg.Logging.Quiet && len(targets) > 0 {
		progress = ui.PrintProgressBar("SYN Scan", len(targets), "progress", "?", 50*time.Millisecond)
		defer func() {
			if progress != nil {
				progress(len(targets))
				fmt.Println()
			}
		}()
	}

	i := 0
	for i < len(targets) {
		burstSize := safeRandInRange(microburstMin, microburstMax)
		end := i + burstSize
		if end > len(targets) {
			end = len(targets)
		}

		for j := i; j < end; j++ {
			t := targets[j]

			select {
			case <-ctx.Done():
				log.Warn().Msg("SYN scan cancelled")
				goto waitAndReturn
			default:
			}

			// Add jitter BEFORE acquiring the semaphore to spread out the burst organically
			time.Sleep(randomJitter(cfg))

			wg.Add(1)
			counter++
			sem <- struct{}{}
			log.Debug().Str("ip", t.host.IP.String()).Int("port", t.port).Int64("goroutine", counter).Msg("Launching goroutine")

			go func(host *model.Host, p int, id int64) {
				log.Debug().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msg("→ [DEBUG] Goroutine started")

				defer func() {
					if r := recover(); r != nil {
						log.Error().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msgf("PANIC recovered: %v", r)
					}
					
					if progress != nil {
						current := atomic.AddInt32(&progressCount, 1)
						progress(int(current))
					}

					<-sem
					wg.Done()
					log.Debug().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msg("→ [DEBUG] Goroutine completed")
				}()

				open, ttl, win, opts, err := sendSYNProbe(ctx, log, iface, srcIP, host.IP, p, cfg.Scan.SYN.TimeoutMs, cfg.Scan.TTL)
				if err != nil {
					log.Debug().Err(err).Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msg("→ [DEBUG] SYN scan error")
					return
				}

				log.Debug().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Bool("open", open).Msg("→ [DEBUG] Scan result returned")

				if open {
					log.Debug().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msg("Port detected OPEN")
					host.AddPort(p)

					// Store parameters for OS fingerprinting
					if ttl > 0 {
						host.TTL = ttl
						if host.TTLAvg == 0 {
							host.TTLAvg = uint8(ttl)
						} else {
							// Simple moyenne glissante
							host.TTLAvg = (host.TTLAvg + uint8(ttl)) / 2
						}
					}
					if win > 0 {
						host.WindowSize = win
					}
					if len(opts) > 0 {
						host.TCPOpts = opts
					}

					// Parse TCP options for consolidation
					tcpOptions := parseTCPOptionsFromStrings(opts)
					order := extractOrderFromTCPOptions(opts)

					// Add to TCP consolidator for grouping by 5-tuple
					analyzer.AddSYNToConsolidator(
						host.IP,
						uint16(rand.Intn(65535-1024)+1024), // Random source port
						host.IP,
						uint16(p),
						6, // TCP protocol
						ttl,
						win,
						tcpOptions,
						order,
					)

					// Get consolidated TCP options
					consolidatedOptions := analyzer.GetConsolidatedTCPOptions(host.IP)
					finalOptions := tcpOptions
					if consolidatedOptions != nil {
						finalOptions = consolidatedOptions
					}

					// Perform OS fingerprinting with consolidated options
					if ttl > 0 && win > 0 {
						// Update host with consolidated TCP options first
						if finalOptions != nil {
							host.TCPOptions = finalOptions
						}

						// Use weighted OS detection
						osResult := analyzer.GuessOSWeighted(host)
						// ONLY overwrite if the new score is better, or if the current guess is empty/Unknown
						if uint8(osResult.Score) >= host.OSScore || host.OSGuess == "" || host.OSGuess == "Unknown" {
							if osResult.Family != "Unknown" || host.OSGuess == "" {
								host.OSGuess = osResult.Family
							}
							host.OSScore = uint8(osResult.Score)
							if len(osResult.Signals) > 0 {
								host.OSSignals = osResult.Signals
							}
						}

						log.Debug().Str("ip", host.IP.String()).Str("os", osResult.Family).Int("score", osResult.Score).Strs("signals", osResult.Signals).Msg("Weighted OS fingerprinting completed")
					}

					// Upgrade the role to "server" for certain ports
					if contains([]int{80, 443, 445, 3389, 22, 25, 110, 143}, p) {
						host.Role = analyzer.MergeRole(host.Role, "server")
					}

					now := time.Now()
					if host.FirstSeen.IsZero() {
						host.FirstSeen = now
					}
					host.LastSeen = now
				} else {
					log.Debug().Str("ip", host.IP.String()).Int("port", p).Int64("goroutine", id).Msg("Port closed or filtered")
				}
			}(t.host, t.port, counter)
		}

		// Pour garantir que les envois se font REELLEMENT en salves distinctes
		// we must wait for the current burst to be fully sent
		// ou au moins on bloque le thread principal selon la pause requise
		if pauseMin > 0 || pauseMax > 0 {
			pause := safeRandInRange(pauseMin, pauseMax)
			time.Sleep(time.Duration(pause) * time.Millisecond)
		}
		
		i = end
	}

waitAndReturn:
	log.Info().Msg("Waiting for all goroutines to complete")
	wg.Wait()
	log.Info().Msg("SYN scan completed (no lock)")
	return hosts
}

// sendSYNProbe sends a SYN and waits for SYN/ACK using BPF on a dedicated handle.
// Returns open status, TTL, Window Size, and TCP options for OS fingerprinting.
func sendSYNProbe(ctx context.Context, log *logger.Logger, iface *net.Interface, srcIP, dstIP net.IP, dstPort int, timeoutMs int, ttlValue int) (bool, int, int, []string, error) {
	log.Debug().Msgf("→ [DEBUG] Entered sendSYNProbe for %s:%d", dstIP.String(), dstPort)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, 10*time.Millisecond)
	if err != nil {
		log.Debug().Err(err).Msg("→ [DEBUG] Failed to open pcap handle")
		return false, 0, 0, nil, err
	}
	defer handle.Close()

	srcPort := layers.TCPPort(rand.Intn(65535-1024) + 1024)

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      uint8(ttlValue),
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Seq:     rand.Uint32(),
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp); err != nil {
		log.Debug().Err(err).Msg("→ [DEBUG] Failed to serialize packet")
		return false, 0, 0, nil, err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Debug().Err(err).Msg("→ [DEBUG] Failed to send packet")
		return false, 0, 0, nil, err
	}

	filter := "tcp and src host " + dstIP.String() + " and dst port " + strconv.Itoa(int(srcPort))
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Debug().Err(err).Msg("→ [DEBUG] Failed to set BPF filter")
		return false, 0, 0, nil, nil
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktChan := packetSource.Packets()

	// Structure to store extracted parameters
	type synAckParams struct {
		open bool
		ttl  int
		win  int
		opts []string
	}

	resultChan := make(chan synAckParams, 1)
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	go func() {
		for pkt := range pktChan {
			if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				if tcp.SYN && tcp.ACK {
					// Extract parameters for OS fingerprinting
					ttl := 0
					if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
						ip := ipLayer.(*layers.IPv4)
						ttl = int(ip.TTL)
					}

					win := int(tcp.Window)

					// Extraire les options TCP
					opts := extractTCPOptions(tcp)

					resultChan <- synAckParams{
						open: true,
						ttl:  ttl,
						win:  win,
						opts: opts,
					}
					return
				}
			}
		}
		resultChan <- synAckParams{open: false}
	}()

	select {
	case <-ctxTimeout.Done():
		log.Debug().Msgf("→ [DEBUG] Timeout expired for %s:%d", dstIP.String(), dstPort)
		return false, 0, 0, nil, nil
	case <-ctx.Done():
		log.Debug().Msgf("→ [DEBUG] Context cancelled for %s:%d", dstIP.String(), dstPort)
		return false, 0, 0, nil, nil
	case res := <-resultChan:
		log.Debug().Msgf("→ [DEBUG] Packet read complete for %s:%d: open=%v", dstIP.String(), dstPort, res.open)
		return res.open, res.ttl, res.win, res.opts, nil
	}
}

// getInterfaceIPv4 retrieves the first IPv4 address of the given interface.
func getInterfaceIPv4(name string) net.IP {
	intf, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := intf.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	return nil
}

// randomJitter returns a randomized delay between configured min/max jitter.
func randomJitter(cfg *config.Config) time.Duration {
	delta := cfg.Scan.SYN.JitterMaxMs - cfg.Scan.SYN.JitterMinMs
	if delta <= 0 {
		return time.Duration(cfg.Scan.SYN.JitterMinMs) * time.Millisecond
	}
	return time.Duration(cfg.Scan.SYN.JitterMinMs+rand.Intn(delta)) * time.Millisecond
}

// isBlacklisted returns true if the IP is present in the configured blacklist.
// This function is kept for backward compatibility but delegates to IsBlacklisted.
func isBlacklisted(ip string, blacklist []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return IsBlacklisted(parsedIP, blacklist)
}

// extractTCPOptions extracts TCP options from a TCP layer for OS fingerprinting.
func extractTCPOptions(tcp *layers.TCP) []string {
	var opts []string

	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				mss := int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
				opts = append(opts, "MSS:"+strconv.Itoa(mss))
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				wscale := int(opt.OptionData[0])
				opts = append(opts, "WSCALE:"+strconv.Itoa(wscale))
			}
		case layers.TCPOptionKindSACKPermitted:
			opts = append(opts, "SACK_PERMITTED")
		case layers.TCPOptionKindSACK:
			opts = append(opts, "SACK")
		case layers.TCPOptionKindTimestamps:
			opts = append(opts, "TIMESTAMPS")
		case 1: // NOP
			opts = append(opts, "NOP")
		case 0: // End of Option List
			opts = append(opts, "EOL")
		default:
			opts = append(opts, "UNKNOWN:"+strconv.Itoa(int(opt.OptionType)))
		}
	}

	return opts
}

// contains checks if a slice contains a specific integer value.
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// parseTCPOptionsFromStrings parses TCP options from string format
func parseTCPOptionsFromStrings(opts []string) *model.TCPOptions {
	if len(opts) == 0 {
		return nil
	}

	tcpOpts := &model.TCPOptions{
		Order: make([]string, 0, len(opts)),
	}

	for _, opt := range opts {
		opt = strings.TrimSpace(opt)
		if strings.HasPrefix(opt, "MSS:") {
			if mss, err := strconv.Atoi(strings.TrimPrefix(opt, "MSS:")); err == nil {
				tcpOpts.MSS = mss
			}
			tcpOpts.Order = append(tcpOpts.Order, "MSS")
		} else if strings.HasPrefix(opt, "WSCALE:") {
			if wscale, err := strconv.Atoi(strings.TrimPrefix(opt, "WSCALE:")); err == nil {
				tcpOpts.WSCALE = wscale
			}
			tcpOpts.Order = append(tcpOpts.Order, "WSCALE")
		} else if opt == "SACK_PERMITTED" {
			tcpOpts.SACKPermitted = true
			tcpOpts.Order = append(tcpOpts.Order, "SACK_PERMITTED")
		} else if opt == "TIMESTAMPS" {
			tcpOpts.Timestamp = true
			tcpOpts.Order = append(tcpOpts.Order, "TIMESTAMP")
		} else if opt == "NOP" {
			tcpOpts.NOPCount++
			tcpOpts.Order = append(tcpOpts.Order, "NOP")
		} else if opt == "EOL" {
			tcpOpts.Order = append(tcpOpts.Order, "EOL")
		} else {
			tcpOpts.Order = append(tcpOpts.Order, opt)
		}
	}

	return tcpOpts
}

// extractOrderFromTCPOptions extracts order from TCP options strings
func extractOrderFromTCPOptions(opts []string) []string {
	var order []string
	for _, opt := range opts {
		opt = strings.TrimSpace(opt)
		if strings.HasPrefix(opt, "MSS:") {
			order = append(order, "MSS")
		} else if strings.HasPrefix(opt, "WSCALE:") {
			order = append(order, "WSCALE")
		} else if opt == "SACK_PERMITTED" {
			order = append(order, "SACK_PERMITTED")
		} else if opt == "TIMESTAMPS" {
			order = append(order, "TIMESTAMP")
		} else if opt == "NOP" {
			order = append(order, "NOP")
		} else if opt == "EOL" {
			order = append(order, "EOL")
		} else {
			order = append(order, opt)
		}
	}
	return order
}
