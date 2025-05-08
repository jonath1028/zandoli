package scanner

import (
	"math/rand"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/google/gopacket/pcap"

	"zandoli/pkg/config"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
	"zandoli/pkg/utils"
)

// ScanARPStealth performs a stealthy ARP scan to avoid detection (rate-limited bursts)
func ScanARPStealth(ifaceName string) {
	logger.Logger.Info().Msg("[STEALTH] Starting stealth ARP scan...")

	// Chargement de la configuration furtive
	cfg := config.StealthARP

	// Interface et sous-réseau local
	_, localIP, localMAC := utils.GetInterfaceInfo(ifaceName)
	subnet := utils.GetLocalSubnet(localIP, ifaceName)

	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to open interface for stealth scan")
		return
	}
	defer handle.Close()

	// Lancement de la capture des réponses ARP en parallèle
	stop := make(chan struct{})
	go sniffer.CaptureARPReplies(ifaceName, stop)

	// Préparation et mélange aléatoire des IP cibles
	targets := gatherTargets(subnet, localIP)
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })

	// Barre de progression
	bar := pb.New(len(targets))
	bar.SetMaxWidth(60)
	bar.SetTemplate(pb.Simple)
	bar.Set("prefix", "🕵 Stealth Scan: ")
	bar.Start()

	var (
		i          = 0
		timestamps []time.Time
	)

	// Boucle d’envoi avec limitation de débit
	for i < len(targets) {
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

		for sentInBurst < burstSize && i < len(targets) {
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

			ip := targets[i]

			// 🔥 Exclusion IP par config
			if config.IsExcludedIP(ip) {
				logger.Logger.Debug().Msgf("[EXCLUDED] Skipping IP %s (matched exclusion list)", ip)
				bar.Increment()
				i++
				continue
			}

			// Envoi ARP
			sendARP(handle, ip, localMAC, localIP)
			timestamps = append(timestamps, time.Now())
			bar.Increment()
			i++
			sentInBurst++

			// Jitter exponentiel
			jitter := time.Duration(rand.ExpFloat64()) * cfg.JitterMean
			time.Sleep(jitter)
		}

		if i < len(targets) {
			pause := cfg.BurstPauseMin + time.Duration(rand.Int63n(int64(cfg.BurstPauseMax-cfg.BurstPauseMin)))
			time.Sleep(pause)
		}
	}

	bar.Finish()
	time.Sleep(500 * time.Millisecond)
	close(stop)
	logger.Logger.Info().Msg("[STEALTH] Stealth ARP scan complete.")
}

