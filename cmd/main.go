package main

import (
	"fmt"
	"os"
	"time"

	"zandoli/pkg/analyzer"
	"zandoli/pkg/config"
	"zandoli/pkg/export"
	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
	"zandoli/pkg/scanner"
	"zandoli/pkg/sniffer"
	"zandoli/pkg/ui"
)

func main() {
	// === CLI flags ===
	parseFlags()
	if enableSubnetExclusion {
		err := config.LoadExclusions("assets/excluded_hosts.txt")
		if err != nil {
			fmt.Printf("Failed to load exclusion list: %v\n", err)
			os.Exit(1)
		}
	}

	// === Load config ===
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// === Apply CLI overrides ===
	if ifaceOverride != "" {
		cfg.Iface = ifaceOverride
	}
	if modeOverride != "" {
		cfg.Scan.Mode = modeOverride
	}
	if activeTypeOverride != "" {
		cfg.Scan.ActiveType = activeTypeOverride
	}
	if timeoutOverride > 0 {
		cfg.PassiveDuration = timeoutOverride
	}
	if enableVerbose {
		cfg.LogLevel = "debug"
	}

	// === Load excluded subnets if flag is set ===
	if enableSubnetExclusion {
		err := config.LoadExclusions("assets/excluded_hosts.txt")
		if err != nil {
			fmt.Printf("Failed to load subnet exclusion list: %v\n", err)
			os.Exit(1)
		}
	}

	// === Init logging ===
	logger.InitLoggerFromConfig(cfg.LogLevel, cfg.LogFile)
	logger.Logger.Info().Msg("Zandoli starting...")
	logger.Logger.Info().Msgf("Interface: %s", cfg.Iface)
	logger.Logger.Info().Msgf("Passive sniffing duration: %d seconds", cfg.PassiveDuration)
	logger.Logger.Info().Msgf("Output directory: %s", cfg.OutputDir)
	logger.Logger.Info().Msgf("Log file: %s", cfg.LogFile)
	logger.Logger.Debug().Msgf("Scan mode: %s | Active type: %s", cfg.Scan.Mode, cfg.Scan.ActiveType)

	// === Load vendor + filtering files ===
	if err := oui.LoadVendors("assets/mac_vendors.txt"); err != nil {
		logger.Logger.Warn().Err(err).Msg("Failed to load vendor list")
	}
	if err := oui.LoadOUILists("assets/oui_defensive.txt", "assets/blacklist_oui.txt"); err != nil {
		logger.Logger.Warn().Err(err).Msg("Failed to load OUI filters")
	}

	// === Dispatch by scan mode ===
	switch cfg.Scan.Mode {
	case "passive":
		logger.Logger.Info().Msg("Running in passive-only mode")
		runPassive(cfg)

	case "active":
		logger.Logger.Info().Msg("Running in active-only mode")
		runActive(cfg)

	case "combined":
		logger.Logger.Info().Msg("Running in combined mode (passive + active)")
		runPassive(cfg)
		if len(sniffer.DiscoveredHosts) == 0 {
			logger.Logger.Warn().Msg("No hosts discovered during passive sniffing.")
		}
		runActive(cfg)

	default:
		logger.Logger.Fatal().Msgf("Invalid scan mode: %s", cfg.Scan.Mode)
	}

	// === Export results ===
	logger.Logger.Info().Msgf("Exporting %d discovered hosts...", len(sniffer.DiscoveredHosts))

	// Ensure output directory exists
	if _, err := os.Stat(cfg.OutputDir); os.IsNotExist(err) {
		err := os.MkdirAll(cfg.OutputDir, 0755)
		if err != nil {
			logger.Logger.Fatal().Err(err).Msgf("Failed to create output directory: %s", cfg.OutputDir)
		}
	}

	err = export.ExportAll(sniffer.DiscoveredHosts, cfg.OutputDir, cfg.Iface, cfg.PassiveDuration)


	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to export results")
		os.Exit(1)
	}
	logger.Logger.Info().Msg("Export completed successfully.")

	// === Display summary ===
	ui.DisplaySummary(sniffer.DiscoveredHosts)
	logger.Logger.Info().Msg("Zandoli finished.")
}

// runPassive encapsulates the passive scan logic
func runPassive(cfg *config.Config) {
	start := time.Now()
	packets := sniffer.StartPassiveSniff(cfg.Iface, cfg.PassiveDuration)
	done := make(chan struct{})

	go func() {
		for packet := range packets {
			analyzer.HandlePacket(packet)
		}
		close(done)
	}()

	select {
	case <-done:
		logger.Logger.Debug().Msg("Packet processing loop ended.")
	case <-time.After(time.Duration(cfg.PassiveDuration+5) * time.Second):
		logger.Logger.Warn().Msg("Packet processing loop timeout reached.")
	}

	logger.Logger.Debug().Msgf("Passive phase done. Hosts: %d | Duration: %s",
		len(sniffer.DiscoveredHosts), time.Since(start))
}

// runActive encapsulates the active scan logic
func runActive(cfg *config.Config) {
	switch cfg.Scan.ActiveType {
	case "stealth":
		logger.Logger.Debug().Msg("Starting stealth ARP scan")
		scanner.ScanARPStealth(cfg.Iface)
	case "standard", "":
		logger.Logger.Debug().Msg("Starting standard ARP scan")
		scanner.ScanARP(cfg.Iface)
	default:
		logger.Logger.Fatal().Msgf("Invalid active_type value: %s", cfg.Scan.ActiveType)
	}
}

