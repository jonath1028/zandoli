// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/internal/validation"
	"zandoli/pkg/orchestrator"
)

func main() {
	demo := flag.Bool("demo", false, "Run CLI progress bar demo instead of scan")

	cfg, outputDir, ok := parseFlags()
	if !ok {
		os.Exit(1)
	}

	// Global logging configuration before any operation
	logFile, err := setupLogging(outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup logging: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	if *demo {
		orchestrator.RunDemoProgressBars()
		os.Exit(0)
	}

	if err := RunZandoli(cfg, outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "Zandoli execution error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Zandoli scan completed successfully.")
	fmt.Printf("🗂  Results saved in: %s\n", outputDir)
	os.Exit(0)
}

func parseFlags() (*config.Config, string, bool) {
	defaultConf := "config.yaml"
	confPath := flag.String("config", defaultConf, "Path to YAML config file (default: config.yaml)")
	showHelp := flag.Bool("help", false, "Display help message and exit")
	summaryFlag := flag.Bool("summary", false, "Show a scan summary in the CLI after execution")

	// Mode
	modePassive := flag.Bool("passive", false, "Run in passive mode (sniffing only)")
	modeActive := flag.Bool("active", false, "Run in active mode (ARP and/or SYN)")
	modeCombined := flag.Bool("combined", false, "Run passive then active mode")
	modePcap := flag.String("pcap", "", "Path to PCAP file for offline analysis (incompatible with active mode)")
	modeSYN := flag.Bool("SYN", false, "Enable SYN scan on unidentified hosts")

	// Interface & logs
	interfaceFlag := flag.String("interface", "", "Network interface to use (default from config)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logs")
	quietFlag := flag.Bool("quiet", false, "Suppress most logs")
	paranoidFlag := flag.Bool("paranoid", false, "Paranoid logging mode (no stdout)")

	// Scan
	passiveDuration := flag.Int("passive-duration", 0, "Passive sniffing duration in seconds")
	ttl := flag.Int("ttl", 0, "TTL for active scan packets")
	arpMaxPerSec := flag.Int("arp-max-per-sec", 0, "Max ARP packets per second")
	arpBurst := flag.Int("arp-burst", 0, "Max ARP packets per burst")
	burstMinDelay := flag.Int("burst-min-delay", 0, "Minimum delay between ARP bursts in ms")
	burstMaxDelay := flag.Int("burst-max-delay", 0, "Maximum delay between ARP bursts in ms")
	synTimeout := flag.Int("syn-timeout", 0, "Timeout for each SYN scan attempt in ms")

	var synPorts []int
	flag.Func("syn-ports", "Comma-separated TCP ports to scan (e.g. 80,443)", func(s string) error {
		for _, p := range strings.Split(s, ",") {
			if val, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				synPorts = append(synPorts, val)
			}
		}
		return nil
	})

	// Output
	ouiFile := flag.String("oui-file", "", "Path to OUI.txt file for vendor lookup")
	outputDir := flag.String("output-dir", "output", "Directory for output files (default: output)")
	recordPcap := flag.Bool("record-pcap", false, "Record live sniffing into a PCAP file")

	var formats []string
	flag.Func("formats", "Comma-separated export formats (json, csv, html)", func(s string) error {
		formats = strings.Split(s, ",")
		return nil
	})

	// Profile
	profileFlag := flag.String("profile", "", "Scan profile: stealth, normal, aggressive, passive-only")

	// Blacklist
	blacklistFlag := flag.String("blacklist", "", "Comma-separated IPs/subnets to exclude (e.g. 192.168.1.1,10.0.0.0/8)")

	// === Final parse ===
	flag.Parse()

	if *showHelp {
		displayHelp()
		return nil, "", false
	}

	// Load the YAML config
	cfg, err := config.Load(*confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config load error: %v\n", err)
		return nil, "", false
	}

	// Apply profile override (before other flag overrides)
	if *profileFlag != "" {
		cfg.Profile = *profileFlag
		config.ApplyProfile(cfg)
	}

	// Override YAML config with flags (if set)
	cfg.CLI.Summary = *summaryFlag

	if *interfaceFlag != "" {
		cfg.Interface = *interfaceFlag
	}

	// Only override logging settings if flags are explicitly provided
	// Use flag.Visit to detect which flags were explicitly set on the command line
	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	if explicitFlags["verbose"] || explicitFlags["quiet"] || explicitFlags["paranoid"] {
		cfg.Logging.Verbose = *verboseFlag
		cfg.Logging.Quiet = *quietFlag
		cfg.Logging.Paranoid = *paranoidFlag
	}

	if *passiveDuration > 0 {
		cfg.Scan.PassiveDurationSeconds = *passiveDuration
	}
	if *ttl > 0 {
		cfg.Scan.TTL = *ttl
	}
	if *arpMaxPerSec > 0 {
		cfg.Scan.ARP.MaxPerSec = *arpMaxPerSec
	}
	if *arpBurst > 0 {
		cfg.Scan.ARP.Burst = *arpBurst
	}
	if *burstMinDelay > 0 {
		cfg.Scan.ARP.BurstMinDelayMs = *burstMinDelay
	}
	if *burstMaxDelay > 0 {
		cfg.Scan.ARP.BurstMaxDelayMs = *burstMaxDelay
	}
	if *synTimeout > 0 {
		cfg.Scan.SYN.TimeoutMs = *synTimeout
	}
	if len(synPorts) > 0 {
		cfg.Scan.SYNPorts = synPorts
	}
	// Flag validation
	blacklistList := []string{}
	if *blacklistFlag != "" {
		blacklistList = strings.Split(*blacklistFlag, ",")
		cfg.Scan.Blacklist = blacklistList
	}

	validationErrors := validation.ValidateFlags(*interfaceFlag, synPorts, blacklistList, *passiveDuration)
	if len(validationErrors) > 0 {
		fmt.Fprintf(os.Stderr, "Flag validation errors:\n")
		for _, err := range validationErrors {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		return nil, "", false
	}

	// Format validation
	if len(formats) > 0 {
		if err := validation.ValidateFormats(formats); err != nil {
			fmt.Fprintf(os.Stderr, "Format validation error: %v\n", err)
			return nil, "", false
		}
	}

	// Override modes only if flags are explicitly set
	if *modePassive {
		cfg.Mode.Passive = *modePassive
		cfg.Mode.Active = false
		cfg.Mode.Combined = false
	}
	if *modeActive {
		cfg.Mode.Active = *modeActive
		cfg.Mode.Passive = false
		cfg.Mode.Combined = false
	}
	if *modeCombined {
		cfg.Mode.Combined = *modeCombined
		cfg.Mode.Passive = false
		cfg.Mode.Active = false
	}
	if *modePcap != "" {
		cfg.Mode.PcapFile = *modePcap
		cfg.Mode.Passive = false
		cfg.Mode.Active = false
		cfg.Mode.Combined = false
	}
	if *modeSYN {
		cfg.Mode.SYN = *modeSYN
	}

	if *ouiFile != "" {
		cfg.Output.OUIFile = *ouiFile
	}
	
	if explicitFlags["output-dir"] {
		cfg.Output.BaseDir = *outputDir
	} else if cfg.Output.BaseDir == "" {
		cfg.Output.BaseDir = "output"
	}
	// Resolve '~' (home directory) taking sudo into account
	if strings.HasPrefix(cfg.Output.BaseDir, "~/") {
		parsedDir := cfg.Output.BaseDir[2:]
		var homeDir string
		
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			// Manually build the home path if running via sudo
			homeDir = filepath.Join("/home", sudoUser)
		} else {
			var err error
			homeDir, err = os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not resolve home directory: %v\n", err)
			}
		}
		
		if homeDir != "" {
			cfg.Output.BaseDir = filepath.Join(homeDir, parsedDir)
		}
	}

	// Handle the record-pcap flag
	if *modePcap != "" {
		// Offline PCAP mode: ignore record-pcap
		if *recordPcap {
			fmt.Println("Debug: record-pcap ignored in PCAP mode")
		}
		cfg.Output.RecordPCAP = false
	} else {
		// Live mode: use the record-pcap flag
		cfg.Output.RecordPCAP = *recordPcap
	}

	if len(formats) > 0 {
		cfg.Output.Formats = formats
	}

	return cfg, cfg.Output.BaseDir, true
}

func RunZandoli(cfg *config.Config, outputDir string) error {
	timestamp := time.Now().Format("20060102-150405")
	fullOutput := filepath.Join(outputDir, "scan_"+timestamp)

	if err := os.MkdirAll(fullOutput, 0755); err != nil {
		return fmt.Errorf("output folder creation failed: %w", err)
	}
	log, err := logger.New(fullOutput, cfg)
	if err != nil {
		return fmt.Errorf("logger creation failed: %w", err)
	}

	// OUI loading is now handled in orchestrator/run_pipeline.go with embedded support
	orch := orchestrator.NewOrchestrator(cfg, log, fullOutput)

	return orch.Run()
}

// setupLogging configures global logging to baseDir/zandoli_application.log only (no console by default)
func setupLogging(baseDir string) (*os.File, error) {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Open zandoli_application.log in append mode
	logPath := filepath.Join(baseDir, "zandoli_application.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open application log file: %w", err)
	}

	// Configure zerolog global logger to write to the file
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zlog := zerolog.New(logFile).With().Timestamp().Caller().Logger()
	zerolog.DefaultContextLogger = &zlog

	return logFile, nil
}

func displayHelp() {
	fmt.Println("Zandoli Alpha — Stealth Network Reconnaissance Tool")
	fmt.Println("")
	fmt.Println("MODE:")
	fmt.Println("  --passive               Passive listening only (sniffing)")
	fmt.Println("  --active                Active scanning only (ARP + SYN)")
	fmt.Println("  --combined              Passive first, then targeted active scan")
	fmt.Println("  --pcap <file>           Analyze a PCAP file offline")
	fmt.Println("  --SYN                   Enable SYN scan on unidentified hosts")
	fmt.Println("  --profile <name>        Scan profile: stealth, normal, aggressive, passive-only")
	fmt.Println("")
	fmt.Println("SCAN:")
	fmt.Println("  --interface <iface>     Network interface (default: eth0)")
	fmt.Println("  --passive-duration <s>  Passive capture duration in seconds")
	fmt.Println("  --ttl <n>               TTL for active scan packets (1-255)")
	fmt.Println("  --arp-max-per-sec <n>   Max ARP packets per second (1-1000)")
	fmt.Println("  --arp-burst <n>         Max ARP packets per burst (1-10000)")
	fmt.Println("  --burst-min-delay <ms>  Min delay between ARP bursts (ms)")
	fmt.Println("  --burst-max-delay <ms>  Max delay between ARP bursts (ms)")
	fmt.Println("  --syn-timeout <ms>      Timeout per SYN probe (100-30000 ms)")
	fmt.Println("  --syn-ports <p1,p2>     TCP ports for SYN scan (comma-separated)")
	fmt.Println("  --blacklist <ip1,ip2>   IPs/CIDRs to exclude from active scanning")
	fmt.Println("")
	fmt.Println("OUTPUT:")
	fmt.Println("  --output-dir <dir>      Output directory (default: output)")
	fmt.Println("  --formats <f1,f2>       Export formats: json,csv,html,markdown,xml")
	fmt.Println("  --record-pcap           Record live traffic to PCAP file")
	fmt.Println("  --oui-file <file>       Custom OUI database (default: embedded)")
	fmt.Println("  --summary               Show scan summary in CLI after completion")
	fmt.Println("")
	fmt.Println("LOGGING:")
	fmt.Println("  --verbose               Detailed debug logging")
	fmt.Println("  --quiet                 Minimal logging (files only)")
	fmt.Println("  --paranoid              No stdout output at all")
	fmt.Println("")
	fmt.Println("OTHER:")
	fmt.Println("  --config <file>         YAML config file (default: config.yaml)")
	fmt.Println("  --demo                  Show CLI progress bar demo (no scan)")
	fmt.Println("  --help                  Display this help message")
}
