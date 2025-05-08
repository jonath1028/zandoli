package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	configPath            string
	showHelp              bool
	enableSubnetExclusion bool
	ifaceOverride         string
	modeOverride          string
	activeTypeOverride    string
	timeoutOverride       int
	enableVerbose         bool
)

func initFlags() {
	flag.StringVar(&configPath, "config", "assets/config.yaml", "Path to the configuration YAML file")
	flag.BoolVar(&showHelp, "h", false, "Show this help message")
	flag.BoolVar(&enableSubnetExclusion, "exclude-subnets", false, "Enable exclusion of IPs from assets/excluded_subnets.txt")

	flag.StringVar(&ifaceOverride, "iface", "", "Override interface defined in config file (e.g., eth0)")
	flag.StringVar(&modeOverride, "mode", "", "Override scan mode: passive, active, combined, or pcap")
	flag.IntVar(&timeoutOverride, "timeout", 0, "Override passive sniffing duration (in seconds)")
	flag.BoolVar(&enableVerbose, "verbose", false, "Enable verbose logging output (equivalent to log_level=debug)")

	flag.Usage = func() {
		fmt.Println("\nZandoli - Network Recon Tool (Red Team Edition)")
		fmt.Println("Author: Jonathan Nomed\n")

		fmt.Println("Overview:")
		fmt.Println("  Zandoli is a stealth-oriented reconnaissance tool designed for internal Red Team operations.")
		fmt.Println("  It passively and actively maps the local network, detects anomalies, classifies hosts,")
		fmt.Println("  and exports results in JSON, CSV and HTML formats.\n")

		fmt.Println("Usage:")
		fmt.Println("  zandoli [flags]\n")

		fmt.Println("Flags:")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("  -%-18s %s (default: %v)\n", f.Name, f.Usage, f.DefValue)
		})

		fmt.Println("\nHow It Works:")
		fmt.Println("  Zandoli supports multiple scan modes:")
		fmt.Println("    passive   → captures network traffic (802.1X, LLDP, DHCP, ARP, etc.) without sending packets")
		fmt.Println("    active    → sends ARP requests to identify hosts (standard or stealth mode)")
		fmt.Println("    combined  → runs passive first, then active")
		fmt.Println("    pcap      → analyzes a PCAP file instead of live capture")
		fmt.Println("  The scan mode and active type are set in config.yaml or overridden via flags.\n")

		fmt.Println("Examples:")
		fmt.Println("  zandoli -config assets/config.yaml")
		fmt.Println("  zandoli --iface eth0 --mode combined --exclude-subnets")
		fmt.Println("  zandoli --help\n")

		fmt.Println("Notes:")
		fmt.Println("  - Run as root for interface access.")
		fmt.Println("  - Output files are stored in the path defined by 'output_dir' in config.")
		fmt.Println("  - Excluded IP ranges must be listed in assets/excluded_subnets.txt.")
		fmt.Println("  - CLI flags override values defined in the configuration file.\n")

		fmt.Println("Documentation:")
		fmt.Println("  https://github.com/ton-repo/zandoli (coming soon)")
	}
}

func parseFlags() {
	initFlags()

	for _, arg := range os.Args[1:] {
		if strings.TrimSpace(arg) == "--help" {
			showHelp = true
		}
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}
}

