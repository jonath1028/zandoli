// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"zandoli/internal/oui"
	"zandoli/pkg/analyzer"
	"zandoli/pkg/exporter"
	"zandoli/pkg/fusion"
	"zandoli/pkg/model"
	"zandoli/pkg/scanner"
	"zandoli/pkg/sniffer"
	"zandoli/pkg/ui"
	"zandoli/pkg/utils"
)

// Run executes the scan pipeline based on the selected mode.
func (o *Orchestrator) Run() error {
	baseCtx := context.Background()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	// Context dedicated to passive capture
	var captureCtx context.Context
	var captureCancel context.CancelFunc
	if o.Config.Mode.Passive || o.Config.Mode.Combined {
		if o.Config.Scan.PassiveDurationSeconds > 0 {
			captureCtx, captureCancel = context.WithTimeout(baseCtx, time.Duration(o.Config.Scan.PassiveDurationSeconds)*time.Second)
		} else {
			captureCtx, captureCancel = context.WithCancel(baseCtx)
		}
		defer captureCancel()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		o.Log.Info().Msg("Scan interrupted. Cleaning up.")
		cancel()
		if captureCancel != nil {
			captureCancel()
		}
	}()

	scanID := time.Now().Format("20060102-150405")
	startTime := time.Now()
	
	o.Log.Info().Str("scan_id", scanID).Msg("Scan started")

	// The output directory is already created in cmd/zandoli/main.go
	// No need to create an additional subdirectory
	outputDir := o.OutputPath

	// Load the OUI map (embedded by default, or override if provided)
	ouiMap := oui.New()
	if o.Config.Output.OUIFile != "" {
		// Override with external file
		if err := ouiMap.Load(o.Config.Output.OUIFile); err != nil {
			o.Log.Warn().Err(err).Str("oui_file", o.Config.Output.OUIFile).Msg("✗ Failed to load custom OUI file, falling back to embedded")
			// Fallback to embedded
			if err := ouiMap.LoadEmbedded(); err != nil {
				o.Log.Error().Err(err).Msg("✗ Critical: Failed to load embedded OUI data")
			} else {
				o.Log.Info().Str("source", "embedded").Int("entries", len(ouiMap.ByPref)).Msg("✓ OUI database loaded (embedded fallback)")
			}
		} else {
			o.Log.Info().Str("source", o.Config.Output.OUIFile).Int("entries", len(ouiMap.ByPref)).Msg("✓ OUI database loaded (custom file)")
		}
	} else {
		// Use embedded by default
		if err := ouiMap.LoadEmbedded(); err != nil {
			o.Log.Error().Err(err).Msg("✗ Critical: Failed to load embedded OUI data")
		} else {
			o.Log.Info().Str("source", "embedded").Int("entries", len(ouiMap.ByPref)).Msg("✓ OUI database loaded (embedded)")
		}
	}

	packetChan := make(chan model.PacketEvent, 70000)
	var passiveResults []*model.Host
	var activeResults []*model.Host

	switch {
	case o.Config.Mode.Combined:
		o.Log.Info().Msg("→ Running in Combined mode")
		sniff := sniffer.NewLiveSniffer(o.Config, packetChan, o.Log, outputDir)
		resultChan := make(chan []*model.Host, 1)
		go func() {
			ctxWithMode := context.WithValue(captureCtx, analyzer.ModeKey, "live")
			opts := &analyzer.Options{
				EnableMetrics: o.Config.Scan.Performance.EnableMetrics,
				SampleRate:    o.Config.Scan.Performance.MetricsSampleRate,
				Workers:       o.Config.Scan.Performance.ParallelWorkers,
				TraceEnabled:  false,
				OUIMap:        ouiMap,
			}
			resultChan <- analyzer.AnalyzeWithCustomOptions(ctxWithMode, packetChan, scanID, o.Log, opts)
		}()
		if err := sniff.Start(captureCtx); err != nil {
			return err
		}
		passiveResults = <-resultChan
		activeResults = o.ActiveScanFunc(ctx, o.Config, o.Log)

	case o.Config.Mode.Active:
		o.Log.Info().Msg("→ Running in Active mode")
		activeResults = o.ActiveScanFunc(ctx, o.Config, o.Log)

	case o.Config.Mode.Passive:
		o.Log.Info().Msg("→ Running in Passive mode")
		sniff := sniffer.NewLiveSniffer(o.Config, packetChan, o.Log, outputDir)
		resultChan := make(chan []*model.Host, 1)
		go func() {
			ctxWithMode := context.WithValue(captureCtx, analyzer.ModeKey, "live")
			opts := &analyzer.Options{
				EnableMetrics: o.Config.Scan.Performance.EnableMetrics,
				SampleRate:    o.Config.Scan.Performance.MetricsSampleRate,
				Workers:       o.Config.Scan.Performance.ParallelWorkers,
				TraceEnabled:  false,
				OUIMap:        ouiMap,
			}
			resultChan <- analyzer.AnalyzeWithCustomOptions(ctxWithMode, packetChan, scanID, o.Log, opts)
		}()
		if err := sniff.Start(captureCtx); err != nil {
			return err
		}
		passiveResults = <-resultChan

	case o.Config.Mode.PcapFile != "":
		o.Log.Info().Msg("→ Running in PCAP mode")
		showUI := !o.Config.Logging.Paranoid && !o.Config.Logging.Quiet
		sniff := sniffer.NewPcapSniffer(o.Config.Mode.PcapFile, packetChan, o.Log, showUI)
		resultChan := make(chan []*model.Host, 1)
		go func() {
			ctxWithMode := context.WithValue(ctx, analyzer.ModeKey, "pcap")
			opts := &analyzer.Options{
				EnableMetrics: o.Config.Scan.Performance.EnableMetrics,
				SampleRate:    o.Config.Scan.Performance.MetricsSampleRate,
				Workers:       o.Config.Scan.Performance.ParallelWorkers,
				TraceEnabled:  false,
				OUIMap:        ouiMap,
			}
			resultChan <- analyzer.AnalyzeWithCustomOptions(ctxWithMode, packetChan, scanID, o.Log, opts)
		}()
		if err := sniff.Start(ctx); err != nil {
			return err
		}
		passiveResults = <-resultChan
	}

	o.Log.Debug().
		Int("passive", len(passiveResults)).
		Int("active", len(activeResults)).
		Msg("→ Host counts before merge")

	allHosts := fusion.MergeResults(passiveResults, activeResults, o.Log)

	// Compute active subnets
	allSubnets := analyzer.ComputeActiveSubnets(allHosts)

	if o.Config.Mode.SYN && !o.Config.Mode.Active {
		o.Log.Info().Msg("→ Running SYN scan on hosts with unknown OS")
		targets := utils.FilterHostsNeedingSYN(allHosts)
		o.Log.Debug().Int("syn_targets", len(targets)).Msg("→ Hosts targeted by SYN scan")
		synResults := scanner.ScanSYNFromPipeline(ctx, o.Config, targets, o.Log)
		allHosts = fusion.MergeResults(allHosts, synResults, o.Log)
	}

	for _, format := range o.Config.Output.Formats {
		var path string
		switch format {
		case "json":
			path = filepath.Join(outputDir, "hosts.json")
			if err := exporter.ExportAll(allHosts, path, o.Log); err != nil {
				return err
			}
		case "csv":
			path = filepath.Join(outputDir, "hosts.csv")
			if err := exporter.ExportCSV(allHosts, path, o.Log); err != nil {
				return err
			}
		case "html":
			path = filepath.Join(outputDir, "report.html")
			if err := exporter.ExportHTMLWithOptions(allHosts, allSubnets, path, o.Log, o.Config.Output.AllowPublicSubnets); err != nil {
				return err
			}
		case "markdown", "md":
			path = filepath.Join(outputDir, "report.md")
			if err := exporter.ExportMarkdown(allHosts, allSubnets, path, o.Log); err != nil {
				return err
			}
		default:
			o.Log.Warn().Str("format", format).Msg("Unknown export format requested")
		}
	}

	// Export private and public IP sets
	if err := exporter.ExportIPSets(allHosts, outputDir, o.Log); err != nil {
		o.Log.Warn().Err(err).Msg("Failed to export IP sets")
		// Do not fail the scan for this non-critical error
	}

	if o.Config.CLI.Summary {
		ui.PrintScanSummary(scanID, allHosts, passiveResults, activeResults, outputDir)
	}

	// Compute total duration
	durationStr := fmt.Sprintf("%.2fs", time.Since(startTime).Seconds())

	o.Log.Info().
		Str("scan_id", scanID).
		Int("hosts", len(allHosts)).
		Str("output", outputDir).
		Str("duration", durationStr).
		Msg("Scan completed")

	return nil
}

// RunDemoProgressBars displays a demonstration of the progress bars
func RunDemoProgressBars() {
	fmt.Println("\033[90m================ ZANDOLI PROGRESS BARS ================\033[0m")

	ui.PrintProgressBar("Sniffing", 60, "time", "", 50*time.Millisecond)
	ui.PrintProgressBar("Scan ARP", 254, "count", "00:17", 10*time.Millisecond)
	ui.PrintProgressBar("Scan SYN", 80, "count", "00:10", 20*time.Millisecond)

	fmt.Println("\033[90m====================     DONE     ======================\033[0m")
}
