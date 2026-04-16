// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package sniffer implements live packet capture using gopacket.
package sniffer

import (
	"context"
	"path/filepath"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/ui"
	"zandoli/pkg/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
)

// LiveSniffer captures traffic in real time from a network interface.
type LiveSniffer struct {
	iface      string
	packetChan chan model.PacketEvent
	log        *logger.Logger
	snapLen    int32
	cfg        *config.Config
	outputDir  string
	handle     *pcap.Handle // Conserver le handle pour pouvoir appeler BreakLoop()
}

// NewLiveSniffer creates a new sniffer on the given interface.
func NewLiveSniffer(cfg *config.Config, packetChan chan model.PacketEvent, log *logger.Logger, outputDir string) *LiveSniffer {
	return &LiveSniffer{
		iface:      cfg.Interface,
		packetChan: packetChan,
		log:        log,
		snapLen:    65536,
		cfg:        cfg,
		outputDir:  outputDir,
	}
}

// Start begins capturing packets until the context is cancelled or timeout is reached.
func (ls *LiveSniffer) Start(ctx context.Context) error {
	// Use a short timeout so reads return quickly
	handle, err := pcap.OpenLive(ls.iface, ls.snapLen, true, 200*time.Millisecond)
	if err != nil {
		ls.log.Error().Err(err).Str("interface", ls.iface).Msg("Failed to open interface")
		return err
	}

	// Keep the handle to be able to call BreakLoop()
	ls.handle = handle

	// Create a channel to signal the end of the read goroutine
	done := make(chan struct{})

	// Apply timeout if configured
	if ls.cfg.Scan.PassiveDurationSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(ls.cfg.Scan.PassiveDurationSeconds)*time.Second)
		defer cancel()
	}

	if !ls.cfg.Logging.Paranoid && !ls.cfg.Logging.Quiet && ls.cfg.Scan.PassiveDurationSeconds > 0 {
		progress := ui.PrintProgressBar("Sniffing", ls.cfg.Scan.PassiveDurationSeconds, "time", "", time.Second)
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for i := 0; i <= ls.cfg.Scan.PassiveDurationSeconds; i++ {
				progress(i)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}

	ls.log.Info().Str("interface", ls.iface).Msg("Live sniffer started")

	// Create the PCAP writer only if RecordPCAP is enabled
	var pcapWriter utils.PCAPWriter
	if ls.cfg.Output.RecordPCAP {
		pcapPath := filepath.Join(ls.outputDir, "capture.pcap")
		ls.log.Debug().Str("pcap_path", pcapPath).Msg("Creating PCAP file")

		var err error
		pcapWriter, err = utils.NewPCAPWriter(pcapPath, int(ls.snapLen))
		if err != nil {
			ls.log.Error().Err(err).Str("file", pcapPath).Msg("Cannot create PCAP writer")
			handle.Close()
			return err
		}
		defer pcapWriter.Close()

		ls.log.Info().Str("file", pcapPath).Msg("Writing live capture to PCAP file")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetChan := packetSource.Packets()

	// Goroutine de lecture des paquets
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetChan:
				if !ok {
					return
				}

				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethLayer == nil {
					continue
				}
				eth := ethLayer.(*layers.Ethernet)

				var ttl uint8 = 0
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ipv4 := ipLayer.(*layers.IPv4)
					ttl = ipv4.TTL
				}

				// Extract VLAN ID from 802.1Q tag if present
				var vlanID int = -1
				dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
				if dot1qLayer != nil {
					dot1q := dot1qLayer.(*layers.Dot1Q)
					vlanID = int(dot1q.VLANIdentifier)
				}

				event := model.PacketEvent{
					Timestamp: packet.Metadata().Timestamp,
					SrcMAC:    eth.SrcMAC,
					DstMAC:    eth.DstMAC,
					Payload:   packet.Data(),
					PacketID:  uuid.New().String(),
					TTL:       ttl,
					VLANID:    vlanID,
				}

				select {
				case ls.packetChan <- event:
				case <-ctx.Done():
					return
				}

				// Write the packet to PCAP only if the writer exists
				if pcapWriter != nil {
					err := pcapWriter.WritePacket(packet)
					if err != nil {
						ls.log.Warn().Err(err).Msg("Failed to write packet to PCAP")
					}
				}
			}
		}
	}()

	// Attendre la fin du contexte ou de la goroutine
	select {
	case <-ctx.Done():
		ls.log.Info().Msg("Live sniffer stopped (timeout or external cancel)")
		// Le timeout de 200ms du handle permet au select dans la goroutine
		// to check ctx.Done() quickly and terminate
		<-done
	case <-done:
		// The goroutine terminated naturally
	}

	// Close the handle safely
	if ls.handle != nil {
		ls.handle.Close()
		ls.handle = nil
	}

	return nil
}
