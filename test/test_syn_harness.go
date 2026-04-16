// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package main

import (
	"context"
	"net"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/scanner"
)

func main() {
	cfg := &config.Config{
		Interface: "eth0",
		Scan: config.ScanSettings{
			SYNPorts:  []int{22, 80},
			Blacklist: []string{},
			SYN: config.SYNSettings{
				TimeoutMs:   1500,
				JitterMinMs: 100,
				JitterMaxMs: 300,
			},
			ARP: config.ARPSettings{
				Burst: 10,
			},
		},
	}

	log, _ := logger.New("debug", cfg)

	hosts := []*model.Host{
		{IP: net.ParseIP("192.168.0.100")},
		{IP: net.ParseIP("192.168.0.101")},
		{IP: net.ParseIP("192.168.0.102")},
		{IP: net.ParseIP("192.168.0.104")},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner.ScanSYNFromActive(ctx, cfg, log, hosts)

	for _, h := range hosts {
		log.Info().Msgf("Host %s has open ports: %v", h.IP.String(), h.Ports)
	}
}
