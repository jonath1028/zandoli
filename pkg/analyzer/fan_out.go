// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"hash/fnv"
	"sync"

	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/sniffer"
)

// analysisShard represents one independent analysis pipeline for fan-out.
type analysisShard struct {
	ch         chan model.PacketEvent
	aggregator *Aggregator
	dispatcher *Dispatcher
}

// hashMAC returns a shard index in [0, k) based on FNV hash of the MAC address.
// Packets with the same SrcMAC always go to the same shard, ensuring
// lock-free aggregation within each shard.
func hashMAC(mac []byte, k int) int {
	h := fnv.New32a()
	h.Write(mac) //nolint:errcheck
	return int(h.Sum32()) % k
}

// fanOutAnalyze distributes packets across k worker goroutines, each with its
// own Dispatcher+Aggregator. After all packets are consumed, results are merged.
// This provides ~linear speedup on multi-core CPUs for CPU-bound analysis.
func fanOutAnalyze(
	packetChan <-chan model.PacketEvent,
	log *logger.Logger,
	opts *Options,
	k int,
) []*model.Host {
	if k < 2 {
		k = 2
	}

	// Create k independent analysis shards
	shards := make([]analysisShard, k)
	for i := 0; i < k; i++ {
		agg := NewAggregator()
		agg.SetLogger(log)

		var metrics *sniffer.AnalyzerMetrics
		if opts != nil {
			metrics = sniffer.NewAnalyzerMetricsWithOptions(log, opts.EnableMetrics, opts.SampleRate)
		} else {
			metrics = sniffer.NewAnalyzerMetricsWithOptions(log, false, 0)
		}

		disp := NewDispatcher(log, agg, opts, metrics)
		shards[i] = analysisShard{
			ch:         make(chan model.PacketEvent, 4096),
			aggregator: agg,
			dispatcher: disp,
		}
	}

	// Start k worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(s analysisShard) {
			defer wg.Done()
			for pkt := range s.ch {
				s.dispatcher.Dispatch(pkt)
			}
		}(shards[i])
	}

	// Route packets to shards by MAC hash
	for pkt := range packetChan {
		idx := hashMAC(pkt.SrcMAC, k)
		shards[idx].ch <- pkt
	}

	// Close all shard channels and wait for workers
	for i := 0; i < k; i++ {
		close(shards[i].ch)
	}
	wg.Wait()

	// Merge all aggregator results
	return mergeShardResults(shards)
}

// mergeShardResults collects hosts from all aggregator shards into a single slice.
// Hosts with the same MAC are merged. Since the hash partitioning by SrcMAC
// ensures each MAC goes to exactly one shard, duplicate MACs across shards
// should not normally occur — but we handle it defensively.
func mergeShardResults(shards []analysisShard) []*model.Host {
	all := make(map[string]*model.Host)

	for _, s := range shards {
		for _, h := range s.aggregator.GetAll() {
			if existing, ok := all[h.MACStr]; ok {
				mergeHosts(existing, h)
			} else {
				all[h.MACStr] = h
			}
		}
	}

	hosts := make([]*model.Host, 0, len(all))
	for _, h := range all {
		hosts = append(hosts, h)
	}
	return hosts
}

// mergeHosts merges host b into host a (a is the target, b is the source).
func mergeHosts(a, b *model.Host) {
	// Merge protocols
	for _, p := range b.Protocols {
		found := false
		for _, ep := range a.Protocols {
			if ep == p {
				found = true
				break
			}
		}
		if !found {
			a.Protocols = append(a.Protocols, p)
		}
	}

	// Merge ports
	for _, p := range b.Ports {
		found := false
		for _, ep := range a.Ports {
			if ep == p {
				found = true
				break
			}
		}
		if !found {
			a.Ports = append(a.Ports, p)
		}
	}

	// Merge anomalies
	a.Anomalies = mergeAnomalySlices(a.Anomalies, b.Anomalies)

	// Take higher role
	a.Role = MergeRole(a.Role, b.Role)

	// Take latest timestamps
	if b.LastSeen.After(a.LastSeen) {
		a.LastSeen = b.LastSeen
	}
	if !b.FirstSeen.IsZero() && (a.FirstSeen.IsZero() || b.FirstSeen.Before(a.FirstSeen)) {
		a.FirstSeen = b.FirstSeen
	}

	// Merge info
	if b.Info != "" && a.Info == "" {
		a.Info = b.Info
	}
	if b.Hostname != "" && a.Hostname == "" {
		a.Hostname = b.Hostname
	}

	// Take better OS guess
	if b.OSScore > a.OSScore {
		a.OSGuess = b.OSGuess
		a.OSScore = b.OSScore
	}

	// Accumulate packet count
	a.PacketCount += b.PacketCount
}
