// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/binary"
	"sync/atomic"
	"time"
	"zandoli/internal/logger"
	"zandoli/internal/oui"
	"zandoli/pkg/model"
	"zandoli/pkg/sniffer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ProtocolPortMap defines default ports for known protocols
var ProtocolPortMap = map[string]struct {
	Port      int
	Transport string
}{
	"MDNS":  {5353, "udp"},
	"SSDP":  {1900, "udp"},
	"LLMNR": {5355, "udp"},
	"NBNS":  {137, "udp"},
	"DHCP":  {67, "udp"},
	"NTP":   {123, "udp"},
}

// addProtocolPorts adds default ports for known protocols to the ParsedRecord
func addProtocolPorts(record *ParsedRecord) {
	if record == nil || len(record.Protocols) == 0 {
		return
	}
	if record.Ports == nil {
		record.Ports = []int{}
	}
	for _, protocol := range record.Protocols {
		if portInfo, exists := ProtocolPortMap[protocol]; exists {
			portExists := false
			for _, existingPort := range record.Ports {
				if existingPort == portInfo.Port {
					portExists = true
					break
				}
			}
			if !portExists {
				record.Ports = append(record.Ports, portInfo.Port)
			}
		}
	}
}

// ParseError represents an error during packet parsing
type ParseError struct {
	Message string
}

func (e *ParseError) Error() string {
	return e.Message
}

// Options represents configuration options for the Dispatcher
type Options struct {
	EnableMetrics bool
	SampleRate    int
	Workers       int
	TraceEnabled  bool
	OUIMap        *oui.Map
}

// ParseFunc is the standard signature for protocol parsers
type ParseFunc func(pkt model.PacketEvent) (*ParsedRecord, error)

// dispatchOpts controls per-call behavior of the generic dispatch helper
type dispatchOpts struct {
	transport string
	srcPort   uint16
	dstPort   uint16
	addPorts  bool // run addProtocolPorts on the result
}

// Dispatcher routes raw packets to protocol parsers and sends results to the aggregator.
type Dispatcher struct {
	log                   *logger.Logger
	aggregator            HostAggregator
	perfMetrics           *sniffer.AnalyzerMetrics
	arpDetector           *ARPAnomalyDetector
	dhcpParser            *DHCPParser
	igmpParser            *IGMPParser
	traceEnabled          bool
	processedPacketsCount uint64 // atomic
}

// NewDispatcher creates a new dispatcher with all parsers initialized.
func NewDispatcher(log *logger.Logger, agg HostAggregator, opts *Options, metrics *sniffer.AnalyzerMetrics) *Dispatcher {
	agg.SetLogger(log)

	dhcpParser := NewDHCPParserSimple()
	dhcpParser.SetLogger(log)

	igmpParser := NewIGMPParser(log)

	var perfMetrics *sniffer.AnalyzerMetrics
	if metrics != nil {
		perfMetrics = metrics
	} else if opts != nil {
		perfMetrics = sniffer.NewAnalyzerMetricsWithOptions(log, opts.EnableMetrics, opts.SampleRate)
	} else {
		perfMetrics = sniffer.NewAnalyzerMetricsWithOptions(log, false, 0)
	}

	traceEnabled := false
	if opts != nil {
		traceEnabled = opts.TraceEnabled
	}

	log.Debug().
		Bool("dhcp_parser", dhcpParser != nil).
		Bool("igmp_parser", igmpParser != nil).
		Bool("arp_detector", true).
		Bool("metrics_enabled", perfMetrics != nil).
		Bool("trace_enabled", traceEnabled).
		Msg("dispatcher: initialized analyzers")

	return &Dispatcher{
		log:          log,
		aggregator:   agg,
		perfMetrics:  perfMetrics,
		arpDetector:  NewARPAnomalyDetector(),
		dhcpParser:   dhcpParser,
		igmpParser:   igmpParser,
		traceEnabled: traceEnabled,
	}
}

// NewDispatcherSimple creates a new dispatcher with basic configuration (backward compatibility).
func NewDispatcherSimple(log *logger.Logger, agg HostAggregator) *Dispatcher {
	return NewDispatcher(log, agg, nil, nil)
}

// NewDispatcherWithMetrics creates a new dispatcher with custom performance metrics (backward compatibility).
func NewDispatcherWithMetrics(log *logger.Logger, agg HostAggregator, perfMetrics *sniffer.AnalyzerMetrics) *Dispatcher {
	return NewDispatcher(log, agg, nil, perfMetrics)
}

// NewDispatcherWithOptions creates a new dispatcher with performance options (backward compatibility).
func NewDispatcherWithOptions(log *logger.Logger, agg HostAggregator, enableMetrics bool, sampleRate int) *Dispatcher {
	opts := &Options{
		EnableMetrics: enableMetrics,
		SampleRate:    sampleRate,
	}
	return NewDispatcher(log, agg, opts, nil)
}

// dispatchProtocol is the generic dispatch helper that eliminates per-protocol boilerplate.
// It measures execution, handles errors/nil/trace, sets transport info, and merges results.
func (d *Dispatcher) dispatchProtocol(name string, pkt model.PacketEvent, parseFn ParseFunc, opts dispatchOpts) {
	var res *ParsedRecord
	err := d.perfMetrics.MeasureExecution(name, func() error {
		var parseErr error
		res, parseErr = parseFn(pkt)
		return parseErr
	})
	if err != nil {
		d.log.Warn().Str("proto", name).Str("src_mac", pkt.SrcMAC.String()).Err(err).Msgf("%s parse error", name)
	} else if res != nil {
		if opts.transport != "" {
			res.Transport = opts.transport
		}
		res.SrcPort = opts.srcPort
		res.DstPort = opts.dstPort
		if opts.addPorts {
			addProtocolPorts(res)
		}
		d.log.Trace().Str("proto", name).Str("src_mac", pkt.SrcMAC.String()).Msg(name + " match")
		d.aggregator.Merge(res)
		d.incrementProcessedPackets()
	} else if d.traceEnabled {
		d.log.Trace().Str("proto", name).Msg("no match")
	}
}

// Dispatch inspects the packet and invokes protocol-specific parsers with early filtering.
func (d *Dispatcher) Dispatch(pkt model.PacketEvent) {
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	switch eth.EthernetType {
	case 0x88cc: // LLDP
		d.dispatchProtocol("LLDP", pkt, ParseLLDPPacket, dispatchOpts{transport: "none"})
	case 0x2000: // CDP direct
		d.dispatchProtocol("CDP", pkt, ParseCDPPacket, dispatchOpts{transport: "none"})
	case 0x888e: // 802.1X
		d.dispatchProtocol("802.1X", pkt, ParseEAPOLPacket, dispatchOpts{transport: "none"})
	case 0x0806: // ARP
		d.processARP(pkt)
	case 0x0800: // IPv4
		d.processIPv4Protocols(packet, pkt)
	case 0x86dd: // IPv6
		d.processIPv6Protocols(packet, pkt)
	default:
		// Try CDP over LLC/SNAP for any unrecognized EtherType.
		// 802.3 frames carry the frame length instead of an EtherType (< 0x0600),
		// but some PCAPs use non-standard EtherType values for LLC-encapsulated frames.
		// processCDPLLCSNAP validates the LLC/SNAP header before parsing.
		d.processCDPLLCSNAP(pkt)
		d.dispatchProtocol("STP", pkt, ParseSTPPacket, dispatchOpts{transport: "none"})
		d.processVLAN(packet, pkt)
	}
}

// processARP handles ARP with anomaly detection (special: uses arpDetector, non-standard ParseFunc)
func (d *Dispatcher) processARP(pkt model.PacketEvent) {
	d.dispatchProtocol("ARP", pkt, func(p model.PacketEvent) (*ParsedRecord, error) {
		res := ParseARPPacketWithAnomalyDetectionAndType(p, d.arpDetector)
		if res == nil {
			return nil, &ParseError{Message: "ARP parsing returned nil"}
		}
		res.Transport = "none"
		return res, nil
	}, dispatchOpts{})
}

// processCDPLLCSNAP handles CDP over LLC/SNAP frames
func (d *Dispatcher) processCDPLLCSNAP(pkt model.PacketEvent) {
	if len(pkt.Payload) < 14+8 {
		return
	}
	llcHeader := pkt.Payload[14:22]
	if llcHeader[0] != 0xAA || llcHeader[1] != 0xAA || llcHeader[2] != 0x03 {
		return
	}
	oui := binary.BigEndian.Uint32(append([]byte{0}, llcHeader[3:6]...))
	pid := binary.BigEndian.Uint16(llcHeader[6:8])
	if oui != 0x00000c || pid != 0x2000 {
		return
	}
	cdpPkt := model.PacketEvent{
		SrcMAC:    pkt.SrcMAC,
		Payload:   pkt.Payload[22:],
		Timestamp: pkt.Timestamp,
	}
	d.dispatchProtocol("CDP_LLC_SNAP", cdpPkt, ParseCDPPacket, dispatchOpts{transport: "none"})
}

// processIPv4Protocols handles IPv4-based protocols (UDP/TCP/IGMP)
func (d *Dispatcher) processIPv4Protocols(packet gopacket.Packet, pkt model.PacketEvent) {
	d.processVLAN(packet, pkt)

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		if ipv4.Protocol == 2 {
			d.processIGMP(pkt)
		}
		if ipv4.Protocol == 112 { // VRRP
			d.dispatchProtocol("VRRP", pkt, ParseVRRPPacket, dispatchOpts{transport: "none"})
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		d.processUDPProtocols(udp, pkt)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		d.processTCPProtocols(tcp, pkt)
	}
}

// processIPv6Protocols handles IPv6-based protocols (UDP/TCP/ICMPv6)
func (d *Dispatcher) processIPv6Protocols(packet gopacket.Packet, pkt model.PacketEvent) {
	d.processVLAN(packet, pkt)

	if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil {
		d.dispatchProtocol("NDP", pkt, ParseNDPPacket, dispatchOpts{transport: "none"})
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		d.processUDPProtocols(udp, pkt)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		d.processTCPProtocols(tcp, pkt)
	}
}

// processUDPProtocols handles UDP-based protocol analysis
func (d *Dispatcher) processUDPProtocols(udp *layers.UDP, pkt model.PacketEvent) {
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// DHCPv4
	if (udp.SrcPort == 67 && udp.DstPort == 68) || (udp.SrcPort == 68 && udp.DstPort == 67) {
		d.processDHCP(pkt, "udp", srcPort, dstPort)
	} else if udp.SrcPort == 546 || udp.DstPort == 546 || udp.SrcPort == 547 || udp.DstPort == 547 {
		d.log.Debug().Uint16("src_port", srcPort).Uint16("dst_port", dstPort).
			Msg("ignoring DHCPv6 packet - not supported by current parser")
	}
	if udp.SrcPort == 137 || udp.DstPort == 137 {
		d.dispatchProtocol("NetBIOS", pkt, ParseNetBIOSPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort, addPorts: true})
	}
	if udp.SrcPort == 5355 || udp.DstPort == 5355 {
		d.dispatchProtocol("LLMNR", pkt, ParseLLMNRPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort, addPorts: true})
	}
	if udp.SrcPort == 5353 || udp.DstPort == 5353 {
		d.dispatchProtocol("mDNS", pkt, ParseMDNSPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort, addPorts: true})
	}
	if udp.SrcPort == 1900 || udp.DstPort == 1900 {
		d.dispatchProtocol("SSDP", pkt, ParseSSDPPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort, addPorts: true})
	}
	if udp.SrcPort == 53 || udp.DstPort == 53 {
		d.dispatchProtocol("DNS", pkt, ParseDNSPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort})
	}
	if udp.SrcPort == 1985 || udp.DstPort == 1985 {
		d.dispatchProtocol("HSRP", pkt, ParseHSRPPacket, dispatchOpts{transport: "udp", srcPort: srcPort, dstPort: dstPort})
	}
}

// processTCPProtocols handles TCP-based protocol analysis
func (d *Dispatcher) processTCPProtocols(tcp *layers.TCP, pkt model.PacketEvent) {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	if (tcp.SYN && !tcp.ACK) || (tcp.SYN && tcp.ACK) {
		d.dispatchProtocol("TCP_OS", pkt, ParseTCPPacket, dispatchOpts{transport: "tcp", srcPort: srcPort, dstPort: dstPort})
	}
	if tcp.SrcPort == 445 || tcp.DstPort == 445 {
		d.dispatchProtocol("SMB", pkt, ParseSMBPacket, dispatchOpts{transport: "tcp", srcPort: srcPort, dstPort: dstPort})
	}
}

// processVLAN handles VLAN packet processing
func (d *Dispatcher) processVLAN(packet gopacket.Packet, pkt model.PacketEvent) {
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		d.dispatchProtocol("VLAN", pkt, ParseVLANTag, dispatchOpts{transport: "none"})
	}
}

// processDHCP handles DHCP with its special dhcpParser instance
func (d *Dispatcher) processDHCP(pkt model.PacketEvent, transport string, srcPort, dstPort uint16) {
	if d.dhcpParser == nil {
		d.log.Warn().Msg("DHCP parser not initialized; skipping DHCP packet")
		return
	}
	d.dispatchProtocol("DHCP", pkt, d.dhcpParser.ParseDHCPPacket, dispatchOpts{
		transport: transport,
		srcPort:   srcPort,
		dstPort:   dstPort,
		addPorts:  true,
	})
}

// processIGMP handles IGMP with pre-logging of IP metadata
func (d *Dispatcher) processIGMP(pkt model.PacketEvent) {
	if d.igmpParser == nil {
		d.log.Warn().Msg("IGMP parser not initialized; skipping")
		return
	}

	// Pre-logging of IP metadata for diagnostics
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)
	var srcIP, dstIP string
	var ipID uint16
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		ipID = ipv4.Id
	}
	d.log.Debug().Str("proto", "IGMP").Str("src_mac", pkt.SrcMAC.String()).
		Str("src_ip", srcIP).Str("dst_ip", dstIP).Uint16("ip_id", ipID).
		Msg("processing IGMP packet")

	d.dispatchProtocol("IGMP", pkt, ParseIGMPPacket, dispatchOpts{transport: "none"})
}

// GetPerformanceMetrics returns the performance metrics for this dispatcher
func (d *Dispatcher) GetPerformanceMetrics() *sniffer.AnalyzerMetrics {
	return d.perfMetrics
}

// LogPerformanceStats logs the performance statistics
func (d *Dispatcher) LogPerformanceStats() {
	d.perfMetrics.LogStatsWithProcessedPackets(d.GetProcessedPacketsCount())
}

// GetProcessedPacketsCount returns the number of successfully processed packets
func (d *Dispatcher) GetProcessedPacketsCount() uint64 {
	return atomic.LoadUint64(&d.processedPacketsCount)
}

// incrementProcessedPackets increments the processed packets counter
func (d *Dispatcher) incrementProcessedPackets() {
	atomic.AddUint64(&d.processedPacketsCount, 1)
}

// CleanupARPData cleans old ARP data to avoid memory leaks
func (d *Dispatcher) CleanupARPData(cutoff time.Time) {
	if d.arpDetector != nil {
		d.arpDetector.CleanupOldData(cutoff)
	}
}
