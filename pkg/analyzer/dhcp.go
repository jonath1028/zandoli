// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DHCPParser handles DHCP packet parsing with correlation cache
type DHCPParser struct {
	cache *DHCPCache
	log   *logger.Logger
}

// NewDHCPParser creates a new DHCP parser with all required fields.
// This constructor guarantees that a valid (non-nil) instance is always returned.
// Correct usage requires going through NewDispatcher for full initialization.
func NewDHCPParser(logger *logger.Logger, agg *Aggregator, opts *Options) *DHCPParser {
	return &DHCPParser{
		cache: NewDHCPCache(),
		log:   logger,
	}
}

// NewDHCPParserSimple creates a basic DHCP parser (backward compatibility).
// Used only by NewDispatcher for initialization.
func NewDHCPParserSimple() *DHCPParser {
	return &DHCPParser{
		cache: NewDHCPCache(),
		log:   nil,
	}
}

// SetLogger sets the logger for the DHCP parser
func (p *DHCPParser) SetLogger(log *logger.Logger) {
	p.log = log
}

// ParseDHCPPacket detects and parses DHCPv4 packets with exhaustive option extraction
func (p *DHCPParser) ParseDHCPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	// Nil-safety: guard against nil receivers
	if p == nil {
		// Silent log to avoid panics - the normal path goes through NewDispatcher
		return nil, errors.New("DHCP parser is nil; skipping")
	}

	if pkt.Payload == nil {
		return nil, errors.New("empty payload")
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		// Check if it is a UDP packet on DHCP ports
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if udp.SrcPort == 67 || udp.SrcPort == 68 || udp.DstPort == 67 || udp.DstPort == 68 {
				// Manually parse options in the UDP payload
				return p.parseDHCPOptionsManually(udp.Payload, pkt)
			}
		}
		return nil, nil
	}

	dhcp := dhcpLayer.(*layers.DHCPv4)
	return p.parseDHCPLayer(dhcp, pkt)
}

// parseDHCPLayer parses a gopacket DHCP layer
func (p *DHCPParser) parseDHCPLayer(dhcp *layers.DHCPv4, pkt model.PacketEvent) (*ParsedRecord, error) {
	// Nil-safety: guard against nil receivers
	if p == nil {
		// Silent log to avoid panics - the normal path goes through NewDispatcher
		return nil, errors.New("DHCP parser is nil; skipping")
	}

	// Extract the Transaction ID
	xid := dhcp.Xid
	clientMAC := pkt.SrcMAC.String()

	// Determine the message type and role
	msgType, role := p.determineMessageTypeAndRole(dhcp)

	// Get or create the cache entry
	cacheEntry := p.cache.GetOrCreate(xid, clientMAC)

	// Parse all DHCP options
	dhcpInfo := p.parseDHCPOptions(dhcp.Options, msgType)

	// Update the cache with new information
	p.updateCacheEntry(cacheEntry, dhcpInfo, dhcp, pkt)

	// Determine the record IP
	recordIP := p.determineRecordIP(dhcp, dhcpInfo, msgType)

	// Check if we should prevent attachment to an IPv6-only host
	if p.shouldPreventIPv6Attachment(recordIP, pkt) {
		// Keep pending - do not create a record for IPv6-only hosts
		if p.log != nil {
			p.log.Debug().
				Str("event", "dhcp_ipv6_only_blocked").
				Str("mac", clientMAC).
				Str("xid", fmt.Sprintf("%d", xid)).
				Msg("DHCP record blocked for IPv6-only host, waiting for IPv4")
		}
		return nil, nil
	}

	// Build the extra information
	extraInfo := p.buildExtraInfo(dhcpInfo, cacheEntry)

	// Build the role signals
	roleSignals := p.buildRoleSignals(msgType, dhcpInfo)

	// Build the textual info string
	info := p.buildInfoString(dhcpInfo, cacheEntry)

	// Extract source and destination IPs from the packet
	var ipSource, ipDest net.IP
	var l3Proto string

	// Reconstruct the packet from the payload to extract IPs
	if len(pkt.Payload) > 0 {
		packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			ipSource = ipv4.SrcIP
			ipDest = ipv4.DstIP
			l3Proto = "IPv4"
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6 := ipv6Layer.(*layers.IPv6)
			ipSource = ipv6.SrcIP
			ipDest = ipv6.DstIP
			l3Proto = "IPv6"
		}
	}

	// Create the record
	record := &ParsedRecord{
		MAC:         pkt.SrcMAC,
		IP:          recordIP,
		Protocols:   []string{"DHCP"},
		Role:        role,
		Info:        info,
		Hostname:    dhcpInfo.Hostname,
		Source:      "passive",
		FirstSeen:   pkt.Timestamp,
		LastSeen:    pkt.Timestamp,
		TTL:         int(pkt.TTL),
		VLANID:      pkt.VLANID,
		Extra:       extraInfo,
		RoleSignals: roleSignals,
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  l3Proto,
		AppProto: "DHCP",
		Strength: "high", // DHCP = high strength
	}

	// Log important information
	p.logDHCPParsing(record, dhcpInfo, xid)

	return record, nil
}

// DHCPInfo contains all information extracted from a DHCP packet
type DHCPInfo struct {
	MsgType      uint8         // Type de message DHCP
	SubnetMask   string        // Option 1: Subnet Mask
	Routers      []string      // Option 3: Router (liste)
	DNSServers   []string      // Option 6: DNS Servers (liste)
	DomainName   string        // Option 15: Domain Name
	LeaseTime    uint32        // Option 51: IP Address Lease Time
	ServerID     string        // Option 54: DHCP Server Identifier
	VendorClass  string        // Option 60: Vendor Class Identifier
	ClientID     string        // Option 61: Client Identifier (hex)
	FQDN         string        // Option 81: Client FQDN
	Routes       []DHCPRoute   // Option 121/249: Classless Static Route
	Relay        DHCPRelayInfo // Option 82: Relay Agent Information
	Hostname     string        // Option 12: Host Name
	ParameterReq []string      // Option 55: Parameter Request List
}

// determineMessageTypeAndRole determines the message type and role
func (p *DHCPParser) determineMessageTypeAndRole(dhcp *layers.DHCPv4) (uint8, string) {
	var msgType uint8
	role := "client" // default

	// Look for option 53 (Message Type)
	for _, option := range dhcp.Options {
		if option.Type == layers.DHCPOptMessageType && len(option.Data) > 0 {
			msgType = option.Data[0]
			break
		}
	}

	// Determine the role based on message type
	switch msgType {
	case 2: // DHCPOFFER
		role = "server"
	case 5: // DHCPACK
		role = "server"
	case 6: // DHCPNAK
		role = "server"
	case 7: // DHCPRELEASE
		role = "client"
	case 8: // DHCPINFORM
		role = "client"
	default:
		// DISCOVER, REQUEST, DECLINE, etc. = client
		role = "client"
	}

	return msgType, role
}

// parseDHCPOptions parses all important DHCP options
func (p *DHCPParser) parseDHCPOptions(options []layers.DHCPOption, msgType uint8) *DHCPInfo {
	info := &DHCPInfo{
		MsgType: msgType,
	}

	for _, option := range options {
		switch option.Type {
		case 1: // Subnet Mask
			if len(option.Data) >= 4 {
				ip := net.IP(option.Data[:4])
				if !ip.IsUnspecified() {
					info.SubnetMask = ip.String()
				}
			}

		case 3: // Router
			info.Routers = parseIPList(option.Data)

		case 6: // DNS Servers
			info.DNSServers = parseIPList(option.Data)

		case 12: // Host Name
			if len(option.Data) > 0 {
				info.Hostname = normalizeString(string(option.Data))
			}

		case 15: // Domain Name
			if len(option.Data) > 0 {
				info.DomainName = normalizeString(string(option.Data))
			}

		case 51: // IP Address Lease Time
			if len(option.Data) >= 4 {
				info.LeaseTime = uint32(option.Data[0])<<24 | uint32(option.Data[1])<<16 |
					uint32(option.Data[2])<<8 | uint32(option.Data[3])
			}

		case 54: // Server Identifier
			if len(option.Data) >= 4 {
				ip := net.IP(option.Data[:4])
				if !ip.IsUnspecified() {
					info.ServerID = ip.String()
				}
			}

		case 55: // Parameter Request List
			if len(option.Data) > 0 {
				for _, param := range option.Data {
					info.ParameterReq = append(info.ParameterReq, strconv.Itoa(int(param)))
				}
			}

		case 60: // Vendor Class Identifier
			if len(option.Data) > 0 {
				info.VendorClass = normalizeString(string(option.Data))
			}

		case 61: // Client Identifier
			if len(option.Data) > 0 {
				info.ClientID = normalizeBytes(option.Data)
			}

		case 81: // Client FQDN
			if len(option.Data) > 0 {
				// The first byte contains the flags, the rest is the name
				if len(option.Data) > 1 {
					info.FQDN = normalizeString(string(option.Data[1:]))
				}
			}

		case 121: // Classless Static Route (RFC3442)
			info.Routes = parseDHCPRoutes(option.Data)

		case 249: // Microsoft Classless Static Route
			// Parse the same way as option 121
			msftRoutes := parseDHCPRoutes(option.Data)
			info.Routes = append(info.Routes, msftRoutes...)

		case 82: // Relay Agent Information
			info.Relay = parseDHCPRelayInfo(option.Data)
		}
	}

	return info
}

// updateCacheEntry updates the cache entry with new information
func (p *DHCPParser) updateCacheEntry(entry *DHCPCacheEntry, info *DHCPInfo, dhcp *layers.DHCPv4, pkt model.PacketEvent) {
	// Update the basic information
	if info.ServerID != "" {
		entry.ServerIP = info.ServerID
	}
	if info.SubnetMask != "" {
		entry.SubnetMask = info.SubnetMask
	}
	if len(info.Routers) > 0 {
		entry.Router = info.Routers
	}
	if len(info.DNSServers) > 0 {
		entry.DNS = info.DNSServers
	}
	if info.DomainName != "" {
		entry.DomainName = info.DomainName
	}
	if info.LeaseTime > 0 {
		entry.LeaseTime = info.LeaseTime
	}
	if info.VendorClass != "" {
		entry.VendorClass = info.VendorClass
	}
	if info.ClientID != "" {
		entry.ClientID = info.ClientID
	}
	if info.FQDN != "" {
		entry.FQDN = info.FQDN
	}
	if len(info.Routes) > 0 {
		entry.Routes = info.Routes
	}
	if info.Relay.CircuitID != "" || info.Relay.RemoteID != "" {
		entry.Relay = info.Relay
	}

	// Update the client IP if available
	if dhcp.YourClientIP != nil && !dhcp.YourClientIP.IsUnspecified() {
		entry.ClientIP = dhcp.YourClientIP.String()
	} else if dhcp.ClientIP != nil && !dhcp.ClientIP.IsUnspecified() {
		entry.ClientIP = dhcp.ClientIP.String()
	}

	// Correlation log for debugging
	if p.log != nil {
		p.log.Debug().
			Str("event", "dhcp_cache_updated").
			Str("xid", fmt.Sprintf("%d", entry.XID)).
			Str("client_mac", entry.ClientMAC).
			Str("client_ip", entry.ClientIP).
			Str("server_ip", entry.ServerIP).
			Str("msg_type", fmt.Sprintf("%d", info.MsgType)).
			Msg("DHCP cache entry updated with correlation data")
	}
}

// determineRecordIP determines the IP to use for the record
func (p *DHCPParser) determineRecordIP(dhcp *layers.DHCPv4, info *DHCPInfo, msgType uint8) net.IP {
	// For server messages (OFFER/ACK), use yiaddr (IP offered to the client)
	if msgType == 2 || msgType == 5 { // DHCPOFFER or DHCPACK
		if dhcp.YourClientIP != nil && !dhcp.YourClientIP.IsUnspecified() {
			// Log the offered IP for correlation
			if p.log != nil {
				p.log.Debug().
					Str("event", "dhcp_ip_offered").
					Str("offered_ip", dhcp.YourClientIP.String()).
					Str("msg_type", fmt.Sprintf("%d", msgType)).
					Str("xid", fmt.Sprintf("%d", dhcp.Xid)).
					Msg("DHCP IP offered to client")
			}
			return dhcp.YourClientIP
		}
	}

	// For client messages, use ciaddr if available
	if dhcp.ClientIP != nil && !dhcp.ClientIP.IsUnspecified() {
		return dhcp.ClientIP
	}

	return nil
}

// buildExtraInfo builds the extra information for the record
func (p *DHCPParser) buildExtraInfo(info *DHCPInfo, cacheEntry *DHCPCacheEntry) map[string]string {
	extra := make(map[string]string)

	// Add DHCP information with stable keys
	if info.SubnetMask != "" {
		extra["dhcp.netmask"] = info.SubnetMask
	}
	if len(info.Routers) > 0 {
		extra["dhcp.router"] = strings.Join(info.Routers, ",")
	}
	if len(info.DNSServers) > 0 {
		extra["dhcp.dns"] = strings.Join(info.DNSServers, ",")
	}
	if info.DomainName != "" {
		extra["dhcp.domain"] = info.DomainName
	}
	if info.LeaseTime > 0 {
		extra["dhcp.lease"] = strconv.FormatUint(uint64(info.LeaseTime), 10)
	}
	if info.ServerID != "" {
		extra["dhcp.serverId"] = info.ServerID
	}
	if info.VendorClass != "" {
		extra["dhcp.vendorClass"] = info.VendorClass
	}
	if info.ClientID != "" {
		extra["dhcp.clientId"] = info.ClientID
	}
	if info.FQDN != "" {
		extra["dhcp.fqdn"] = info.FQDN
	}
	if len(info.Routes) > 0 {
		var routeStrs []string
		for _, route := range info.Routes {
			routeStrs = append(routeStrs, fmt.Sprintf("%s->%s", route.Prefix, route.NextHop))
		}
		extra["dhcp.routes"] = strings.Join(routeStrs, ",")
	}
	if info.Relay.CircuitID != "" || info.Relay.RemoteID != "" {
		relayInfo := fmt.Sprintf("circuit:%s,remote:%s", info.Relay.CircuitID, info.Relay.RemoteID)
		extra["dhcp.relay"] = relayInfo
	}

	// Add the message type and Transaction ID
	extra["dhcp.msgType"] = strconv.Itoa(int(info.MsgType))
	extra["dhcp.xid"] = strconv.FormatUint(uint64(cacheEntry.XID), 10)

	return extra
}

// shouldPreventIPv6Attachment checks if DHCP attachment to an IPv6-only host should be prevented
func (p *DHCPParser) shouldPreventIPv6Attachment(recordIP net.IP, pkt model.PacketEvent) bool {
	// Check if the packet is transported over IPv6
	if len(pkt.Payload) > 0 {
		packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			// The DHCP packet is transported over IPv6 - this is an IPv6-only host
			// Prevent attachment to avoid false positives
			return true
		}
	}

	// Check if the record IP is IPv6 link-local (fe80::/10)
	if recordIP != nil {
		if ipv6 := recordIP.To16(); ipv6 != nil && ipv6.To4() == nil {
			// Check if it is an IPv6 link-local address
			if len(ipv6) >= 2 && ipv6[0] == 0xfe && (ipv6[1]&0xc0) == 0x80 {
				// This is an IPv6 link-local address - prevent attachment
				return true
			}
		}
	}

	return false
}

// buildRoleSignals builds the role signals
func (p *DHCPParser) buildRoleSignals(msgType uint8, info *DHCPInfo) []string {
	var signals []string

	switch msgType {
	case 2, 5, 6: // OFFER, ACK, NAK
		signals = append(signals, "server_protocol:dhcp")
	case 1, 3, 4, 7, 8: // DISCOVER, REQUEST, DECLINE, RELEASE, INFORM
		signals = append(signals, "client_protocol:dhcp")
	}

	return signals
}

// buildInfoString builds the textual information string
func (p *DHCPParser) buildInfoString(info *DHCPInfo, cacheEntry *DHCPCacheEntry) string {
	var parts []string

	// Add the main information
	if len(info.Routers) > 0 {
		parts = append(parts, "Router:"+strings.Join(info.Routers, ","))
	}
	if len(info.DNSServers) > 0 {
		parts = append(parts, "DNS:"+strings.Join(info.DNSServers, ","))
	}
	if info.ServerID != "" {
		parts = append(parts, "Server:"+info.ServerID)
	}
	if info.DomainName != "" {
		parts = append(parts, "Domain:"+info.DomainName)
	}
	if info.VendorClass != "" {
		parts = append(parts, "VendorClass:"+info.VendorClass)
	}
	if info.ClientID != "" {
		parts = append(parts, "ClientID:"+info.ClientID)
	}
	if len(info.ParameterReq) > 0 {
		parts = append(parts, "Params:["+strings.Join(info.ParameterReq, ",")+"]")
	}

	return strings.Join(parts, " ")
}

// logDHCPParsing logs important DHCP parsing information
func (p *DHCPParser) logDHCPParsing(record *ParsedRecord, info *DHCPInfo, xid uint32) {
	if p.log == nil {
		return
	}

	// Log the DHCP server identification
	if record.Role == "server" && info.ServerID != "" {
		p.log.Debug().
			Str("event", "dhcp_server_identified").
			Str("server_ip", info.ServerID).
			Str("mac", record.MAC.String()).
			Uint32("xid", xid).
			Msg("DHCP server identified")
	}

	// Log the DHCP subnet addition
	if info.SubnetMask != "" && record.IP != nil {
		// Calculate the exact CIDR
		ip := record.IP.To4()
		if ip != nil {
			mask := net.ParseIP(info.SubnetMask).To4()
			if mask != nil {
				ones, _ := net.IPMask(mask).Size()
				subnet := ip.Mask(net.CIDRMask(ones, 32))
				cidr := fmt.Sprintf("%s/%d", subnet.String(), ones)

				p.log.Debug().
					Str("event", "dhcp_subnet_added").
					Str("cidr", cidr).
					Str("source", "dhcp").
					Str("evidence", "option1").
					Msg("DHCP subnet added")
			}
		}
	}

	// Log ignored options (if needed)
	// This section can be extended to log malformed options
}

// parseDHCPOptionsManually parses DHCP options manually from the UDP payload
func (p *DHCPParser) parseDHCPOptionsManually(payload []byte, pkt model.PacketEvent) (*ParsedRecord, error) {
	// Look for option 12 (Host Name) anywhere in the payload
	hostname := ""
	for i := 0; i < len(payload)-1; i++ {
		if payload[i] == 12 { // Option 12: Host Name
			if i+1 < len(payload) {
				length := int(payload[i+1])
				if i+2+length <= len(payload) {
					hostname = normalizeString(string(payload[i+2 : i+2+length]))
					break
				}
			}
		}
	}

	// Extract source and destination IPs from the packet
	var ipSource, ipDest net.IP
	var l3Proto string

	// Reconstruct the packet from the payload to extract IPs
	if len(pkt.Payload) > 0 {
		packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			ipSource = ipv4.SrcIP
			ipDest = ipv4.DstIP
			l3Proto = "IPv4"
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6 := ipv6Layer.(*layers.IPv6)
			ipSource = ipv6.SrcIP
			ipDest = ipv6.DstIP
			l3Proto = "IPv6"
		}
	}

	// Check if we should prevent attachment to an IPv6-only host
	if p.shouldPreventIPv6Attachment(nil, pkt) {
		// Keep pending - do not create a record for IPv6-only hosts
		if p.log != nil {
			p.log.Debug().
				Str("event", "dhcp_manual_ipv6_only_blocked").
				Str("mac", pkt.SrcMAC.String()).
				Msg("DHCP manual record blocked for IPv6-only host, waiting for IPv4")
		}
		return nil, nil
	}

	// Create a basic record for malformed DHCP packets
	return &ParsedRecord{
		MAC:         pkt.SrcMAC,
		Protocols:   []string{"DHCP"},
		Role:        "client", // Default for malformed packets
		Hostname:    hostname,
		Source:      "passive",
		FirstSeen:   pkt.Timestamp,
		LastSeen:    pkt.Timestamp,
		TTL:         int(pkt.TTL),
		VLANID:      pkt.VLANID,
		Extra:       make(map[string]string),
		RoleSignals: []string{"client_protocol:dhcp"},
		// New fields
		IPSource: ipSource,
		IPDest:   ipDest,
		L3Proto:  l3Proto,
		AppProto: "DHCP",
		Strength: "high", // DHCP = high strength
	}, nil
}
