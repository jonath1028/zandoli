package analyzer

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"zandoli/internal/logger"
	"zandoli/internal/oui"
	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

// Aggregator accumulates parsed records and merges them into Host objects by MAC address.
type Aggregator struct {
	mu       sync.Mutex
	cache    map[string]*model.Host
	ttlCache map[string][]int
	ipToMacs map[string][]string // IP -> list of MAC addresses
	macToIPs map[string][]string // MAC -> list of IP addresses
	log      *logger.Logger
	ouiMap   *oui.Map // OUI map for vendor resolution
}

// NewAggregator creates a new Aggregator instance.
// OUI data is NOT loaded automatically — call SetOUIMap() to inject it.
func NewAggregator() *Aggregator {
	return &Aggregator{
		cache:    make(map[string]*model.Host),
		ttlCache: make(map[string][]int),
		ipToMacs: make(map[string][]string),
		macToIPs: make(map[string][]string),
	}
}

// NewAggregatorWithLogger creates a new Aggregator instance with logging support.
// OUI data is NOT loaded automatically — call SetOUIMap() to inject it.
func NewAggregatorWithLogger(log *logger.Logger) *Aggregator {
	return &Aggregator{
		cache:    make(map[string]*model.Host),
		ttlCache: make(map[string][]int),
		ipToMacs: make(map[string][]string),
		macToIPs: make(map[string][]string),
		log:      log,
	}
}

// SetLogger sets the logger for the aggregator.
func (a *Aggregator) SetLogger(log *logger.Logger) {
	a.log = log
}

// SetOUIMap injects the OUI map for vendor resolution.
func (a *Aggregator) SetOUIMap(m *oui.Map) {
	a.ouiMap = m
}

// Merge integrates a ParsedRecord into the aggregation cache.
func (a *Aggregator) Merge(record *ParsedRecord) {
	if record == nil || record.MAC == nil {
		return
	}

	macStr := record.MAC.String()
	vendor := ""
	if a.ouiMap != nil {
		vendor = a.ouiMap.VendorFromMAC(macStr)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	host, exists := a.cache[macStr]
	if !exists {
		// Safe initialization
		firstSeen := record.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = time.Now().UTC()
		}

		lastSeen := record.LastSeen
		if lastSeen.IsZero() {
			lastSeen = time.Now().UTC()
		}

		host = &model.Host{
			MAC:       record.MAC,
			MACStr:    macStr,
			Protocols: []string{},
			Anomalies: []model.Anomaly{},
			Ports:     []int{},
			OSScore:   0,
			Source:    record.Source,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			Vendor:    vendor,
			Category:  InferCategory(vendor),
			VLANStats: make(map[int]int),
		}

		a.cache[macStr] = host

		// Log host creation
		if a.log != nil {
			ipStr := ""
			if record.IP != nil {
				ipStr = record.IP.String()
			}
			a.log.Debug().
				Str("event", "host_created").
				Str("mac", macStr).
				Str("ip", ipStr).
				Str("vendor", vendor).
				Msg("aggregator created host")
		}
	}

	// If the vendor was discovered or updated and the category is still unknown
	if vendor != "" && host.Vendor == "" {
		host.Vendor = vendor
		host.Category = InferCategory(vendor)
	}

	// Update IP <-> MAC mappings for anomaly detection
	if record.IP != nil {
		ipStr := record.IP.String()

		// Add MAC to the list of MACs for this IP
		if !utils.ContainsString(a.ipToMacs[ipStr], macStr) {
			a.ipToMacs[ipStr] = append(a.ipToMacs[ipStr], macStr)
		}

		// Add IP to the list of IPs for this MAC
		if !utils.ContainsString(a.macToIPs[macStr], ipStr) {
			a.macToIPs[macStr] = append(a.macToIPs[macStr], ipStr)
		}

		// Update the host's IP
		host.IP = record.IP
	}

	// Increment packet counter for ARP storm detection
	host.PacketCount++

	// Logical merge
	if len(record.Protocols) > 0 {
		host.Protocols = utils.MergeStrUnique(host.Protocols, record.Protocols)
		// Recalculate OnlyARP after merging protocols
		host.OnlyARP = calculateOnlyARP(host.Protocols)
	}
	if record.Info != "" {
		// Do not overwrite host.Info with VLAN IDs or hostnames
		// as they are now managed via the dedicated Hostname and VLANs fields
		if !containsVLANInfo(record.Info) {
			host.Info = mergeHostInfo(host.Info, record.Info)
		}
	}
	// Convert record anomalies to Anomaly struct if needed
	recordAnomalies := make([]model.Anomaly, len(record.Anomalies))
	for i, anomaly := range record.Anomalies {
		recordAnomalies[i] = model.Anomaly{
			Description: anomaly,
			Severity:    "low", // By default, record anomalies are low severity
			Type:        "",    // Legacy anomaly without type
			Parameters:  nil,   // No parameters for legacy anomalies
		}
	}
	host.Anomalies = mergeAnomalySlices(host.Anomalies, recordAnomalies)
	host.Ports = utils.MergeIntUnique(host.Ports, record.Ports)

	if record.Role != "" {
		host.Role = MergeRole(host.Role, record.Role)
	}

	// Infer role with confidence and signals
	roleInfo := InferRole(host)
	if roleInfo != nil {
		host.RoleInfo = roleInfo
		host.RoleConfidence = roleInfo.Confidence
		host.RoleSignals = roleInfo.Signals
		// Update the legacy Role field with the inferred role for backward compatibility
		if host.Role == "" || roleInfo.Confidence > 80 {
			host.Role = roleInfo.Role
		}
	}

	// Hostname management: set if empty, keep the first value if different
	if record.Hostname != "" {
		if host.Hostname == "" {
			host.Hostname = record.Hostname
		}
		// If host.Hostname is already set and different, keep the first value (no overwriting)
	}

	// VLAN management: add only if not already present
	if record.VLANID > 0 {
		host.AddVLAN(record.VLANID)
	}
	if record.TTL > 0 {
		a.ttlCache[macStr] = append(a.ttlCache[macStr], record.TTL)
		sum := 0
		for _, val := range a.ttlCache[macStr] {
			sum += val
		}
		// Calculate the average with rounding as specified
		avgFloat := float64(sum) / float64(len(a.ttlCache[macStr]))
		host.TTLAvg = uint8(avgFloat + 0.5) // Round to the nearest integer
	}
	if record.OnlyARP {
		host.OnlyARP = true
	}
	// OS Fingerprinting data
	if record.OSGuess != "" {
		host.OSGuess = record.OSGuess
	}
	if record.TCPOpts != nil {
		host.TCPOpts = record.TCPOpts
	}
	if record.OSScore > 0 {
		host.OSScore = uint8(record.OSScore)
	}

	// Merge detailed TCP options for OS fingerprinting
	if record.TCPOptions != nil {
		// Use mergeTCPFingerprint function to intelligently merge TCP data
		mergeTCPFingerprint(host, record)
	}

	// Merge CDP information
	if record.CDP != nil {
		host.CDP = record.CDP
	}

	// Merge LLDP information
	if record.LLDP != nil {
		host.LLDP = record.LLDP
	}

	// Re-run weighted OS detection after merging all data
	osResult := GuessOSWeighted(host)
	// ONLY overwrite if the new score is better, or if the current guess is empty/Unknown
	if uint8(osResult.Score) >= host.OSScore || host.OSGuess == "" || host.OSGuess == "Unknown" {
		if osResult.Family != "Unknown" || host.OSGuess == "" {
			host.OSGuess = osResult.Family
		}
		host.OSScore = uint8(osResult.Score)
		if len(osResult.Signals) > 0 {
			host.OSSignals = osResult.Signals
		}
	}

	// Merge STP information
	if record.STPInfo != nil {
		host.STP = record.STPInfo
	}

	// Merge gateway redundancy information (HSRP/VRRP)
	if record.GatewayRedundancy != nil {
		hadGR := len(host.GatewayRedundancy) > 0
		mergeGatewayRedundancy(host, record.GatewayRedundancy)
		// Log plaintext auth capture once per host (security finding)
		if !hadGR && a.log != nil {
			for _, gr := range record.GatewayRedundancy.Groups {
				if gr.Auth != "" {
					a.log.Warn().
						Str("protocol", record.GatewayRedundancy.Protocol).
						Str("auth", gr.Auth).
						Str("vip", gr.VirtualIP).
						Int("group", gr.GroupID).
						Str("mac", macStr).
						Msg("plaintext authentication captured — security finding")
				}
			}
		}
	}

	// Always try to create detailed TCP options from tcpOpts if we have TCP data
	if len(record.TCPOpts) > 0 {
		if host.TCPOptions == nil {
			host.TCPOptions = &model.TCPOptions{}
		}
		// Parse the TCP options strings to populate the detailed structure
		for _, opt := range record.TCPOpts {
			if strings.HasPrefix(opt, "MSS:") {
				if mss, err := strconv.Atoi(strings.TrimPrefix(opt, "MSS:")); err == nil {
					host.TCPOptions.MSS = mss
				}
			} else if strings.HasPrefix(opt, "WSCALE:") {
				if wscale, err := strconv.Atoi(strings.TrimPrefix(opt, "WSCALE:")); err == nil {
					host.TCPOptions.WSCALE = wscale
				}
			} else if opt == "SACK_PERMITTED" {
				host.TCPOptions.SACKPermitted = true
			} else if opt == "TIMESTAMP" {
				host.TCPOptions.Timestamp = true
			} else if strings.HasPrefix(opt, "NOP:") {
				if nop, err := strconv.Atoi(strings.TrimPrefix(opt, "NOP:")); err == nil {
					host.TCPOptions.NOPCount = nop
				}
			}
			host.TCPOptions.Order = append(host.TCPOptions.Order, opt)
		}
	}

	// Update Window Size if available
	if record.WindowSize > 0 {
		host.WindowSize = record.WindowSize
	}

	if !record.FirstSeen.IsZero() && (host.FirstSeen.IsZero() || record.FirstSeen.Before(host.FirstSeen)) {
		host.FirstSeen = record.FirstSeen
	}
	if !record.LastSeen.IsZero() && record.LastSeen.After(host.LastSeen) {
		host.LastSeen = record.LastSeen
	}

	// Re-classify after each merge — higher-confidence signals override vendor-only guesses
	classification := ClassifyHost(host)
	host.Category = classification.Category
}

// GetAll returns all aggregated hosts in thread-safe manner.
func (a *Aggregator) GetAll() []*model.Host {
	a.mu.Lock()
	defer a.mu.Unlock()

	hosts := make([]*model.Host, 0, len(a.cache))
	for _, h := range a.cache {
		// Recalculate OnlyARP for all hosts before returning them
		h.OnlyARP = calculateOnlyARP(h.Protocols)
		
		// Categorize ports into TCP/UDP services for exports and role inference
		h.CategorizePorts()
		
		hosts = append(hosts, h)
	}
	return hosts
}

// DetectAnomalies analyses IP <-> MAC mappings to detect anomalies
// and adds them to the relevant hosts with severity scores.
func (a *Aggregator) DetectAnomalies() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Detect "IP duplicate": same IP for multiple MACs (severity: medium)
	for ip, macs := range a.ipToMacs {
		if len(macs) > 1 {
			anomaly := model.NewAnomaly(
				"ip_duplicate",
				"medium",
				"IP duplicate",
				map[string]interface{}{
					"ip":   ip,
					"macs": macs,
				},
			)
			for _, macStr := range macs {
				if host, exists := a.cache[macStr]; exists {
					if !containsAnomaly(host.Anomalies, anomaly) {
						host.Anomalies = append(host.Anomalies, anomaly)
					}
				}
			}
		}
	}

	// Detect "MAC multiple IP": same MAC with multiple IPs (severity: medium)
	// Do not flag if exactly one IPv4 and one IPv6 (normal dual-stack)
	for mac, ips := range a.macToIPs {
		if len(ips) > 1 {
			// Check if this is a normal dual-stack case (exactly 1 IPv4 and 1 IPv6)
			hasIPv4 := false
			hasIPv6 := false
			for _, ipStr := range ips {
				if ip := net.ParseIP(ipStr); ip != nil {
					if ip.To4() != nil {
						hasIPv4 = true
					} else {
						hasIPv6 = true
					}
				}
			}

			// If not a normal dual-stack case, flag the anomaly
			if !(hasIPv4 && hasIPv6 && len(ips) == 2) {
				anomaly := model.NewMACMultipleIPAnomaly(ips)
				if host, exists := a.cache[mac]; exists {
					if !containsAnomaly(host.Anomalies, anomaly) {
						host.Anomalies = append(host.Anomalies, anomaly)
					}
				}
			}
		}
	}

	// Detect "silent host": OnlyARP host with no protocol or port (severity: low)
	for _, host := range a.cache {
		if host.OnlyARP && len(host.Protocols) == 0 && len(host.Ports) == 0 {
			anomaly := model.NewAnomaly(
				"silent_host",
				"low",
				"silent host",
				map[string]interface{}{
					"mac": host.MACStr,
				},
			)
			if !containsAnomaly(host.Anomalies, anomaly) {
				host.Anomalies = append(host.Anomalies, anomaly)
			}
		}
	}

	// Detect "ARP storm": host with many ARP packets (severity: high)
	for _, host := range a.cache {
		if host.OnlyARP && host.PacketCount > 100 { // Arbitrary threshold for ARP storm detection
			// Calculate approximate PPS based on observation duration
			duration := host.LastSeen.Sub(host.FirstSeen).Seconds()
			if duration > 0 {
				pps := int(float64(host.PacketCount) / duration)
				anomaly := model.NewARPStormAnomaly(pps, int(duration))
				if !containsAnomaly(host.Anomalies, anomaly) {
					host.Anomalies = append(host.Anomalies, anomaly)
				}
			}
		}
	}

	// Detect "Multiple DHCP servers": count hosts with DHCP and Role == "server" (severity: high)
	dhcpServers := make([]string, 0)
	for mac, host := range a.cache {
		if host.Role == "server" && utils.ContainsString(host.Protocols, "DHCP") {
			dhcpServers = append(dhcpServers, mac)
		}
	}
	if len(dhcpServers) > 1 {
		anomaly := model.NewAnomaly(
			"multiple_dhcp_servers",
			"high",
			"Multiple DHCP servers",
			map[string]interface{}{
				"count": len(dhcpServers),
				"macs":  dhcpServers,
			},
		)
		for _, mac := range dhcpServers {
			if host, exists := a.cache[mac]; exists {
				if !containsAnomaly(host.Anomalies, anomaly) {
					host.Anomalies = append(host.Anomalies, anomaly)
				}
			}
		}
	}

	// Detect "Multiple STP roots": count STP hosts claiming to be root (severity: high)
	stpRoots := make([]string, 0)
	for mac, host := range a.cache {
		if utils.ContainsString(host.Protocols, "STP") && host.Info != "" {
			// Parse STP information to check if stpRoot=true
			if strings.Contains(host.Info, "stpRoot=true") {
				stpRoots = append(stpRoots, mac)
			}
		}
	}
	if len(stpRoots) > 1 {
		anomaly := model.NewAnomaly(
			"multiple_stp_roots",
			"high",
			"Multiple STP roots",
			map[string]interface{}{
				"count": len(stpRoots),
				"macs":  stpRoots,
			},
		)
		for _, mac := range stpRoots {
			if host, exists := a.cache[mac]; exists {
				if !containsAnomaly(host.Anomalies, anomaly) {
					host.Anomalies = append(host.Anomalies, anomaly)
				}
			}
		}
	}

	// Detect "Duplicate hostnames": same hostname for multiple MACs (severity: low)
	hostnameMap := make(map[string][]string) // hostname -> list of MACs
	for mac, host := range a.cache {
		if host.Hostname != "" {
			hostnameMap[host.Hostname] = append(hostnameMap[host.Hostname], mac)
		}
	}
	for hostname, macs := range hostnameMap {
		if len(macs) > 1 {
			anomaly := model.NewAnomaly(
				"duplicate_hostname",
				"low",
				fmt.Sprintf("Duplicate hostname: %s", hostname),
				map[string]interface{}{
					"hostname": hostname,
					"macs":     macs,
				},
			)
			for _, mac := range macs {
				if host, exists := a.cache[mac]; exists {
					if !containsAnomaly(host.Anomalies, anomaly) {
						host.Anomalies = append(host.Anomalies, anomaly)
					}
				}
			}
		}
	}
}

// -- helpers (can move elsewhere) --

func mergeAnomalySlices(a, b []model.Anomaly) []model.Anomaly {
	m := make(map[string]bool)
	for _, v := range a {
		key := v.Description + ":" + v.Severity
		m[key] = true
	}
	for _, v := range b {
		key := v.Description + ":" + v.Severity
		if !m[key] {
			a = append(a, v)
			m[key] = true
		}
	}
	return a
}

func MergeRole(oldRole, newRole string) string {
	prio := map[string]int{"": 0, "client": 1, "server": 2, "switch": 3, "network_device": 4, "router": 5}
	if prio[newRole] > prio[oldRole] {
		return newRole
	}
	return oldRole
}

func containsAnomaly(slice []model.Anomaly, item model.Anomaly) bool {
	for _, a := range slice {
		// Compare by type and severity for typed anomalies
		if a.Type != "" && item.Type != "" {
			if a.Type == item.Type && a.Severity == item.Severity {
				return true
			}
		} else {
			// Fallback for legacy description-based anomalies
			if a.Description == item.Description && a.Severity == item.Severity {
				return true
			}
		}
	}
	return false
}

// containsVLANInfo checks if info contains VLAN information
// now managed via the dedicated VLANs field
func containsVLANInfo(info string) bool {
	return strings.Contains(info, "VLANID:")
}

// ComputeActiveSubnets analyses hosts to detect active subnets
func ComputeActiveSubnets(hosts []*model.Host) []model.Subnet {
	subnetMap := make(map[string]model.Subnet)

	for _, host := range hosts {
		// Derive /24 and /16 for each IPv4
		if host.IP != nil && host.IP.To4() != nil {
			ipv4 := host.IP.To4()

			// /24 subnet
			subnet24 := fmt.Sprintf("%s/24", ipv4.Mask(net.CIDRMask(24, 32)).String())
			if _, exists := subnetMap[subnet24+"-ARP"]; !exists {
				subnetMap[subnet24+"-ARP"] = model.Subnet{
					CIDR:   subnet24,
					Source: "ARP",
					Hosts:  []string{},
				}
			}
			// Add the IP to the hosts list
			subnet := subnetMap[subnet24+"-ARP"]
			if !utils.ContainsString(subnet.Hosts, host.IP.String()) {
				subnet.Hosts = append(subnet.Hosts, host.IP.String())
				subnetMap[subnet24+"-ARP"] = subnet
			}

			// /16 subnet
			subnet16 := fmt.Sprintf("%s/16", ipv4.Mask(net.CIDRMask(16, 32)).String())
			if _, exists := subnetMap[subnet16+"-ARP"]; !exists {
				subnetMap[subnet16+"-ARP"] = model.Subnet{
					CIDR:   subnet16,
					Source: "ARP",
					Hosts:  []string{},
				}
			}
			// Add the IP to the hosts list
			subnet = subnetMap[subnet16+"-ARP"]
			if !utils.ContainsString(subnet.Hosts, host.IP.String()) {
				subnet.Hosts = append(subnet.Hosts, host.IP.String())
				subnetMap[subnet16+"-ARP"] = subnet
			}
		}

		// Analyse protocols to extract management addresses
		for _, protocol := range host.Protocols {
			switch protocol {
			case "DHCP":
				// Extract Router and DNS from DHCP info
				if host.Info != "" {
					extractDHCPSubnets(host.Info, subnetMap)
				}
			case "CDP":
				// Extract Management Address from CDP info
				if host.Info != "" {
					extractCDPSubnets(host.Info, subnetMap)
				}
			case "LLDP":
				// Extract Management Address from LLDP info
				if host.Info != "" {
					extractLLDPSubnets(host.Info, subnetMap)
				}
			case "VLAN":
				// Extract VLAN ID from VLAN info
				if host.Info != "" {
					extractVLANSubnets(host.Info, subnetMap)
				}
			}
		}
	}

	// Convert the map to a slice
	subnets := make([]model.Subnet, 0, len(subnetMap))
	for _, subnet := range subnetMap {
		subnets = append(subnets, subnet)
	}

	return subnets
}

// extractDHCPSubnets extracts subnets from DHCP information
func extractDHCPSubnets(info string, subnetMap map[string]model.Subnet) {
	parts := strings.Split(info, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "Router:") {
			ipStr := strings.TrimPrefix(part, "Router:")
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				addSubnetsForIP(ip, "DHCP", subnetMap)
			}
		} else if strings.HasPrefix(part, "DNS:") {
			ipStr := strings.TrimPrefix(part, "DNS:")
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				addSubnetsForIP(ip, "DHCP", subnetMap)
			}
		}
	}
}

// extractCDPSubnets extracts subnets from CDP information
func extractCDPSubnets(info string, subnetMap map[string]model.Subnet) {
	parts := strings.Split(info, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "MgmtIP:") {
			ipStr := strings.TrimPrefix(part, "MgmtIP:")
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				addSubnetsForIP(ip, "CDP", subnetMap)
			}
		}
	}
}

// extractLLDPSubnets extracts subnets from LLDP information
func extractLLDPSubnets(info string, subnetMap map[string]model.Subnet) {
	parts := strings.Split(info, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "MgmtIP:") {
			ipStr := strings.TrimPrefix(part, "MgmtIP:")
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				addSubnetsForIP(ip, "LLDP", subnetMap)
			}
		}
	}
}

// extractVLANSubnets extracts VLANs from VLAN information
func extractVLANSubnets(info string, subnetMap map[string]model.Subnet) {
	parts := strings.Split(info, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "VLANID:") {
			vlanID := strings.TrimPrefix(part, "VLANID:")
			key := "VLAN-" + vlanID + "-VLAN"
			if _, exists := subnetMap[key]; !exists {
				subnetMap[key] = model.Subnet{
					CIDR:   "VLAN-" + vlanID,
					Source: "VLAN",
					Hosts:  []string{},
				}
			}
		}
	}
}

// addSubnetsForIP adds /24 and /16 subnets for a given IP
func addSubnetsForIP(ip net.IP, source string, subnetMap map[string]model.Subnet) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return
	}

	// /24 subnet
	subnet24 := fmt.Sprintf("%s/24", ipv4.Mask(net.CIDRMask(24, 32)).String())
	key24 := subnet24 + "-" + source
	if _, exists := subnetMap[key24]; !exists {
		subnetMap[key24] = model.Subnet{
			CIDR:   subnet24,
			Source: source,
			Hosts:  []string{},
		}
	}

	// /16 subnet
	subnet16 := fmt.Sprintf("%s/16", ipv4.Mask(net.CIDRMask(16, 32)).String())
	key16 := subnet16 + "-" + source
	if _, exists := subnetMap[key16]; !exists {
		subnetMap[key16] = model.Subnet{
			CIDR:   subnet16,
			Source: source,
			Hosts:  []string{},
		}
	}
}

// mergeHostInfo merges host information strings without overwriting existing services
func mergeHostInfo(existing, new string) string {
	if existing == "" {
		return new
	}
	if new == "" {
		return existing
	}

	// Parse existing info into parts
	existingParts := utils.ParseInfoParts(existing)
	newParts := utils.ParseInfoParts(new)

	// Merge parts, avoiding duplicates
	mergedParts := make(map[string]string)

	// Add existing parts
	for key, value := range existingParts {
		mergedParts[key] = value
	}

	// Add new parts, but don't overwrite existing ones for certain keys
	for key, value := range newParts {
		if key == "hostname" {
			// Keep existing hostname, don't overwrite
			if _, exists := mergedParts[key]; !exists {
				mergedParts[key] = value
			}
		} else if key == "service" {
			// For services, we need to append multiple services
			if existingService, exists := mergedParts[key]; exists {
				// Check if this service is already listed
				if !strings.Contains(existingService, value) {
					mergedParts[key] = existingService + "," + value
				}
			} else {
				mergedParts[key] = value
			}
		} else {
			// For other keys, don't overwrite existing values
			if _, exists := mergedParts[key]; !exists {
				mergedParts[key] = value
			}
		}
	}

	// Rebuild info string
	var parts []string
	for key, value := range mergedParts {
		parts = append(parts, key+"="+value)
	}

	return strings.Join(parts, "; ")
}

// calculateOnlyARP determines if a host only has the ARP protocol.
// Rule: onlyArp = (len(protocols) == 1 && protocols[0] == "ARP")
func calculateOnlyARP(protocols []string) bool {
	return len(protocols) == 1 && protocols[0] == "ARP"
}

// GetAllSubnets returns all detected subnets (stub for compatibility)
func (a *Aggregator) GetAllSubnets() []*model.Subnet {
	// Simplified aggregator no longer tracks subnets
	return []*model.Subnet{}
}

// mergeGatewayRedundancy appends gateway redundancy info, deduplicating by protocol+groupID.
func mergeGatewayRedundancy(host *model.Host, gr *model.GatewayRedundancyInfo) {
	// Find existing entry for this protocol
	for i, existing := range host.GatewayRedundancy {
		if existing.Protocol == gr.Protocol {
			// Merge groups, deduplicate by GroupID
			for _, newGroup := range gr.Groups {
				found := false
				for j, existingGroup := range existing.Groups {
					if existingGroup.GroupID == newGroup.GroupID {
						// Update with latest data
						host.GatewayRedundancy[i].Groups[j] = newGroup
						found = true
						break
					}
				}
				if !found {
					host.GatewayRedundancy[i].Groups = append(host.GatewayRedundancy[i].Groups, newGroup)
				}
			}
			return
		}
	}
	// No existing entry for this protocol — append
	host.GatewayRedundancy = append(host.GatewayRedundancy, *gr)
}
