// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import "fmt"

// AnomalyType represents the type of anomaly as a string constant
type AnomalyType string

const (
	AnomArpStorm              AnomalyType = "ARP storm detected"
	AnomMultiIP               AnomalyType = "Multiple IPs per MAC detected"
	AnomAbnormalTTL           AnomalyType = "Abnormal TTL values detected"
	AnomBroadcastDestinations AnomalyType = "Multiple broadcast destinations detected"
	AnomMultipleDHCPServers   AnomalyType = "Multiple DHCP servers detected"
	AnomSuspiciousTTL         AnomalyType = "Suspicious TTL values detected"
	AnomUnusualPorts          AnomalyType = "Unusual port combinations detected"
	AnomMACAnomalies          AnomalyType = "MAC address anomalies detected"
)

// Anomaly represents a detected network anomaly with severity level
type Anomaly struct {
	Type        string                 `json:"type"`        // Type of anomaly: "ip_duplicate_v4", "mac_multiple_ip", "flip_suspect", "duplicate_hostname"
	Severity    string                 `json:"severity"`    // Severity level: "low", "medium", "high"
	Key         string                 `json:"key"`         // Unique deduplication key
	Parameters  map[string]interface{} `json:"parameters"`  // Type-specific parameters
	Scope       string                 `json:"scope"`       // Scope: "global" or "vlan:<id>"
	Description string                 `json:"description"` // Human-readable description (for backward compatibility)
}

// NewAnomaly creates a new typed anomaly with parameters
func NewAnomaly(anomalyType, severity, description string, parameters map[string]interface{}) Anomaly {
	return Anomaly{
		Type:        anomalyType,
		Severity:    severity,
		Description: description,
		Parameters:  parameters,
		Key:         "",
		Scope:       "global",
	}
}

// NewAnomalyWithKey creates a new typed anomaly with key and scope
func NewAnomalyWithKey(anomalyType, severity, key, scope, description string, parameters map[string]interface{}) Anomaly {
	return Anomaly{
		Type:        anomalyType,
		Severity:    severity,
		Key:         key,
		Scope:       scope,
		Description: description,
		Parameters:  parameters,
	}
}

// NewARPStormAnomaly creates an ARP storm anomaly with PPS and duration parameters
func NewARPStormAnomaly(pps int, durationSeconds int) Anomaly {
	return NewAnomaly("arp_storm", "high", "ARP storm detected",
		map[string]interface{}{"pps": pps, "duration_s": durationSeconds})
}

// NewMACMultipleIPAnomaly creates a MAC multiple IP anomaly with IP list
func NewMACMultipleIPAnomaly(ips []string) Anomaly {
	return NewAnomaly("mac_multiple_ip", "medium", "MAC multiple IP",
		map[string]interface{}{"ips": ips})
}

// --- Key generators (package-level, stateless) ---

// GenerateIPDuplicateV4Key generates key for ip_duplicate_v4: "ip:<ip>/vlan:<vlanID|null>"
func GenerateIPDuplicateV4Key(ip string, vlanID int) string {
	if vlanID > 0 {
		return fmt.Sprintf("ip:%s/vlan:%d", ip, vlanID)
	}
	return fmt.Sprintf("ip:%s/vlan:null", ip)
}

// GenerateMACMultipleIPKey generates key for mac_multiple_ip: "mac:<mac>/vlan:<vlanID|null>"
func GenerateMACMultipleIPKey(mac string, vlanID int) string {
	if vlanID > 0 {
		return fmt.Sprintf("mac:%s/vlan:%d", mac, vlanID)
	}
	return fmt.Sprintf("mac:%s/vlan:null", mac)
}

// GenerateFlipSuspectKey generates key for flip_suspect: "ip:<ip>/mac:<mac>/proto:<p>"
func GenerateFlipSuspectKey(ip, mac, protocol string) string {
	return fmt.Sprintf("ip:%s/mac:%s/proto:%s", ip, mac, protocol)
}

// GenerateDuplicateHostnameKey generates key for duplicate_hostname: "hostname:<name>"
func GenerateDuplicateHostnameKey(hostname string) string {
	return fmt.Sprintf("hostname:%s", hostname)
}

// GenerateAnomalyScope generates scope string: "global" or "vlan:<id>"
func GenerateAnomalyScope(vlanID int) string {
	if vlanID > 0 {
		return fmt.Sprintf("vlan:%d", vlanID)
	}
	return "global"
}

// --- Anomaly constructors with key/scope ---

// NewIPDuplicateV4Anomaly creates an IP duplicate IPv4 anomaly with proper key and scope
func NewIPDuplicateV4Anomaly(ip string, vlanID int, macs []string) Anomaly {
	key := GenerateIPDuplicateV4Key(ip, vlanID)
	scope := GenerateAnomalyScope(vlanID)
	return NewAnomalyWithKey("ip_duplicate_v4", "medium", key, scope, "IPv4 duplicate detected",
		map[string]interface{}{"ip": ip, "vlan": vlanID, "macs": macs, "count": len(macs)})
}

// NewMACMultipleIPAnomalyWithKey creates a MAC multiple IP anomaly with proper key and scope
func NewMACMultipleIPAnomalyWithKey(mac string, vlanID int, ips []string, ipDetails []map[string]interface{}) Anomaly {
	key := GenerateMACMultipleIPKey(mac, vlanID)
	scope := GenerateAnomalyScope(vlanID)
	return NewAnomalyWithKey("mac_multiple_ip", "medium", key, scope, "MAC multiple IP detected",
		map[string]interface{}{"ips": ips, "ip_details": ipDetails, "total_count": len(ips)})
}

// NewFlipSuspectAnomaly creates a flip suspect anomaly with proper key and scope
func NewFlipSuspectAnomaly(ip, mac, protocol string, vlanID int, reason string) Anomaly {
	key := GenerateFlipSuspectKey(ip, mac, protocol)
	scope := GenerateAnomalyScope(vlanID)
	return NewAnomalyWithKey("flip_suspect", "medium", key, scope, "IP↔MAC flip attempt blocked by priority",
		map[string]interface{}{"ip": ip, "mac": mac, "vlan": vlanID, "protocol": protocol, "reason": reason})
}

// NewDuplicateHostnameAnomaly creates a duplicate hostname anomaly with proper key and scope
func NewDuplicateHostnameAnomaly(hostname string, macs []string) Anomaly {
	key := GenerateDuplicateHostnameKey(hostname)
	return NewAnomalyWithKey("duplicate_hostname", "low", key, "global",
		fmt.Sprintf("Duplicate hostname: %s", hostname),
		map[string]interface{}{"hostname": hostname, "macs": macs})
}

// --- Anomaly deduplicator ---

// AnomalyDeduplicator manages server-side deduplication of anomalies by key
type AnomalyDeduplicator struct {
	anomalies map[string]Anomaly
}

// NewAnomalyDeduplicator creates a new anomaly deduplicator
func NewAnomalyDeduplicator() *AnomalyDeduplicator {
	return &AnomalyDeduplicator{anomalies: make(map[string]Anomaly)}
}

// AddAnomaly adds an anomaly, replacing any existing one with the same key
func (d *AnomalyDeduplicator) AddAnomaly(anomaly Anomaly) {
	if anomaly.Key != "" {
		d.anomalies[anomaly.Key] = anomaly
	}
}

// GetAnomalies returns all unique anomalies
func (d *AnomalyDeduplicator) GetAnomalies() []Anomaly {
	anomalies := make([]Anomaly, 0, len(d.anomalies))
	for _, anomaly := range d.anomalies {
		anomalies = append(anomalies, anomaly)
	}
	return anomalies
}

// GetAnomalyByKey returns an anomaly by its key, or nil if not found
func (d *AnomalyDeduplicator) GetAnomalyByKey(key string) *Anomaly {
	if anomaly, exists := d.anomalies[key]; exists {
		return &anomaly
	}
	return nil
}

// HasAnomaly checks if an anomaly with the given key exists
func (d *AnomalyDeduplicator) HasAnomaly(key string) bool {
	_, exists := d.anomalies[key]
	return exists
}

// RemoveAnomaly removes an anomaly by its key
func (d *AnomalyDeduplicator) RemoveAnomaly(key string) {
	delete(d.anomalies, key)
}

// Clear removes all anomalies
func (d *AnomalyDeduplicator) Clear() {
	d.anomalies = make(map[string]Anomaly)
}

// Count returns the number of unique anomalies
func (d *AnomalyDeduplicator) Count() int {
	return len(d.anomalies)
}
