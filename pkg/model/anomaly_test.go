// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"testing"
)

func TestAnomalyKeyGeneration(t *testing.T) {
	// Test IP duplicate v4 key generation
	key1 := GenerateIPDuplicateV4Key("192.168.1.1", 10)
	expected1 := "ip:192.168.1.1/vlan:10"
	if key1 != expected1 {
		t.Errorf("Expected %s, got %s", expected1, key1)
	}

	key2 := GenerateIPDuplicateV4Key("192.168.1.1", 0)
	expected2 := "ip:192.168.1.1/vlan:null"
	if key2 != expected2 {
		t.Errorf("Expected %s, got %s", expected2, key2)
	}

	// Test MAC multiple IP key generation
	key3 := GenerateMACMultipleIPKey("aa:bb:cc:dd:ee:ff", 20)
	expected3 := "mac:aa:bb:cc:dd:ee:ff/vlan:20"
	if key3 != expected3 {
		t.Errorf("Expected %s, got %s", expected3, key3)
	}

	key4 := GenerateMACMultipleIPKey("aa:bb:cc:dd:ee:ff", 0)
	expected4 := "mac:aa:bb:cc:dd:ee:ff/vlan:null"
	if key4 != expected4 {
		t.Errorf("Expected %s, got %s", expected4, key4)
	}

	// Test flip suspect key generation
	key5 := GenerateFlipSuspectKey("192.168.1.1", "aa:bb:cc:dd:ee:ff", "DHCP")
	expected5 := "ip:192.168.1.1/mac:aa:bb:cc:dd:ee:ff/proto:DHCP"
	if key5 != expected5 {
		t.Errorf("Expected %s, got %s", expected5, key5)
	}

	// Test duplicate hostname key generation
	key6 := GenerateDuplicateHostnameKey("server1")
	expected6 := "hostname:server1"
	if key6 != expected6 {
		t.Errorf("Expected %s, got %s", expected6, key6)
	}

	// Test scope generation
	scope1 := GenerateAnomalyScope(10)
	expectedScope1 := "vlan:10"
	if scope1 != expectedScope1 {
		t.Errorf("Expected %s, got %s", expectedScope1, scope1)
	}

	scope2 := GenerateAnomalyScope(0)
	expectedScope2 := "global"
	if scope2 != expectedScope2 {
		t.Errorf("Expected %s, got %s", expectedScope2, scope2)
	}
}

func TestAnomalyDeduplicator(t *testing.T) {
	dedup := NewAnomalyDeduplicator()

	// Test adding anomalies
	anomaly1 := NewIPDuplicateV4Anomaly("192.168.1.1", 10, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})
	anomaly2 := NewMACMultipleIPAnomalyWithKey("aa:bb:cc:dd:ee:ff", 10, []string{"192.168.1.1", "192.168.1.2"}, nil)
	anomaly3 := NewFlipSuspectAnomaly("192.168.1.1", "aa:bb:cc:dd:ee:ff", "DHCP", 10, "flip_blocked_priority_too_low")
	anomaly4 := NewDuplicateHostnameAnomaly("server1", []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})

	// Add anomalies
	dedup.AddAnomaly(anomaly1)
	dedup.AddAnomaly(anomaly2)
	dedup.AddAnomaly(anomaly3)
	dedup.AddAnomaly(anomaly4)

	// Test count
	if dedup.Count() != 4 {
		t.Errorf("Expected 4 anomalies, got %d", dedup.Count())
	}

	// Test getting anomalies
	anomalies := dedup.GetAnomalies()
	if len(anomalies) != 4 {
		t.Errorf("Expected 4 anomalies, got %d", len(anomalies))
	}

	// Test deduplication - add same anomaly again
	dedup.AddAnomaly(anomaly1)
	if dedup.Count() != 4 {
		t.Errorf("Expected 4 anomalies after duplicate, got %d", dedup.Count())
	}

	// Test getting anomaly by key
	key := anomaly1.Key
	retrieved := dedup.GetAnomalyByKey(key)
	if retrieved == nil {
		t.Errorf("Expected to find anomaly with key %s", key)
	}
	if retrieved.Key != key {
		t.Errorf("Expected key %s, got %s", key, retrieved.Key)
	}

	// Test has anomaly
	if !dedup.HasAnomaly(key) {
		t.Errorf("Expected to have anomaly with key %s", key)
	}

	// Test removing anomaly
	dedup.RemoveAnomaly(key)
	if dedup.Count() != 3 {
		t.Errorf("Expected 3 anomalies after removal, got %d", dedup.Count())
	}

	// Test clear
	dedup.Clear()
	if dedup.Count() != 0 {
		t.Errorf("Expected 0 anomalies after clear, got %d", dedup.Count())
	}
}

func TestAnomalyCreation(t *testing.T) {
	// Test IP duplicate v4 anomaly
	anomaly1 := NewIPDuplicateV4Anomaly("192.168.1.1", 10, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})

	if anomaly1.Type != "ip_duplicate_v4" {
		t.Errorf("Expected type ip_duplicate_v4, got %s", anomaly1.Type)
	}
	if anomaly1.Severity != "medium" {
		t.Errorf("Expected severity medium, got %s", anomaly1.Severity)
	}
	if anomaly1.Key != "ip:192.168.1.1/vlan:10" {
		t.Errorf("Expected key ip:192.168.1.1/vlan:10, got %s", anomaly1.Key)
	}
	if anomaly1.Scope != "vlan:10" {
		t.Errorf("Expected scope vlan:10, got %s", anomaly1.Scope)
	}

	// Test MAC multiple IP anomaly
	anomaly2 := NewMACMultipleIPAnomalyWithKey("aa:bb:cc:dd:ee:ff", 0, []string{"192.168.1.1", "192.168.1.2"}, nil)

	if anomaly2.Type != "mac_multiple_ip" {
		t.Errorf("Expected type mac_multiple_ip, got %s", anomaly2.Type)
	}
	if anomaly2.Severity != "medium" {
		t.Errorf("Expected severity medium, got %s", anomaly2.Severity)
	}
	if anomaly2.Key != "mac:aa:bb:cc:dd:ee:ff/vlan:null" {
		t.Errorf("Expected key mac:aa:bb:cc:dd:ee:ff/vlan:null, got %s", anomaly2.Key)
	}
	if anomaly2.Scope != "global" {
		t.Errorf("Expected scope global, got %s", anomaly2.Scope)
	}

	// Test flip suspect anomaly
	anomaly3 := NewFlipSuspectAnomaly("192.168.1.1", "aa:bb:cc:dd:ee:ff", "DHCP", 10, "flip_blocked_priority_too_low")

	if anomaly3.Type != "flip_suspect" {
		t.Errorf("Expected type flip_suspect, got %s", anomaly3.Type)
	}
	if anomaly3.Severity != "medium" {
		t.Errorf("Expected severity medium, got %s", anomaly3.Severity)
	}
	if anomaly3.Key != "ip:192.168.1.1/mac:aa:bb:cc:dd:ee:ff/proto:DHCP" {
		t.Errorf("Expected key ip:192.168.1.1/mac:aa:bb:cc:dd:ee:ff/proto:DHCP, got %s", anomaly3.Key)
	}
	if anomaly3.Scope != "vlan:10" {
		t.Errorf("Expected scope vlan:10, got %s", anomaly3.Scope)
	}

	// Test duplicate hostname anomaly
	anomaly4 := NewDuplicateHostnameAnomaly("server1", []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})

	if anomaly4.Type != "duplicate_hostname" {
		t.Errorf("Expected type duplicate_hostname, got %s", anomaly4.Type)
	}
	if anomaly4.Severity != "low" {
		t.Errorf("Expected severity low, got %s", anomaly4.Severity)
	}
	if anomaly4.Key != "hostname:server1" {
		t.Errorf("Expected key hostname:server1, got %s", anomaly4.Key)
	}
	if anomaly4.Scope != "global" {
		t.Errorf("Expected scope global, got %s", anomaly4.Scope)
	}
}
