// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/csv"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

func createTempCSVPath() string {
	f, err := os.CreateTemp("", "hosts_*.csv")
	if err != nil {
		panic(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	return path
}

func TestExportCSV_IncludesAllColumns(t *testing.T) {
	path := createTempCSVPath()
	defer os.Remove(path)

	now := time.Now()
	hosts := []*model.Host{
		{
			IP:             net.IPv4(192, 168, 1, 1),
			MAC:            net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			MACStr:         "00:11:22:33:44:55",
			Vendor:         "TestVendor",
			Hostname:       "server1",
			Role:           "server",
			RoleConfidence: 90,
			Category:       "infrastructure",
			OSGuess:        "Linux",
			OSScore:        85,
			TTL:            64,
			TTLAvg:         64,
			Source:         "passive",
			Ports:          []int{80, 443},
			PacketCount:    42,
			Anomalies:      []model.Anomaly{{Description: "unusual_port", Severity: "low"}},
			Info:           "web server",
			FirstSeen:      now,
			LastSeen:       now,
			CDP:            &model.CDPInfo{DeviceID: "switch01"},
			LLDP:           &model.LLDPInfo{SysName: "core-sw"},
		},
		{
			IP:        net.IPv4(192, 168, 1, 2),
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			MACStr:    "00:11:22:33:44:66",
			Role:      "client",
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	dummyCfg := &config.Config{}
	log, err := logger.New("debug", dummyCfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	err = ExportCSV(hosts, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	reader.Comma = ';'
	records, err := reader.ReadAll()
	assert.NoError(t, err)
	assert.Equal(t, 3, len(records)) // header + 2 hosts

	// Verify all expected headers
	headers := records[0]
	expectedHeaders := []string{
		"MAC", "Vendor", "Hostname", "Role", "RoleConfidence", "Category",
		"IP", "IPv6", "VLANs", "L2Flags",
		"UDP_Services", "TCP_Services", "Protocols",
		"OS", "OSScore", "TTL", "TTLAvg",
		"Source", "FirstSeen", "LastSeen", "PacketCount",
		"Anomalies", "CDP_DeviceID", "LLDP_SysName", "Info",
	}
	assert.Equal(t, expectedHeaders, headers)

	// Build column index for readable assertions
	colIdx := make(map[string]int, len(headers))
	for i, h := range headers {
		colIdx[h] = i
	}

	// Host 1 — fully populated
	h1 := records[1]
	assert.Equal(t, "00:11:22:33:44:55", h1[colIdx["MAC"]])
	assert.Equal(t, "TestVendor", h1[colIdx["Vendor"]])
	assert.Equal(t, "server1", h1[colIdx["Hostname"]])
	assert.Equal(t, "server", h1[colIdx["Role"]])
	assert.Equal(t, "90", h1[colIdx["RoleConfidence"]])
	assert.Equal(t, "infrastructure", h1[colIdx["Category"]])
	assert.Equal(t, "192.168.1.1", h1[colIdx["IP"]])
	assert.Equal(t, "Linux", h1[colIdx["OS"]])
	assert.Equal(t, "85", h1[colIdx["OSScore"]])
	assert.Equal(t, "64", h1[colIdx["TTL"]])
	assert.Equal(t, "64", h1[colIdx["TTLAvg"]])
	assert.Equal(t, "passive", h1[colIdx["Source"]])
	assert.Equal(t, "42", h1[colIdx["PacketCount"]])
	assert.Equal(t, "1", h1[colIdx["Anomalies"]])
	assert.Equal(t, "switch01", h1[colIdx["CDP_DeviceID"]])
	assert.Equal(t, "core-sw", h1[colIdx["LLDP_SysName"]])
	assert.Equal(t, "web server", h1[colIdx["Info"]])

	// Host 2 — minimal, should have dashes for missing fields
	h2 := records[2]
	assert.Equal(t, "—", h2[colIdx["Vendor"]])
	assert.Equal(t, "—", h2[colIdx["Hostname"]])
	assert.Equal(t, "client", h2[colIdx["Role"]])
	assert.Equal(t, "—", h2[colIdx["RoleConfidence"]])
	assert.Equal(t, "—", h2[colIdx["Category"]])
	assert.Equal(t, "—", h2[colIdx["OS"]])
	assert.Equal(t, "—", h2[colIdx["OSScore"]])
	assert.Equal(t, "0", h2[colIdx["Anomalies"]])
	assert.Equal(t, "—", h2[colIdx["CDP_DeviceID"]])
	assert.Equal(t, "—", h2[colIdx["LLDP_SysName"]])
	assert.Equal(t, "—", h2[colIdx["Info"]])
}

func TestExportCSV_HandlesEmptyHosts(t *testing.T) {
	path := createTempCSVPath()
	defer os.Remove(path)

	dummyCfg := &config.Config{}
	log, err := logger.New("info", dummyCfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	err = ExportCSV([]*model.Host{}, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	reader.Comma = ';'
	records, err := reader.ReadAll()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(records), "Should only contain header row")

	assert.Contains(t, records[0], "OS", "CSV header should contain OS column")
	assert.Contains(t, records[0], "Hostname", "CSV header should contain Hostname column")
	assert.Contains(t, records[0], "CDP_DeviceID", "CSV header should contain CDP_DeviceID column")
}
