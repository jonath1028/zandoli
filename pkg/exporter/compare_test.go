// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestHosts returns a rich set of test hosts covering various field combinations.
func buildTestHosts() []*model.Host {
	now := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	later := now.Add(5 * time.Minute)

	return []*model.Host{
		{
			IP:             net.IPv4(192, 168, 1, 1),
			IPv6Primary:    net.ParseIP("fe80::1"),
			MAC:            net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
			MACStr:         "aa:bb:cc:dd:ee:01",
			Vendor:         "Cisco",
			Hostname:       "router1",
			Role:           "server",
			RoleConfidence: 95,
			Category:       "network",
			OSGuess:        "IOS",
			OSScore:        80,
			TTL:            255,
			TTLAvg:         255,
			Source:         "passive",
			Info:           "gateway",
			PacketCount:    100,
			Protocols:      []string{"ARP", "DHCP", "CDP"},
			Services:       model.ServicesInfo{TCP: []int{22, 80}, UDP: []int{53}},
			L2Signals:      model.L2SignalsInfo{CDP: true, VLANs: []int{1, 10}},
			Anomalies:      []model.Anomaly{{Description: "arp_storm", Severity: "high"}},
			CDP:            &model.CDPInfo{DeviceID: "router1.local"},
			LLDP:           &model.LLDPInfo{SysName: "router1-lldp"},
			FirstSeen:      now,
			LastSeen:       later,
		},
		{
			IP:        net.IPv4(192, 168, 1, 50),
			MAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
			MACStr:    "aa:bb:cc:dd:ee:02",
			Vendor:    "Apple",
			Role:      "client",
			TTLAvg:    64,
			Source:    "passive",
			Protocols: []string{"ARP", "mDNS"},
			FirstSeen: now,
			LastSeen:  later,
		},
		{
			// L2-only host (no IP, only MAC)
			MAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03},
			MACStr:    "aa:bb:cc:dd:ee:03",
			Vendor:    "HP",
			L2Signals: model.L2SignalsInfo{STP: true, LLDP: true},
			Protocols: []string{"STP", "LLDP"},
			Source:    "passive",
			FirstSeen: now,
			LastSeen:  later,
		},
	}
}

func TestCSVJSON_HostCountMatch(t *testing.T) {
	t.Parallel()

	hosts := buildTestHosts()
	log := newTestLogger(t)

	csvPath := tempFile(t, "compare_*.csv")
	jsonPath := tempFile(t, "compare_*.json")

	// Export both formats
	require.NoError(t, ExportCSV(hosts, csvPath, log))
	require.NoError(t, ExportAll(hosts, jsonPath, log))

	// Parse CSV
	csvHosts := parseCSVHosts(t, csvPath)

	// Parse JSON
	jsonHosts := parseJSONHosts(t, jsonPath)

	// Host count must match
	assert.Equal(t, len(jsonHosts), len(csvHosts),
		"JSON host count (%d) must equal CSV host count (%d)", len(jsonHosts), len(csvHosts))
}

func TestCSVJSON_FieldsMatch(t *testing.T) {
	t.Parallel()

	hosts := buildTestHosts()
	log := newTestLogger(t)

	csvPath := tempFile(t, "compare_*.csv")
	jsonPath := tempFile(t, "compare_*.json")

	require.NoError(t, ExportCSV(hosts, csvPath, log))
	require.NoError(t, ExportAll(hosts, jsonPath, log))

	csvRows := parseCSVHostsIndexed(t, csvPath)
	jsonHosts := parseJSONHosts(t, jsonPath)

	// For each JSON host, find the matching CSV row by MAC and verify fields
	for _, jh := range jsonHosts {
		mac := jsonStr(jh, "macStr")
		if mac == "" {
			continue
		}

		csvRow, ok := csvRows[mac]
		if !ok {
			t.Errorf("JSON host with MAC %s not found in CSV", mac)
			continue
		}

		// IP
		if ip := jsonStr(jh, "ip"); ip != "" {
			assert.Equal(t, ip, csvRow["IP"], "IP mismatch for MAC %s", mac)
		}

		// Vendor
		if vendor := jsonStr(jh, "vendor"); vendor != "" {
			assert.Equal(t, vendor, csvRow["Vendor"], "Vendor mismatch for MAC %s", mac)
		}

		// Hostname
		if hostname := jsonStr(jh, "hostname"); hostname != "" {
			assert.Equal(t, hostname, csvRow["Hostname"], "Hostname mismatch for MAC %s", mac)
		}

		// Role
		if role := jsonStr(jh, "role"); role != "" {
			assert.Equal(t, role, csvRow["Role"], "Role mismatch for MAC %s", mac)
		}

		// Source
		if source := jsonStr(jh, "source"); source != "" {
			assert.Equal(t, source, csvRow["Source"], "Source mismatch for MAC %s", mac)
		}

		// OS
		if osGuess := jsonStr(jh, "osGuess"); osGuess != "" {
			assert.Equal(t, osGuess, csvRow["OS"], "OS mismatch for MAC %s", mac)
		}

		// Category
		if cat := jsonStr(jh, "category"); cat != "" {
			assert.Equal(t, cat, csvRow["Category"], "Category mismatch for MAC %s", mac)
		}

		// Info
		if info := jsonStr(jh, "info"); info != "" {
			assert.Equal(t, info, csvRow["Info"], "Info mismatch for MAC %s", mac)
		}

		// CDP DeviceID
		if cdp, ok := jh["cdp"].(map[string]interface{}); ok {
			if devID, ok := cdp["device_id"].(string); ok && devID != "" {
				assert.Equal(t, devID, csvRow["CDP_DeviceID"], "CDP_DeviceID mismatch for MAC %s", mac)
			}
		}

		// LLDP SysName
		if lldp, ok := jh["lldp"].(map[string]interface{}); ok {
			if sysName, ok := lldp["sys_name"].(string); ok && sysName != "" {
				assert.Equal(t, sysName, csvRow["LLDP_SysName"], "LLDP_SysName mismatch for MAC %s", mac)
			}
		}
	}
}

// --- helpers ---

func newTestLogger(t *testing.T) *logger.Logger {
	t.Helper()
	dummyCfg := &config.Config{}
	log, err := logger.New("error", dummyCfg)
	require.NoError(t, err)
	return log
}

func tempFile(t *testing.T, pattern string) string {
	t.Helper()
	f, err := os.CreateTemp("", pattern)
	require.NoError(t, err)
	path := f.Name()
	f.Close()
	os.Remove(path)
	t.Cleanup(func() { os.Remove(path) })
	return path
}

func parseCSVHosts(t *testing.T, path string) []map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.Comma = ';'
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.True(t, len(records) >= 1, "CSV must have at least a header row")

	headers := records[0]
	var rows []map[string]string
	for _, rec := range records[1:] {
		row := make(map[string]string, len(headers))
		for i, h := range headers {
			row[h] = rec[i]
		}
		rows = append(rows, row)
	}
	return rows
}

func parseCSVHostsIndexed(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	rows := parseCSVHosts(t, path)
	indexed := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		indexed[row["MAC"]] = row
	}
	return indexed
}

func parseJSONHosts(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var export struct {
		Hosts []map[string]interface{} `json:"hosts"`
	}
	require.NoError(t, json.Unmarshal(data, &export))
	return export.Hosts
}

func jsonStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
