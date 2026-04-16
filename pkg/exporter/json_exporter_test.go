// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTempPath() string {
	f, err := ioutil.TempFile("", "hosts_*.json")
	if err != nil {
		panic(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	return path
}

func TestExportAll_CreatesValidJSON(t *testing.T) {
	path := createTempPath()

	hosts := []*model.Host{
		{
			IP:        net.IPv4(192, 168, 1, 1),
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			MACStr:    "00:11:22:33:44:55",
			Role:      "server",
			Protocols: []string{"dhcp"},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	dummyCfg := &config.Config{}
	log, err := logger.New("debug", dummyCfg)

	err = ExportAll(hosts, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.True(t, len(content) > 0)

	var out Export
	require.NoError(t, json.Unmarshal(content, &out))
	require.Equal(t, "1", out.Version)
	require.Equal(t, 1, out.Count)
	require.Len(t, out.Hosts, 1)
	assert.Equal(t, "server", out.Hosts[0]["role"])
	assert.Contains(t, out.Hosts[0]["protocols"], "dhcp")

	os.Remove(path)
}

func TestExportAll_HandlesEmptyList(t *testing.T) {
	path := createTempPath()

	dummyCfg := &config.Config{}
	log, err := logger.New("info", dummyCfg)

	err = ExportAll([]*model.Host{}, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)

	var out Export
	require.NoError(t, json.Unmarshal(content, &out))
	require.Equal(t, "1", out.Version)
	require.Equal(t, 0, out.Count)
	require.Len(t, out.Hosts, 0)

	os.Remove(path)
}

func TestExportAll_IncludesL2HostsWithoutIP(t *testing.T) {
	path := createTempPath()

	// Créer des hôtes L2 sans IP
	hosts := []*model.Host{
		{
			IP:        nil, // Pas d'IP
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			MACStr:    "00:11:22:33:44:55",
			Role:      "switch",
			Protocols: []string{"CDP"},
			Info:      "DeviceID:Switch1",
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        nil, // Pas d'IP
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			MACStr:    "00:11:22:33:44:66",
			Role:      "router",
			Protocols: []string{"LLDP"},
			Info:      "DeviceID:Router1",
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        net.IPv4(192, 168, 1, 100), // Hôte avec IP
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77},
			MACStr:    "00:11:22:33:44:77",
			Role:      "client",
			Protocols: []string{"DHCP"},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	dummyCfg := &config.Config{}
	log, err := logger.New("debug", dummyCfg)

	err = ExportAll(hosts, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.True(t, len(content) > 0)

	var out Export
	require.NoError(t, json.Unmarshal(content, &out))
	require.Equal(t, "1", out.Version)
	require.Equal(t, 3, out.Count)
	require.Len(t, out.Hosts, 3)

	// Vérifier que les hôtes L2 sont présents
	macStrings := make(map[string]bool)
	for _, host := range out.Hosts {
		if macStr, ok := host["macStr"].(string); ok {
			macStrings[macStr] = true
		}
	}

	assert.True(t, macStrings["00:11:22:33:44:55"], "L2 host with CDP should be exported")
	assert.True(t, macStrings["00:11:22:33:44:66"], "L2 host with LLDP should be exported")
	assert.True(t, macStrings["00:11:22:33:44:77"], "Host with IP should be exported")

	// Vérifier que les protocoles L2 sont présents
	for _, host := range out.Hosts {
		if protocols, ok := host["protocols"].([]interface{}); ok {
			protocolStrs := make([]string, len(protocols))
			for i, p := range protocols {
				protocolStrs[i] = p.(string)
			}

			if macStr, ok := host["macStr"].(string); ok {
				switch macStr {
				case "00:11:22:33:44:55":
					assert.Contains(t, protocolStrs, "CDP")
				case "00:11:22:33:44:66":
					assert.Contains(t, protocolStrs, "LLDP")
				case "00:11:22:33:44:77":
					assert.Contains(t, protocolStrs, "DHCP")
				}
			}
		}
	}

	os.Remove(path)
}

func TestExportAll_IncludesOSInformation(t *testing.T) {
	path := createTempPath()

	hosts := []*model.Host{
		{
			IP:        net.IPv4(192, 168, 1, 1),
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			MACStr:    "00:11:22:33:44:55",
			Role:      "server",
			Protocols: []string{"dhcp"},
			OSGuess:   "Linux",
			OSScore:   85,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			IP:        net.IPv4(192, 168, 1, 2),
			MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			MACStr:    "00:11:22:33:44:66",
			Role:      "client",
			Protocols: []string{"dhcp"},
			// OSGuess et OSScore vides - ne doivent pas apparaître dans le JSON
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	dummyCfg := &config.Config{}
	log, err := logger.New("debug", dummyCfg)

	err = ExportAll(hosts, path, log)
	assert.NoError(t, err)

	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.True(t, len(content) > 0)

	var out Export
	require.NoError(t, json.Unmarshal(content, &out))
	require.Equal(t, "1", out.Version)
	require.Equal(t, 2, out.Count)
	require.Len(t, out.Hosts, 2)

	// Vérifier le premier host avec informations OS
	host1 := out.Hosts[0]
	assert.Equal(t, "Linux", host1["osGuess"])
	assert.Equal(t, float64(85), host1["osScore"]) // JSON unmarshal les nombres en float64

	// Vérifier le deuxième host sans informations OS
	host2 := out.Hosts[1]
	_, hasOSGuess := host2["osGuess"]
	_, hasOSScore := host2["osScore"]
	assert.False(t, hasOSGuess, "osGuess should not be present when empty")
	assert.False(t, hasOSScore, "osScore should not be present when empty")

	os.Remove(path)
}
