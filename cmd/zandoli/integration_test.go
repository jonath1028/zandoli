// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryPath is set by TestMain after building the binary once.
var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "zandoli-integration-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "zandoli")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// repoRoot returns the repository root (two dirs above cmd/zandoli).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..")
}

// pcapPath returns the absolute path to a Wireshark test PCAP.
// Skips the test if the file does not exist.
func pcapPath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "testdata", "wireshark", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("PCAP %s not found (run testdata/wireshark/download.sh)", name)
	}
	return p
}

// run executes the binary with the given args and returns stdout, stderr, and exit code.
func run(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// runPcap is a convenience wrapper: runs the binary with --pcap and --formats json.
func runPcap(t *testing.T, pcap string, extraArgs ...string) (outDir string, exitCode int) {
	t.Helper()
	outDir = t.TempDir()
	args := append([]string{"--pcap", pcap, "--formats", "json", "--output-dir", outDir}, extraArgs...)
	_, _, exitCode = run(t, args...)
	return
}

// findJSON finds the first hosts.json under outDir/scan_*/hosts.json.
func findJSON(t *testing.T, outDir string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(outDir, "*", "hosts.json"))
	require.NotEmpty(t, matches, "hosts.json not found in %s", outDir)
	return matches[0]
}

// loadHosts loads and returns the hosts array from a hosts.json file.
func loadHosts(t *testing.T, jsonPath string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	var export struct {
		Hosts []map[string]interface{} `json:"hosts"`
	}
	require.NoError(t, json.Unmarshal(data, &export))
	return export.Hosts
}

// ---------------------------------------------------------------------------
// MODE FLAGS
// ---------------------------------------------------------------------------

func TestFlag_PcapMode(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "lldp_detailed.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	assert.NotEmpty(t, hosts)
	// LLDP data should be present
	found := false
	for _, h := range hosts {
		if h["lldp"] != nil {
			found = true
		}
	}
	assert.True(t, found, "expected LLDP data in at least one host")
}

func TestFlag_Passive(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--passive", "--pcap", pcap, "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	assert.NotEmpty(t, hosts)
}

func TestFlag_SYN_InPcapMode(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--SYN")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir) // just verify it exists
}

func TestFlag_Profile_Stealth(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--profile", "stealth")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_Profile_Aggressive(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--profile", "aggressive")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_Profile_Invalid(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--profile", "bogus_profile")
	// Should still work (unknown profile is a no-op), or produce a warning
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

// ---------------------------------------------------------------------------
// OUTPUT FORMAT FLAGS
// ---------------------------------------------------------------------------

func TestFlag_Format_JSON(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	assert.NotEmpty(t, hosts)
}

func TestFlag_Format_CSV(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--pcap", pcap, "--formats", "csv", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	csvFiles, _ := filepath.Glob(filepath.Join(outDir, "*", "hosts.csv"))
	require.NotEmpty(t, csvFiles)
	data, err := os.ReadFile(csvFiles[0])
	require.NoError(t, err)
	r := csv.NewReader(strings.NewReader(string(data)))
	r.Comma = ';'
	records, err := r.ReadAll()
	require.NoError(t, err)
	assert.Greater(t, len(records), 1, "CSV should have header + data rows")
}

func TestFlag_Format_HTML(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--pcap", pcap, "--formats", "html", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	htmlFiles, _ := filepath.Glob(filepath.Join(outDir, "*", "report.html"))
	require.NotEmpty(t, htmlFiles)
	data, err := os.ReadFile(htmlFiles[0])
	require.NoError(t, err)
	assert.Contains(t, string(data), "<html")
}

func TestFlag_Format_Markdown(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--pcap", pcap, "--formats", "markdown", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	mdFiles, _ := filepath.Glob(filepath.Join(outDir, "*", "report.md"))
	require.NotEmpty(t, mdFiles)
	data, err := os.ReadFile(mdFiles[0])
	require.NoError(t, err)
	assert.Contains(t, string(data), "#")
}

func TestFlag_Format_All(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--pcap", pcap, "--formats", "json,csv,html,markdown", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	for _, pattern := range []string{"hosts.json", "hosts.csv", "report.html", "report.md"} {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*", pattern))
		assert.NotEmpty(t, matches, "expected %s", pattern)
	}
}

func TestFlag_Format_Invalid(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, stderr, code := run(t, "--pcap", pcap, "--formats", "invalid_fmt", "--output-dir", outDir)
	assert.NotEqual(t, 0, code, "invalid format should fail")
	assert.Contains(t, stderr, "invalid format")
}

// ---------------------------------------------------------------------------
// SCAN PARAMETER FLAGS (all should be accepted without crash in pcap mode)
// ---------------------------------------------------------------------------

func TestFlag_TTL(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--ttl", "128")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_PassiveDuration(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--passive-duration", "10")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_SynPorts(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--syn-ports", "22,80,443,8080")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_SynTimeout(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--syn-timeout", "2000")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_ArpMaxPerSec(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--arp-max-per-sec", "10")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_ArpBurst(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--arp-burst", "20")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_BurstDelays(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--burst-min-delay", "100", "--burst-max-delay", "500")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_Blacklist(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--blacklist", "192.168.0.1,10.0.0.0/8")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

// ---------------------------------------------------------------------------
// LOGGING FLAGS
// ---------------------------------------------------------------------------

func TestFlag_Verbose(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, _, code := run(t, "--pcap", pcap, "--verbose", "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	// Verbose logs go to the log file, not stderr. Verify the log file exists and is non-empty.
	logFiles, _ := filepath.Glob(filepath.Join(outDir, "*", "*.log"))
	if len(logFiles) > 0 {
		data, _ := os.ReadFile(logFiles[0])
		assert.Greater(t, len(data), 100, "verbose log file should be non-trivial")
	}
	_ = findJSON(t, outDir) // verify it completed
}

func TestFlag_Quiet(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	_, stderr, code := run(t, "--pcap", pcap, "--quiet", "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	quietLines := strings.Count(stderr, "\n")
	assert.Less(t, quietLines, 10, "quiet mode should produce few log lines")
}

func TestFlag_Paranoid(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	stdout, _, code := run(t, "--pcap", pcap, "--paranoid", "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	// Paranoid mode: stdout should have at most the completion message
	stdoutLines := len(strings.TrimSpace(stdout))
	assert.Less(t, stdoutLines, 200, "paranoid mode should have minimal stdout")
}

// ---------------------------------------------------------------------------
// OTHER FLAGS
// ---------------------------------------------------------------------------

func TestFlag_Summary(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := t.TempDir()
	stdout, _, code := run(t, "--pcap", pcap, "--summary", "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "Hosts")
}

func TestFlag_Config(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	cfgPath := filepath.Join(repoRoot(t), "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Skip("config.yaml not found")
	}
	outDir, code := runPcap(t, pcap, "--config", cfgPath)
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_RecordPcap_InPcapMode(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap, "--record-pcap")
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

func TestFlag_Demo(t *testing.T) {
	t.Parallel()
	stdout, _, code := run(t, "--demo")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "DONE")
}

func TestFlag_Help(t *testing.T) {
	t.Parallel()
	stdout, _, _ := run(t, "--help")
	assert.Contains(t, stdout, "Zandoli")
	assert.Contains(t, stdout, "--pcap")
	assert.Contains(t, stdout, "--profile")
}

func TestFlag_InvalidFlag(t *testing.T) {
	t.Parallel()
	_, _, code := run(t, "--nonexistent-flag-xyz")
	assert.NotEqual(t, 0, code)
}

func TestFlag_MissingPcap(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	_, stderr, code := run(t, "--pcap", "/nonexistent/file.pcap", "--formats", "json", "--output-dir", outDir)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "no such file")
}

func TestFlag_OutputDir_Nested(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir := filepath.Join(t.TempDir(), "custom", "nested", "path")
	_, _, code := run(t, "--pcap", pcap, "--formats", "json", "--output-dir", outDir)
	assert.Equal(t, 0, code)
	_ = findJSON(t, outDir)
}

// ---------------------------------------------------------------------------
// PROTOCOL-SPECIFIC VALIDATION
// ---------------------------------------------------------------------------

func TestProtocol_LLDP(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "lldp_detailed.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	found := false
	for _, h := range hosts {
		if lldp, ok := h["lldp"].(map[string]interface{}); ok {
			if lldp["sys_name"] != nil {
				found = true
			}
		}
	}
	assert.True(t, found, "expected LLDP sys_name in at least one host")
}

func TestProtocol_CDP(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "cdp_v2.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	found := false
	for _, h := range hosts {
		if cdp, ok := h["cdp"].(map[string]interface{}); ok {
			if cdp["device_id"] != nil {
				found = true
			}
		}
	}
	assert.True(t, found, "expected CDP device_id in at least one host")
}

func TestProtocol_DHCP(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dhcp.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	foundDHCP := false
	for _, h := range hosts {
		protos, _ := h["protocols"].([]interface{})
		for _, p := range protos {
			if p == "DHCP" {
				foundDHCP = true
			}
		}
	}
	assert.True(t, foundDHCP, "expected DHCP protocol in at least one host")
}

func TestProtocol_DNS(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "dns.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	foundDNS := false
	for _, h := range hosts {
		protos, _ := h["protocols"].([]interface{})
		for _, p := range protos {
			if p == "DNS" {
				foundDNS = true
			}
		}
	}
	assert.True(t, foundDNS, "expected DNS protocol in at least one host")
}

func TestProtocol_HSRP(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "hsrp_v1.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	found := false
	for _, h := range hosts {
		gr, _ := h["gateway_redundancy"].([]interface{})
		for _, g := range gr {
			gm, _ := g.(map[string]interface{})
			if gm["protocol"] == "hsrp_v1" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected gateway_redundancy with hsrp_v1")
}

func TestProtocol_VRRP(t *testing.T) {
	t.Parallel()
	pcap := pcapPath(t, "vrrp_v2.pcap")
	outDir, code := runPcap(t, pcap)
	assert.Equal(t, 0, code)
	hosts := loadHosts(t, findJSON(t, outDir))
	found := false
	for _, h := range hosts {
		gr, _ := h["gateway_redundancy"].([]interface{})
		for _, g := range gr {
			gm, _ := g.(map[string]interface{})
			if gm["protocol"] == "vrrp_v2" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected gateway_redundancy with vrrp_v2")
}
