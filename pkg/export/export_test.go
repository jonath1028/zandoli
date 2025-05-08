package export

import (
	"path/filepath"
	"testing"
	"time"

	"zandoli/pkg/sniffer"
	"net"
)

func TestExportAll(t *testing.T) {
	tmpDir := t.TempDir()

	hosts := []sniffer.Host{
		{
			IP:              net.ParseIP("192.168.1.10"),
			MAC:             mustParseMAC("00:11:22:33:44:55"),
			Timestamp:       time.Now(),
			DetectionMethod: "passive",
			Vendor:          "TestVendor",
			Category:        "workstation",
			Hostname:        "testhost",
			DomainName:      "example.local",
			ProtocolsSeen:   map[string]bool{"DNS": true},
			Metadata:        map[string]string{"dhcp_server": "192.168.1.1"},
		},
	}

	err := ExportAll(hosts, tmpDir, "eth0", 60)
	if err != nil {
		t.Fatalf("ExportAll failed: %v", err)
	}

	expected := []string{".json", ".csv", ".html"}
	for _, ext := range expected {
		matches, _ := filepath.Glob(filepath.Join(tmpDir, "*"+ext))
		if len(matches) == 0 {
			t.Errorf("expected file with extension %s not found", ext)
		}
	}
}

func mustParseMAC(mac string) net.HardwareAddr {
	addr, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return addr
}

