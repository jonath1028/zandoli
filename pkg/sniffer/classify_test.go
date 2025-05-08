package sniffer

import (
	"net"
	"testing"
)

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		name          string
		protocols     map[string]bool
		expectedClass string
	}{
		{"SMBHost", map[string]bool{"SMB": true}, "server"},
		{"NetBIOSHost", map[string]bool{"NetBIOS": true}, "server"},
		{"WorkstationHost", map[string]bool{"mDNS": true}, "workstation"},
		{"NetworkDevice", map[string]bool{"LLDP": true}, "network"},
		{"Fallback", map[string]bool{}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &Host{
				IP:            net.IPv4(192, 168, 1, 1),
				MAC:           net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
				MACStr:        "de:ad:be:ef:00:01",
				ProtocolsSeen: tt.protocols,
				Vendor:        "UnknownVendor",
			}

			ClassifyHost(host)

			if host.Category != tt.expectedClass {
				t.Errorf("expected category %s, got %s", tt.expectedClass, host.Category)
			}
		})
	}
}

