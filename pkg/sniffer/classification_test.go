package sniffer

import (
	"net"
	"testing"
)

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		name         string
		protocols    []string
		expected     string
	}{
		{"Workstation with DHCP and mDNS", []string{"DHCP", "mDNS"}, "workstation"},
		{"Server with SMB", []string{"SMB"}, "server"},
		{"Network device with LLDP", []string{"LLDP"}, "network"},
		{"Unknown with DNS only", []string{"DNS"}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Host{
				IP:            net.ParseIP("192.168.1.100"),
				MAC:           net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
				ProtocolsSeen: map[string]bool{},
			}
			for _, p := range tt.protocols {
				h.ProtocolsSeen[p] = true
			}
			ClassifyHost(h)
			if h.Category != tt.expected {
				t.Errorf("Expected category %s, got %s", tt.expected, h.Category)
			}
		})
	}
}

