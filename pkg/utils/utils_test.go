package utils

import (
	"net"
	"testing"
)

func TestIPsInSubnet(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("failed to parse subnet: %v", err)
	}

	exclude := net.ParseIP("192.168.1.1")
	ips := []string{}
	for ip := range IPsInSubnet(subnet, exclude) {
		ips = append(ips, ip.String())
	}

	expected := []string{"192.168.1.0", "192.168.1.2", "192.168.1.3"}
	if len(ips) != len(expected) {
		t.Fatalf("expected %d IPs, got %d", len(expected), len(ips))
	}
	for i, ip := range expected {
		if ips[i] != ip {
			t.Errorf("expected %s, got %s", ip, ips[i])
		}
	}
}


