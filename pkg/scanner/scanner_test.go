package scanner

import (
	"net"
	"testing"
)

func TestIterateIPs(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.0.0/30")
	ips := []string{}
	for ip := range iterateIPs(subnet) {
		ips = append(ips, ip.String())
	}

	expected := []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}
	if len(ips) != len(expected) {
		t.Errorf("expected %d IPs, got %d", len(expected), len(ips))
	}
}
