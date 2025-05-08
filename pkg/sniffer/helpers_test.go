package sniffer

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := map[string]bool{
		"192.168.1.1": true,
		"10.0.0.1":    true,
		"172.16.5.5":  true,
		"8.8.8.8":     false,
	}

	for ipStr, expected := range tests {
		ip := net.ParseIP(ipStr)
		if isPrivateIP(ip) != expected {
			t.Errorf("isPrivateIP(%s) = %v; want %v", ipStr, !expected, expected)
		}
	}
}

func TestUpdateHostDNS(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 42).To4()
	DiscoveredHosts = []Host{{
		IP:            ip,
		ProtocolsSeen: make(map[string]bool),
	}}

	domain := "host.example.local"
	UpdateHostDNS(ip, domain)

	host := FindHostByIP(ip)
	if host == nil {
		t.Fatal("host not found after UpdateHostDNS")
	}
	if host.Hostname != "host" {
		t.Errorf("expected hostname 'host', got '%s'", host.Hostname)
	}
	if host.DomainName != domain {
		t.Errorf("expected domain '%s', got '%s'", domain, host.DomainName)
	}
	if !host.ProtocolsSeen["dns"] {
		t.Errorf("expected 'dns' in ProtocolsSeen")
	}
}

