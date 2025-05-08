package utils

import (
	"net"
	"testing"
)

func TestIncIP(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 1).To4()
	IncIP(ip)
	expected := "192.168.1.2"
	if ip.String() != expected {
		t.Errorf("expected %s, got %s", expected, ip.String())
	}
}

