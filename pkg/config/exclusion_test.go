package config

import (
	"net"
	"os"
	"testing"
)

func writeTempExclusionFile(t *testing.T, content string) string {
	tmpfile, err := os.CreateTemp("", "excluded_subnets_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	return tmpfile.Name()
}

func TestLoadExcludedSubnets(t *testing.T) {
	data := `
192.168.1.0/24
10.0.0.0/8
172.16.0.0/12
# this is a comment
`

	path := writeTempExclusionFile(t, data)
	defer os.Remove(path)

	err := LoadExcludedSubnets(path)
	if err != nil {
		t.Fatalf("failed to load subnets: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.42", true},
		{"10.5.5.5", true},
		{"172.16.42.42", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("invalid IP test case: %s", tc.ip)
		}
		result := IsIPExcluded(ip)
		if result != tc.expected {
			t.Errorf("IsIPExcluded(%s) = %v; want %v", tc.ip, result, tc.expected)
		}
	}
}
