// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package model

import (
	"net"
	"testing"
)

func TestHost_DualStack_NoOverwrite(t *testing.T) {
	tests := []struct {
		name             string
		ipsToAdd         []net.IP
		expectedIPv4     net.IP
		expectedIPv6     net.IP
		expectedIPsCount int
	}{
		{
			name: "IPv6 puis IPv4",
			ipsToAdd: []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("192.168.1.100"),
			},
			expectedIPv4:     net.ParseIP("192.168.1.100"),
			expectedIPv6:     net.ParseIP("2001:db8::1"),
			expectedIPsCount: 2,
		},
		{
			name: "IPv4 puis IPv6",
			ipsToAdd: []net.IP{
				net.ParseIP("192.168.1.100"),
				net.ParseIP("2001:db8::1"),
			},
			expectedIPv4:     net.ParseIP("192.168.1.100"),
			expectedIPv6:     net.ParseIP("2001:db8::1"),
			expectedIPsCount: 2,
		},
		{
			name: "Multiple IPv4 et IPv6",
			ipsToAdd: []net.IP{
				net.ParseIP("192.168.1.100"),
				net.ParseIP("2001:db8::1"),
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::2"),
			},
			expectedIPv4:     net.ParseIP("10.0.0.1"),    // Dernière IPv4 ajoutée
			expectedIPv6:     net.ParseIP("2001:db8::2"), // Dernière IPv6 ajoutée
			expectedIPsCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &Host{
				IPs: []net.IP{},
			}

			// Ajouter les IPs dans l'ordre spécifié
			for _, ip := range tt.ipsToAdd {
				host.AddIP(ip)
			}

			// Vérifier que les deux familles sont préservées
			if !host.IP.Equal(tt.expectedIPv4) {
				t.Errorf("IPv4 principale = %v, attendu %v", host.IP, tt.expectedIPv4)
			}

			if !host.IPv6Primary.Equal(tt.expectedIPv6) {
				t.Errorf("IPv6 principale = %v, attendu %v", host.IPv6Primary, tt.expectedIPv6)
			}

			if len(host.IPs) != tt.expectedIPsCount {
				t.Errorf("Nombre d'IPs = %d, attendu %d", len(host.IPs), tt.expectedIPsCount)
			}

			// Vérifier qu'aucune IPv6 n'est dans le champ IP (pas d'écrasement)
			if host.IP != nil && host.IP.To4() == nil {
				t.Errorf("Le champ IP contient une IPv6: %v", host.IP)
			}

			// Vérifier qu'aucune IPv4 n'est dans le champ IPv6Primary (pas d'écrasement)
			if host.IPv6Primary != nil && host.IPv6Primary.To4() != nil {
				t.Errorf("Le champ IPv6Primary contient une IPv4: %v", host.IPv6Primary)
			}
		})
	}
}

func TestHost_LinkLocal_NotPrimary(t *testing.T) {
	host := &Host{
		IPs: []net.IP{},
	}

	// Ajouter une IPv6 link-local et une IPv4 privée
	host.AddIP(net.ParseIP("fe80::1"))
	host.AddIP(net.ParseIP("192.168.1.100"))

	// Vérifier que l'IPv6 link-local n'est pas sélectionnée comme primaire
	if host.IPv6Primary != nil {
		t.Errorf("IPv6Primary ne devrait pas être définie pour fe80::/10, reçu: %v", host.IPv6Primary)
	}

	// Vérifier que l'IPv4 est correctement définie
	if !host.IP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("IPv4 principale = %v, attendu 192.168.1.100", host.IP)
	}

	// Vérifier que l'IPv6 link-local est dans la liste des IPs
	found := false
	for _, ip := range host.IPs {
		if ip.Equal(net.ParseIP("fe80::1")) {
			found = true
			break
		}
	}
	if !found {
		t.Error("IPv6 link-local fe80::1 devrait être présente dans la liste des IPs")
	}
}

func TestHost_GetPrimaryMethods(t *testing.T) {
	host := &Host{
		IPs: []net.IP{},
	}

	host.AddIP(net.ParseIP("192.168.1.100"))
	host.AddIP(net.ParseIP("2001:db8::1"))

	// Tester les méthodes de récupération des IPs principales
	if !host.GetPrimaryIPv4().Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("GetPrimaryIPv4() = %v, attendu 192.168.1.100", host.GetPrimaryIPv4())
	}

	if !host.GetPrimaryIPv6().Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("GetPrimaryIPv6() = %v, attendu 2001:db8::1", host.GetPrimaryIPv6())
	}
}

func TestHost_GetIPsAsStrings(t *testing.T) {
	host := &Host{
		IPs: []net.IP{},
	}

	host.AddIP(net.ParseIP("2001:db8::1"))
	host.AddIP(net.ParseIP("192.168.1.100"))
	host.AddIP(net.ParseIP("10.0.0.1"))

	// Tester GetAllIPsAsStrings
	allIPs := host.GetAllIPsAsStrings()
	expectedCount := 3
	if len(allIPs) != expectedCount {
		t.Errorf("GetAllIPsAsStrings() retourne %d IPs, attendu %d", len(allIPs), expectedCount)
	}

	// Tester GetIPv4sAsStrings
	ipv4s := host.GetIPv4sAsStrings()
	expectedIPv4Count := 2
	if len(ipv4s) != expectedIPv4Count {
		t.Errorf("GetIPv4sAsStrings() retourne %d IPv4, attendu %d", len(ipv4s), expectedIPv4Count)
	}

	// Tester GetIPv6sAsStrings
	ipv6s := host.GetIPv6sAsStrings()
	expectedIPv6Count := 1
	if len(ipv6s) != expectedIPv6Count {
		t.Errorf("GetIPv6sAsStrings() retourne %d IPv6, attendu %d", len(ipv6s), expectedIPv6Count)
	}

	// Vérifier que les listes sont triées
	for i := 1; i < len(allIPs); i++ {
		if allIPs[i-1] > allIPs[i] {
			t.Error("GetAllIPsAsStrings() ne retourne pas une liste triée")
		}
	}
}

func TestIsLinkLocalIPv6(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"fe80::1", true},
		{"fe80::1234:5678:9abc:def0", true},
		{"2001:db8::1", false},
		{"::1", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := isLinkLocalIPv6(ip)
			if result != tt.expected {
				t.Errorf("isLinkLocalIPv6(%s) = %v, attendu %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestHost_DuplicateIPs(t *testing.T) {
	host := &Host{
		IPs: []net.IP{},
	}

	// Ajouter la même IP plusieurs fois
	ip := net.ParseIP("192.168.1.100")
	host.AddIP(ip)
	host.AddIP(ip)
	host.AddIP(ip)

	// Vérifier qu'il n'y a qu'une seule occurrence
	if len(host.IPs) != 1 {
		t.Errorf("Nombre d'IPs = %d, attendu 1 (pas de doublons)", len(host.IPs))
	}

	if !host.IPs[0].Equal(ip) {
		t.Errorf("IP stockée = %v, attendu %v", host.IPs[0], ip)
	}
}
