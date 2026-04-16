// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package exporter

import (
	"testing"

	"zandoli/pkg/model"
	"zandoli/pkg/utils"
)

func TestSubnetFilteringInExporters(t *testing.T) {
	// Créer des sous-réseaux de test avec différents masques
	subnets := []model.Subnet{
		{CIDR: "192.168.1.0/24", Source: "ARP", Hosts: []string{"192.168.1.1", "192.168.1.2"}},
		{CIDR: "192.168.2.0/24", Source: "DHCP", Hosts: []string{"192.168.2.1"}},
		{CIDR: "10.0.0.0/16", Source: "ARP", Hosts: []string{"10.0.0.1", "10.0.1.1"}},
		{CIDR: "172.16.0.0/12", Source: "CDP", Hosts: []string{"172.16.0.1"}},
		{CIDR: "192.168.3.0/24", Source: "LLDP", Hosts: []string{"192.168.3.1"}},
	}

	// Tester la fonction de filtrage
	filtered := utils.FilterSubnets24(subnets)

	// Vérifier que seuls les /24 sont conservés
	expectedCount := 3
	if len(filtered) != expectedCount {
		t.Errorf("Attendu %d sous-réseaux /24, obtenu %d", expectedCount, len(filtered))
	}

	// Vérifier que tous les sous-réseaux filtrés sont bien /24
	for _, subnet := range filtered {
		if !isSubnet24(subnet.CIDR) {
			t.Errorf("Le sous-réseau %s n'est pas un /24", subnet.CIDR)
		}
	}

	// Vérifier que les sous-réseaux /16 et /12 ne sont pas inclus
	for _, subnet := range filtered {
		if subnet.CIDR == "10.0.0.0/16" || subnet.CIDR == "172.16.0.0/12" {
			t.Errorf("Le sous-réseau %s ne devrait pas être inclus", subnet.CIDR)
		}
	}
}

// isSubnet24 vérifie si un CIDR est un sous-réseau /24
func isSubnet24(cidr string) bool {
	// Vérification simple pour les tests
	return len(cidr) >= 3 && cidr[len(cidr)-3:] == "/24"
}


