package security

import (
	"net"
)

// Summary contient les signaux de sécurité réseau détectés passivement.
// Ce module est conçu pour rester minimal, structuré et extensible.
// Chaque champ reflète un indicateur pouvant signaler une configuration défensive ou une anomalie réseau.
type Summary struct {
	// ✅ Présence de 802.1X / EAPOL (environnement NAC)
	PassiveSecurity8021X bool `json:"eapol_8021x,omitempty"`

	// ✅ MACs vues avec plusieurs IPs (souvent VM, bridge, spoof, NAT...)
	MACWithMultipleIPs map[string][]net.IP `json:"mac_with_multiple_ips,omitempty"`

	// Multiple mac une ip
	IPWithMultipleMACs map[string][]net.HardwareAddr `json:"ip_with_multiple_macs,omitempty"`
	// 🔜 D'autres signaux à venir (DHCP snooping, proxy, TTL incohérent...)

}

// Exporté globalement pour accès cross-module
var SecuritySummary = Summary{
	MACWithMultipleIPs:  make(map[string][]net.IP),
	IPWithMultipleMACs:  make(map[string][]net.HardwareAddr),
}

