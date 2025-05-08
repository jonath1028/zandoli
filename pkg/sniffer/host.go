package sniffer

import (
	"net"
	"time"

	"zandoli/pkg/logger"
	"zandoli/pkg/oui"
)

type Host struct {
	IP              net.IP           `json:"ip"`
	MAC             net.HardwareAddr `json:"-"`
	MACStr          string           `json:"mac"`
	Timestamp       time.Time        `json:"timestamp"`
	DetectionMethod string           `json:"detection_method"`
	Vendor          string           `json:"vendor"`
	Category        string           `json:"category"`

	// Champs enrichis par l’analyse passive
	Hostname      string            `json:"hostname,omitempty"`
	DomainName    string            `json:"domain_name,omitempty"`
	ProtocolsSeen map[string]bool   `json:"protocols_seen,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// NewHost crée un nouvel hôte découvert sur le réseau
func NewHost(ip net.IP, mac net.HardwareAddr, method string) Host {
	vendor := oui.GetVendor(mac.String())
	category := oui.GuessCategory(vendor)

	h := Host{
		IP:              ip,
		MAC:             mac,
		MACStr:          mac.String(),
		Timestamp:       time.Now(),
		DetectionMethod: method,
		Vendor:          vendor,
		Category:        category,
		Hostname:        "",
		DomainName:      "",
		ProtocolsSeen:   make(map[string]bool),
		Metadata:        make(map[string]string),
	}

	logger.Logger.Debug().Msgf("[DEBUG] NewHost() => IP=%s MAC=%s Vendor=%s InitialCategory=%s",
		h.IP, h.MACStr, h.Vendor, h.Category)

	return h
}

// FindHostByIP retourne un pointeur vers l’hôte déjà connu (ou nil sinon)
func FindHostByIP(ip net.IP) *Host {
	for i := range DiscoveredHosts {
		if DiscoveredHosts[i].IP.Equal(ip) {
			logger.Logger.Debug().Msgf("[FindHostByIP] MATCH: %s", ip)
			return &DiscoveredHosts[i]
		} else {
			logger.Logger.Debug().Msgf("[FindHostByIP] MISMATCH: wanted %s, got %s", ip, DiscoveredHosts[i].IP)
		}
	}
	return nil
}

// ClassifyHost attribue une catégorie à l'hôte selon les protocoles observés
func ClassifyHost(h *Host) {
	switch {
	case h.ProtocolsSeen["SMB"] || h.ProtocolsSeen["NetBIOS"]:
		h.Category = "server"
	case h.ProtocolsSeen["DHCP"] || h.ProtocolsSeen["mDNS"] || h.ProtocolsSeen["LLMNR"]:
		h.Category = "workstation"
	case h.ProtocolsSeen["CDP"] || h.ProtocolsSeen["LLDP"] || h.ProtocolsSeen["STP"]:
		h.Category = "network"
	default:
		h.Category = oui.GuessCategory(h.Vendor) // fallback
	}

	logger.Logger.Debug().Msgf("[DEBUG] ClassifyHost() => IP=%s Category=%s (based on protocols)", h.IP, h.Category)
}

