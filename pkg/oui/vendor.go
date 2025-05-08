package oui

import (
	"strings"

	"zandoli/pkg/logger"
)

var Vendors = map[string]string{}

// LoadVendors charge les données de vendors depuis un fichier texte (ex: mac_vendors.txt)
// Format attendu : 00:11:22\tApple Inc.
func LoadVendors(path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			oui := normalizeOUI(parts[0])
			vendor := strings.TrimSpace(parts[1])
			if oui != "" && vendor != "" {
				Vendors[oui] = vendor
			}
		}
	}
	return nil
}

// GetVendor retourne le nom du constructeur associé à une adresse MAC
func GetVendor(mac string) string {
	oui := normalizeOUI(mac)
	if vendor, found := Vendors[oui]; found {
		return vendor
	}
	return "Unknown"
}

// GuessCategory retourne une catégorie probable à partir du nom du vendor
func GuessCategory(vendor string) string {
	v := strings.ToLower(vendor)
	v = strings.ReplaceAll(v, "-", " ")
	v = strings.ReplaceAll(v, ":", " ")
	v = strings.ReplaceAll(v, ".", " ")
	v = strings.ReplaceAll(v, ",", " ")
	v = strings.ReplaceAll(v, "_", " ")

	logger.Logger.Debug().Msgf("[GuessCategory] Vendor raw: '%s' | Normalized: '%s'", vendor, v)

	switch {
	// Workstations
	case strings.Contains(v, "dell"),
		strings.Contains(v, "lenovo"),
		strings.Contains(v, "hp"),
		strings.Contains(v, "hewlett"),
		strings.Contains(v, "samsung"),
		strings.Contains(v, "apple"),
		strings.Contains(v, "acer"),
		strings.Contains(v, "asus"),
		strings.Contains(v, "toshiba"),
		strings.Contains(v, "msi"):
		return "workstation"

	// Printers
	case strings.Contains(v, "canon"),
		strings.Contains(v, "epson"),
		strings.Contains(v, "brother"),
		strings.Contains(v, "ricoh"),
		strings.Contains(v, "lexmark"),
		strings.Contains(v, "xerox"),
		strings.Contains(v, "kyocera"):
		return "printer"

	// Switches
	case strings.Contains(v, "cisco"),
		strings.Contains(v, "juniper"),
		strings.Contains(v, "arista"),
		strings.Contains(v, "netgear"),
		strings.Contains(v, "tp link"),
		strings.Contains(v, "d link"),
		strings.Contains(v, "extremenetworks"),
		strings.Contains(v, "ubiquiti"),
		strings.Contains(v, "mikrotik"),
		strings.Contains(v, "huawei"),
		strings.Contains(v, "asus"),
		strings.Contains(v, "netgear"),
		strings.Contains(v, "tp link"),
		strings.Contains(v, "linksys"),
		strings.Contains(v, "zyxel"):
		return "network"

	// IoT
	case strings.Contains(v, "espressif"),
		strings.Contains(v, "tuya"),
		strings.Contains(v, "sonoff"),
		strings.Contains(v, "shelly"),
		strings.Contains(v, "broadlink"),
		strings.Contains(v, "tplink"),
		strings.Contains(v, "nordic"),
		strings.Contains(v, "smartthings"):
		return "iot"

	// Virtual Machines
	case strings.Contains(v, "vmware"),
		strings.Contains(v, "virtualbox"),
		strings.Contains(v, "xen"),
		strings.Contains(v, "qemu"),
		strings.Contains(v, "parallels"):
		return "virtual"

	// Firewalls
	case strings.Contains(v, "fortinet"),
		strings.Contains(v, "palo alto"),
		strings.Contains(v, "sophos"),
		strings.Contains(v, "watchguard"),
		strings.Contains(v, "checkpoint"):
		return "firewall"

	// Wi-Fi Access Points
	case strings.Contains(v, "aruba"),
		strings.Contains(v, "linksys"),
		strings.Contains(v, "ubiquiti"),
		strings.Contains(v, "tp link"),
		strings.Contains(v, "d link"):
		return "access_point"

	// IP Cameras
	case strings.Contains(v, "hikvision"),
		strings.Contains(v, "dahua"),
		strings.Contains(v, "axis"),
		strings.Contains(v, "reolink"),
		strings.Contains(v, "amcrest"):
		return "camera"

	// NAS / Storage
	case strings.Contains(v, "synology"),
		strings.Contains(v, "qnap"),
		strings.Contains(v, "seagate"),
		strings.Contains(v, "wd"),
		strings.Contains(v, "western digital"),
		strings.Contains(v, "drobo"):
		return "storage"

	default:
		logger.Logger.Debug().Msgf("[GuessCategory] ❌ Unmatched category for vendor: '%s'", vendor)
		return "unknown"
	}
}
