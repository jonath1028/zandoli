package oui

import (
	"bufio"
	"os"
	"strings"
)

type LabelType string

const (
	LabelDefensive   LabelType = "defensive"
	LabelBlacklisted LabelType = "blacklisted"
)

type LabelInfo struct {
	Type   LabelType
	Source string
}

var Labels = map[string]LabelInfo{}

// LoadOUILists charge et fusionne les fichiers OUI défensifs et blacklistés
func LoadOUILists(defensivePath, blacklistPath string) error {
	if err := loadOUIFile(defensivePath, LabelDefensive); err != nil {
		return err
	}
	if err := loadOUIFile(blacklistPath, LabelBlacklisted); err != nil {
		return err
	}
	return nil
}

func loadOUIFile(path string, label LabelType) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	for _, line := range lines {
		oui := normalizeOUI(line)
		if oui != "" {
			Labels[oui] = LabelInfo{Type: label, Source: path}
		}
	}
	return nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func normalizeOUI(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(clean) >= 6 {
		return clean[:6]
	}
	return ""
}

func IsFiltered(mac string) bool {
	oui := normalizeOUI(mac)
	_, found := Labels[oui]
	return found
}

// GetLabel returns the label type for a MAC address (or "unknown")
func GetLabel(mac string) (LabelType, bool) {
	oui := normalizeOUI(mac)
	if label, found := Labels[oui]; found {
		return label.Type, true
	}
	return "unknown", false
}

