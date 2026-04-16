// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package oui

import (
	"bufio"
	_ "embed"
	"io"
	"os"
	"strings"
)

//go:embed oui_embedded.txt
var EmbeddedOUIData string

type Map struct {
	ByPref map[string]string
	Source string // "embedded" ou chemin du fichier
}

func New() *Map {
	return &Map{ByPref: make(map[string]string, 40000)}
}

func normPref(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.NewReplacer("-", ":", ".", ":").Replace(s)
	if len(s) >= 8 {
		return s[:8]
	} // "AA:BB:CC"
	return s
}

// LoadEmbedded loads the OUI database embedded in the binary
func (m *Map) LoadEmbedded() error {
	m.Source = "embedded"
	return m.loadFromReader(strings.NewReader(EmbeddedOUIData))
}

// Load charge un fichier OUI au format: "AA:BB:CC<TAB/SPACE>Vendor Name"
// If path is empty, loads the embedded data
func (m *Map) Load(path string) error {
	if path == "" {
		return m.LoadEmbedded()
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	m.Source = path
	return m.loadFromReader(f)
}

// loadFromReader loads OUI data from an io.Reader
func (m *Map) loadFromReader(r io.Reader) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept TAB or multiple spaces as separator
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pref := normPref(parts[0])
		vend := strings.TrimSpace(strings.Join(parts[1:], " "))
		if pref != "" && vend != "" {
			m.ByPref[pref] = vend
		}
	}
	return sc.Err()
}

func (m *Map) VendorFromMAC(mac string) string {
	mac = normPref(mac)
	if len(mac) < 8 {
		return ""
	}
	if v, ok := m.ByPref[mac[:8]]; ok {
		return v
	}
	return ""
}
