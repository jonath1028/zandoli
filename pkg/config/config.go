package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Configuration du mode de scan (passive, active, combined, pcap)
type ScanConfig struct {
	Mode       string `yaml:"mode"`        // passive | active | combined | pcap
	ActiveType string `yaml:"active_type"` // standard | stealth
}

// Configuration fine pour le mode stealth
type StealthConfig struct {
	MaxPerSecond  int           `yaml:"max_requests_per_second"`
	MaxPerBurst   int           `yaml:"max_requests_per_burst"`
	MinPerBurst   int           `yaml:"min_requests_per_burst,omitempty"` // valeur optionnelle
	BurstWindow   time.Duration `yaml:"burst_interval_seconds"`
	JitterMean    time.Duration `yaml:"jitter_mean,omitempty"`      // valeur calculée ou fixe
	BurstPauseMin time.Duration `yaml:"burst_pause_min,omitempty"` // intervalle optionnel
	BurstPauseMax time.Duration `yaml:"burst_pause_max,omitempty"`
}

// Valeurs par défaut si certaines ne sont pas définies dans le YAML
var StealthARP = StealthConfig{
	MaxPerSecond:  3,
	MinPerBurst:   2,
	MaxPerBurst:   10,
	JitterMean:    200 * time.Millisecond,
	BurstWindow:   25 * time.Second,
	BurstPauseMin: 1 * time.Second,
	BurstPauseMax: 3 * time.Second,
}

// Structure principale de configuration
type Config struct {
	Iface           string        `yaml:"iface"`
	PassiveDuration int           `yaml:"passive_duration"`
	OutputDir       string        `yaml:"output_dir"`
	LogFile         string        `yaml:"log_file"`
	LogLevel        string        `yaml:"log_level"`
	ExcludeIPs      []string      `yaml:"exclude_ips"`
	Scan            ScanConfig    `yaml:"scan"`
	Stealth         StealthConfig `yaml:"stealth_scan"` // correspond à la clé YAML
}

// Charge et parse le fichier de configuration YAML
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Appliquer les valeurs par défaut si certains champs sont manquants
	if cfg.Stealth.MaxPerSecond == 0 {
		cfg.Stealth.MaxPerSecond = StealthARP.MaxPerSecond
	}
	if cfg.Stealth.MaxPerBurst == 0 {
		cfg.Stealth.MaxPerBurst = StealthARP.MaxPerBurst
	}
	if cfg.Stealth.BurstWindow == 0 {
		cfg.Stealth.BurstWindow = StealthARP.BurstWindow
	}

	return &cfg, nil
}

