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
	MaxPerSecond int
	MaxPerBurst  int
	MinPerBurst  int
	BurstWindow  time.Duration
	JitterMean   time.Duration
	BurstPauseMin time.Duration
	BurstPauseMax time.Duration
}

var StealthARP = StealthConfig{
	MaxPerSecond: 3,
	MinPerBurst:  2,
	MaxPerBurst:  10,
	JitterMean:   200 * time.Millisecond,
	BurstWindow:  25 * time.Second,
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
	Stealth         StealthConfig `yaml:"stealth"` // ← configuration du scan furtif
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
	return &cfg, nil
}

