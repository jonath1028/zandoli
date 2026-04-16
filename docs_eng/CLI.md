# CLI Reference

This document provides a comprehensive reference for Zandoli's command-line interface.

## Basic Usage

```bash
zandoli [OPTIONS]
```

## Mode Selection

### Passive Mode
```bash
# Sniff network traffic only (no active scanning)
zandoli --passive --passive-duration 60 --interface eth0
```

### Active Mode
```bash
# Perform active scanning (ARP and SYN) only
zandoli --active --interface eth0
```

### Combined Mode
```bash
# Run passive sniffing followed by active scanning
zandoli --combined --passive-duration 60 --interface eth0
```

### PCAP Analysis Mode
```bash
# Analyze existing PCAP file (disables active scanning)
zandoli --pcap traffic.pcap
```

## Command Line Options

### Mode Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--passive` | bool | false | Run passive mode only (sniffing) |
| `--active` | bool | false | Run active mode only (ARP, SYN) |
| `--combined` | bool | false | Run passive then active scan |
| `--pcap` | string | "" | Path to PCAP file for offline analysis |
| `--demo` | bool | false | Run CLI progress bar demo instead of scan |

### Scan Configuration

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--passive-duration` | int | 0 | Passive sniffing duration in seconds |
| `--interface` | string | from config | Network interface to use |
| `--SYN` | bool | false | Enable SYN scan on unidentified hosts |
| `--syn-ports` | string | "" | Comma-separated TCP ports to scan (e.g. 80,443) |
| `--syn-timeout` | int | 0 | Timeout for each SYN scan attempt in ms |

### Network Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ttl` | int | 0 | TTL value for active scan packets |
| `--arp-max-per-sec` | int | 0 | Maximum ARP requests per second |
| `--arp-burst` | int | 0 | Maximum ARP requests per burst |
| `--burst-min-delay` | int | 0 | Minimum delay between ARP bursts in ms |
| `--burst-max-delay` | int | 0 | Maximum delay between ARP bursts in ms |
| `--stealth` | bool | false | Enable ARP stealth mode (randomized) |
| `--blacklist` | string | "" | Comma-separated IPs/subnets to exclude |

### Output Configuration

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output-dir` | string | "output" | Directory for output files |
| `--formats` | string | "" | Comma-separated export formats (json,csv,html,markdown,xml) |
| `--oui-file` | string | "" | Path to OUI.txt file for MAC vendor lookup |
| `--record-pcap` | bool | false | Record live sniffing into a PCAP file |

### Logging Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | bool | false | Enable verbose logging |
| `--quiet` | bool | false | Reduce log verbosity |
| `--paranoid` | bool | false | Suppress all stdout logs |
| `--summary` | bool | false | Show a scan summary in the CLI after execution |

### Configuration and Help

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | "config.yaml" | Path to YAML config file |
| `--help` | bool | false | Display help message and exit |

## Usage Examples

### Basic PCAP Analysis
```bash
# Analyze a PCAP file and generate HTML report
zandoli --pcap traffic.pcap --formats html

# Analyze with multiple output formats
zandoli --pcap traffic.pcap --formats html,csv,json --output-dir results
```

### Live Network Scanning
```bash
# Passive sniffing for 2 minutes
zandoli --passive --passive-duration 120 --interface eth0 --formats html,json

# Combined mode with custom output directory
zandoli --combined --passive-duration 60 --interface eth0 --output-dir /tmp/scan
```

### Active Scanning
```bash
# ARP scanning only
zandoli --active --interface eth0 --arp-max-per-sec 5

# SYN scanning with custom ports
zandoli --active --SYN --syn-ports 22,80,443,3389 --interface eth0
```

### Advanced Configuration
```bash
# Stealth mode with blacklist
zandoli --combined --stealth --blacklist "192.168.1.1,10.0.0.0/8" --interface eth0

# Custom scan parameters
zandoli --active --ttl 128 --arp-burst 20 --burst-min-delay 100 --interface eth0
```

### Verbose Logging
```bash
# Enable verbose logging for debugging
zandoli --pcap traffic.pcap --verbose --formats json

# Quiet mode for automated scripts
zandoli --passive --quiet --passive-duration 30 --formats csv
```

## Configuration File

### Default Configuration

Zandoli uses a YAML configuration file (`config.yaml`) for default settings:

```yaml
interface: "eth0"
logging:
  verbose: false
  quiet: false
  paranoid: false
scan:
  ttl: 64
  arp_max_per_sec: 3
  arp_burst: 10
  stealth: false
  burst_min_delay_ms: 100
  burst_max_delay_ms: 500
  syn_timeout_ms: 1000
  syn_ports: [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
  passive_duration_seconds: 60
  targeted: false
mode:
  passive: false
  active: false
  combined: false
  pcap: ""
  syn: false
output:
  base_dir: "output"
  record_pcap: false
  formats: ["json"]
  oui_file: ""
  allow_public_subnets: false
```

### CLI Override Behavior

Command-line flags override configuration file settings:

1. **Mode flags** (`--passive`, `--active`, `--combined`, `--pcap`) take absolute precedence
2. **Scan parameters** override config file values when specified
3. **Logging flags** override config only when explicitly provided
4. **Output settings** merge with config file defaults

## Input/Output Files

### Input Files

#### PCAP Files
```bash
# Supported formats
zandoli --pcap traffic.pcap        # Standard PCAP
zandoli --pcap traffic.pcapng      # PCAP-NG format
zandoli --pcap /path/to/file.pcap  # Absolute path
```

#### OUI Database
```bash
# IEEE OUI database for MAC vendor lookup
zandoli --oui-file /path/to/oui.txt
```

#### Configuration File
```bash
# Custom configuration file
zandoli --config /path/to/custom.yaml
```

### Output Files

#### Default Output Structure
```
output/
├── scan_20240115-124500/
│   ├── hosts.html          # HTML report
│   ├── hosts.csv           # CSV export
│   ├── hosts.json          # JSON export
│   ├── hosts.md            # Markdown export
│   ├── hosts.xml           # XML export
│   ├── traffic.pcap        # Recorded traffic (if --record-pcap)
│   └── log.txt             # Scan log
└── log.txt                 # Global log
```

#### Custom Output Directory
```bash
# Specify custom output directory
zandoli --output-dir /custom/path --formats html,json
```

Results will be saved to:
```
/custom/path/
└── scan_20240115-124500/
    ├── hosts.html
    ├── hosts.json
    └── log.txt
```

## Network Interface Selection

### Interface Specification
```bash
# Use specific interface
zandoli --interface eth0 --passive

# Use interface from config file
zandoli --passive  # Uses interface from config.yaml
```

### Interface Validation
- Interface must exist on the system
- Interface must support packet capture
- Root privileges required for live capture
- Interface validation occurs before scanning starts

## Port and Protocol Configuration

### SYN Scan Ports
```bash
# Default ports (from config)
zandoli --active --SYN

# Custom port list
zandoli --active --SYN --syn-ports 22,80,443,3389,5432

# Single port
zandoli --active --SYN --syn-ports 22
```

### Protocol Detection
Zandoli automatically detects and parses:
- **ARP/NDP**: Address resolution protocols
- **DHCP**: Dynamic host configuration
- **CDP**: Cisco Discovery Protocol
- **LLDP**: Link Layer Discovery Protocol
- **STP**: Spanning Tree Protocol
- **802.1X**: EAPOL authentication
- **TCP/UDP**: Transport layer protocols
- **HTTP/HTTPS**: Application protocols
- **DNS**: Domain name resolution
- **SMB**: Server Message Block

## Blacklist and Filtering

### IP/Subnet Exclusion
```bash
# Exclude specific IPs
zandoli --blacklist "192.168.1.1,10.0.0.1" --passive

# Exclude subnets
zandoli --blacklist "192.168.1.0/24,10.0.0.0/8" --passive

# Mixed exclusion list
zandoli --blacklist "192.168.1.1,10.0.0.0/8,172.16.0.0/12" --passive
```

### Built-in Exclusions
Zandoli automatically excludes:
- **Loopback addresses**: 127.0.0.0/8, ::1/128
- **Multicast addresses**: 224.0.0.0/4, ff00::/8
- **Broadcast addresses**: 255.255.255.255
- **Link-local addresses**: 169.254.0.0/16, fe80::/10

## Rate Limiting and Stealth

### ARP Rate Limiting
```bash
# Conservative scanning
zandoli --active --arp-max-per-sec 1 --arp-burst 5

# Aggressive scanning
zandoli --active --arp-max-per-sec 10 --arp-burst 50

# Burst control
zandoli --active --burst-min-delay 200 --burst-max-delay 1000
```

### Stealth Mode
```bash
# Enable randomized timing
zandoli --active --stealth --interface eth0

# Stealth with custom parameters
zandoli --active --stealth --arp-max-per-sec 3 --arp-burst 8
```

Stealth mode features:
- **Randomized timing** between packets
- **Variable burst patterns**
- **Jitter in packet spacing**
- **Unpredictable scan patterns**

## Logging Configuration

### Log Levels

#### Verbose Mode
```bash
zandoli --verbose --pcap traffic.pcap
```
- Detailed protocol parsing information
- Host discovery events
- Role inference details
- Performance metrics

#### Quiet Mode
```bash
zandoli --quiet --passive --passive-duration 60
```
- Minimal console output
- Essential information only
- Suitable for automated scripts

#### Paranoid Mode
```bash
zandoli --paranoid --passive --passive-duration 60
```
- No stdout output
- All information goes to log files
- Maximum stealth for sensitive environments

### Log Files
- **Global log**: `output/log.txt`
- **Scan-specific log**: `output/scan_TIMESTAMP/log.txt`
- **Log format**: Timestamp, level, message, context

## Error Handling

### Common Error Conditions

#### Permission Errors
```bash
# Error: permission denied for interface access
sudo zandoli --passive --interface eth0
```

#### Interface Errors
```bash
# Error: interface not found
zandoli --interface nonexistent --passive
# Solution: Check available interfaces with 'ip link show'
```

#### File Errors
```bash
# Error: PCAP file not found
zandoli --pcap missing.pcap
# Solution: Verify file path and permissions
```

#### Configuration Errors
```bash
# Error: invalid YAML syntax
zandoli --config invalid.yaml
# Solution: Check YAML syntax and structure
```

### Exit Codes
- **0**: Success
- **1**: General error (configuration, permissions, file access)
- **2**: Network interface error
- **3**: PCAP file error
- **4**: Validation error

## Performance Considerations

### Large PCAP Files
```bash
# For large PCAP files, use streaming mode
zandoli --pcap large_file.pcap --formats json
```

### Memory Usage
- **Streaming processing** for large captures
- **Configurable workers** for parallel processing
- **Memory-efficient** data structures

### Network Impact
- **Rate limiting** prevents network flooding
- **Stealth modes** minimize detection
- **Blacklist support** excludes sensitive networks

## Integration Examples

### Script Integration
```bash
#!/bin/bash
# Automated network scanning script

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/var/log/zandoli/scans"

zandoli --combined \
        --passive-duration 120 \
        --interface eth0 \
        --output-dir "$OUTPUT_DIR" \
        --formats html,json \
        --quiet

if [ $? -eq 0 ]; then
    echo "Scan completed successfully: $OUTPUT_DIR/scan_$TIMESTAMP"
else
    echo "Scan failed with exit code $?"
fi
```

### Cron Job
```bash
# Daily network scan at 2 AM
0 2 * * * /usr/local/bin/zandoli --combined --passive-duration 300 --interface eth0 --output-dir /var/log/daily-scans --quiet
```

## See Also

- [Export Formats](EXPORTS.md)
- [Configuration Reference](ARCHITECTURE.md#configuration)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Security Considerations](SECURITY.md)
