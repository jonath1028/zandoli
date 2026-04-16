# Zandoli - Network Reconnaissance Tool

Zandoli is a Go-based network reconnaissance tool that performs passive and active network scanning to discover hosts, analyze Layer 2 protocols, and generate comprehensive reports in multiple formats.

## What Zandoli Does

Zandoli analyzes network traffic (live capture or PCAP files) to:

- **Discover network hosts** through passive sniffing and active scanning
- **Analyze Layer 2 protocols** (CDP, LLDP, STP, 802.1X) for network device identification
- **Infer device roles** (client, server, network infrastructure) using behavioral analysis
- **Detect network anomalies** and potential security issues
- **Generate comprehensive reports** in HTML, CSV, JSON, Markdown, and XML formats
- **Support both IPv4 and IPv6** networks with dual-stack capabilities

## Target Audience

- **Network administrators** performing network discovery and inventory
- **Security professionals** conducting network reconnaissance and analysis
- **IT professionals** troubleshooting network connectivity and topology issues
- **Researchers** studying network protocols and device behaviors

## Quick Start

### Prerequisites

- Go ≥ 1.18
- Linux/Unix environment
- Network interface with packet capture capabilities
- Root privileges for live sniffing (or appropriate capabilities)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd zandoli

# Build the binary
go build -o zandoli cmd/zandoli/main.go

# Make it executable
chmod +x zandoli
```

### Basic Usage

#### 1. Analyze a PCAP File (Offline)
```bash
./zandoli --pcap traffic.pcap --formats html,csv,json --output-dir results
```

#### 2. Live Network Scanning (Combined Mode)
```bash
sudo ./zandoli --combined --passive-duration 60 --interface eth0 --formats html,json
```

#### 3. Passive Sniffing Only
```bash
sudo ./zandoli --passive --passive-duration 120 --interface eth0 --formats html
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--passive` | Run passive mode only (sniffing) | false |
| `--active` | Run active mode only (ARP, SYN) | false |
| `--combined` | Run passive then active scan | false |
| `--pcap <file>` | Analyze PCAP file (disables active scan) | "" |
| `--passive-duration <s>` | Passive sniffing duration in seconds | 0 |
| `--interface <iface>` | Network interface to use | from config |
| `--output-dir <dir>` | Output directory for results | output |
| `--formats <f1,f2>` | Output formats: json,csv,html,markdown,xml | json |
| `--oui-file <file>` | Path to OUI.txt for MAC vendor lookup | "" |
| `--verbose` | Enable verbose logging | false |
| `--quiet` | Reduce log verbosity | false |
| `--help` | Display help message | - |

For complete CLI documentation, see [CLI Reference](CLI.md).

## Output Formats

### HTML Report
- Interactive web interface with filtering and search
- Comprehensive host details with Layer 2 information
- Network topology visualization
- Subnet analysis with RFC1918 classification

### CSV Export
- Semicolon-delimited format (`;`) for Excel/LibreOffice compatibility
- Structured data for further analysis
- All host information in tabular format

### JSON Export
- Machine-readable format for integration
- Complete host details including anomalies
- Network topology and subnet information

## Report Sections

### 1. Global Summary
- Total hosts discovered
- Vendor distribution
- Role classification (client/server/network)
- Protocol usage statistics

### 2. Host Discovery
- IP addresses (IPv4/IPv6 dual-stack)
- MAC addresses with vendor identification
- Inferred roles with confidence scores
- Layer 2 protocol details (CDP, LLDP, STP, 802.1X)
- Service ports and protocols

### 3. Network Topology
- Subnet discovery and classification
- VLAN information
- Network device relationships
- IPv4/IPv6 network mapping

### 4. Layer 2 Details
- CDP information (Device ID, Platform, Version, Capabilities)
- LLDP details (System Name, Description, Management Addresses)
- STP topology (Bridge IDs, Root Bridge, Path Costs)
- 802.1X authentication status
- VLAN assignments

## Key Features

### Role Inference
Zandoli uses sophisticated role inference algorithms:

1. **Layer 2 Priority**: CDP/LLDP/STP/802.1X protocols override all other signals
2. **OUI Fallback**: Network vendor OUI classification when no L2 protocols present
3. **Behavioral Analysis**: Client vs Server detection based on protocol responses
4. **Confidence Scoring**: 0-100% confidence levels for role assignments

### Anomaly Detection
- ARP storms and flooding detection
- Multiple IPs per MAC address
- Duplicate hostnames across devices
- Suspicious TTL values
- Multiple DHCP servers

### Performance Features
- Concurrent packet processing
- Memory-efficient streaming for large PCAPs
- Stealth scanning modes to minimize network impact
- Configurable rate limiting and burst control

## Configuration

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
  syn_timeout_ms: 1000
  syn_ports: [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
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
  allow_public_subnets: false
```

## Documentation Structure

- **[Architecture](ARCHITECTURE.md)** - System design and module relationships
- **[Pipeline](PIPELINE.md)** - Detailed data processing workflow
- **[Data Model](DATA_MODEL.md)** - Core data structures and schemas
- **[Layer 2 Protocols](L2_PROTOCOLS.md)** - CDP, LLDP, STP, 802.1X details
- **[Exports](EXPORTS.md)** - Output format specifications
- **[CLI Reference](CLI.md)** - Complete command-line documentation
- **[Logging](LOGGING.md)** - Log configuration and levels
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions
- **[Security](SECURITY.md)** - Security considerations and best practices
- **[Contributing](CONTRIBUTING.md)** - Development guidelines
- **[Glossary](GLOSSARY.md)** - Networking terminology
- **[Changelog](CHANGELOG.md)** - Version history and changes

## License

[License information to be added]

## Credits

Zandoli is built using:
- [gopacket](https://github.com/google/gopacket) for packet parsing
- [zerolog](https://github.com/rs/zerolog) for structured logging
- [yaml.v3](https://gopkg.in/yaml.v3) for configuration parsing

## See Also

- [Architecture Overview](ARCHITECTURE.md)
- [Quick Start Guide](PIPELINE.md)
- [CLI Reference](CLI.md)
- [Troubleshooting](TROUBLESHOOTING.md)
