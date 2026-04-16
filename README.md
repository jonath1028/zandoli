# Zandoli Alpha – Passive/Active Network Analyzer

> 📖 **[Version française](LISMOI.md)**

Zandoli is an advanced network analyzer that combines passive listening and active scanning to discover and map network devices. It analyzes PCAP files or listens in real-time, extracts Layer 2 (CDP, LLDP, STP, 802.1X) and Layer 3 information, then generates detailed HTML, CSV, and JSON reports.

## ⚠️ Disclaimer

**This software is provided for security auditing, testing, and research purposes.**

- **Authorization required**: use this tool only on systems, networks, or captures for which you have explicit permission. Unauthorized use may be illegal.

- **Compliance**: you must follow applicable laws and policies (data protection, privacy, terms of use, internal rules).

- **Data & privacy**: analysis may expose sensitive information (IP addresses, host identifiers, metadata). You are solely responsible for handling, storing, and disposing of such data in compliance with regulations (e.g., GDPR).

- **No warranty**: the software is provided "as is", without warranty of accuracy or fitness for a particular purpose. Authors and contributors shall not be liable for any direct or indirect damages arising from its use.

- **Third-party & trademarks**: referenced trademarks belong to their respective owners. Third-party dependencies remain under their own licenses.

- **Contributions**: by contributing, you agree your contributions are released under the project's license.

**By using this software, you acknowledge and accept this disclaimer.**

---

## 🎯 Objective

Zandoli enables network administrators and security professionals to:
- **Discover** all network-connected devices
- **Identify** device roles (routers, switches, servers, clients)
- **Analyze** active protocols and services
- **Map** network topology with VLANs
- **Detect** anomalies and suspicious behaviors

## 🚀 Installation & Build

### Prerequisites
- Go ≥ 1.24.2
- Linux/Unix (tested on Kali Linux)
- Root privileges for network capture (optional)

### Build
```bash
git clone <repository-url>
cd zandoli
go build -o build/zandoli ./cmd/zandoli
```

### Quick Installation
```bash
# Build and install
git clone <repository-url> && cd zandoli
sudo bash install.sh --deps

# Or manually
go build -o build/zandoli ./cmd/zandoli
sudo cp build/zandoli /usr/local/bin/

# Verify
zandoli --help
```

## ⚡ Quick Start

### 1. PCAP Analysis (recommended for beginners)
```bash
# Analyze a PCAP file with all formats
zandoli --pcap capture.pcap --formats json,csv,html

# Results in output/scan_YYYYMMDD-HHMMSS/
```

### 2. Passive Listening (30 seconds)
```bash
# Passive listening on eth0 interface
sudo zandoli --passive --passive-duration 30 --interface eth0

# With stealth profile and PCAP recording
sudo zandoli --passive --profile stealth --record-pcap
```

### 3. Combined Scan (passive + active)
```bash
# Listen for 30s then ARP scan unknown hosts
sudo zandoli --combined --passive-duration 30 --interface eth0
```

## 📊 Output Formats

| Format | File | Description |
|--------|------|-------------|
| **HTML** | `report.html` | Interactive report with filters, search, badges |
| **CSV** | `hosts.csv` | Tabular export (`;` delimiter) |
| **JSON** | `hosts.json` | Structured data for integration |
| **Markdown** | `report.md` | Text documentation |
| **XML** | `hosts.xml` | Standardized XML format |

## 🔧 Main Options

### Execution Modes
```bash
--passive              # Passive mode only (listening)
--active               # Active mode only (ARP/SYN)
--combined             # Combined mode (passive then active)
--pcap <file>          # Offline PCAP analysis
--SYN                  # SYN scan on unidentified hosts
--profile <name>       # stealth, normal, aggressive, passive-only
```

### Network Configuration
```bash
--interface <iface>    # Network interface (default: eth0)
--passive-duration <s> # Passive listening duration (seconds)
--ttl <n>              # TTL for active packets
--blacklist <ips>      # IPs/subnets to exclude
```

### Formats and Output
```bash
--formats html,csv,json    # Export formats
--output-dir <dir>         # Output directory
--oui-file <file>          # OUI file for vendor lookup
--record-pcap              # Record listening to PCAP
```

### Logging
```bash
--verbose             # Detailed logs
--quiet               # Reduced logs
--paranoid            # No stdout logs
--summary             # Display summary at end
```

## 📋 Table of Contents

### User Documentation
- [**CLI & Options**](docs/CLI.md) - Complete command reference
- [**Processing Pipeline**](docs/PIPELINE.md) - Detailed process steps
- [**Export Formats**](docs/EXPORTS.md) - HTML, CSV, JSON details
- [**L2 Protocols**](docs/L2_PROTOCOLS.md) - CDP, LLDP, STP, 802.1X
- [**Logging**](docs/LOGGING.md) - Configuration and log rotation

### Technical Documentation
- [**Architecture**](docs/ARCHITECTURE.md) - Modules and data flow
- [**Data Model**](docs/DATA_MODEL.md) - Structures and types
- [**Troubleshooting**](docs/TROUBLESHOOTING.md) - Common errors and solutions
- [**Security**](docs/SECURITY.md) - Considerations and best practices

### Developer Documentation
- [**Contributing**](CONTRIBUTING.md) - Guide to contribute to the project
- [**Glossary**](docs/GLOSSARY.md) - Technical terms and acronyms
- [**Changelog**](CHANGELOG.md) - Version history

## 🎯 Report Examples

### HTML Report
The generated HTML report contains:
- **Overview**: global statistics, VLAN topology
- **Discovered hosts**: interactive table with filters by role, VLAN, vendor
- **L2 Details**: CDP/LLDP/STP/802.1X information
- **Services**: open TCP/UDP ports per host
- **Anomalies**: automatic detection of suspicious behaviors
- **Subnets**: network segment mapping

### CSV Export
Tabular format with columns:
```
MAC;Vendor;VLANs;L2Flags;IP;IPv6;UDP_Services;TCP_Services;Protocols
```

### JSON Export
Complete hierarchical structure with metadata:
```json
{
  "version": "Alpha",
  "generatedAt": "2025-01-30T10:30:00Z",
  "count": 42,
  "hosts": [...],
  "subnets": [...]
}
```

## ⚠️ Notes & Limitations

- **Privileges**: Network capture requires root privileges
- **Performance**: Optimized for networks < 1000 simultaneous hosts
- **PCAP**: Supports .pcap and .pcapng formats
- **VLANs**: Automatic detection via 802.1Q tags
- **IPv6**: Full IPv4/IPv6 dual-stack support

## 🔒 Security

Zandoli is a **passive** tool that does not exploit vulnerabilities. It:
- ✅ Only reads network traffic
- ✅ Does not send malicious packets
- ✅ Respects protocol RFCs
- ✅ Can be used in production without risk

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](./LICENSE) file for details.

_Contributions are welcome; see [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`DCO.md`](./DCO.md)._

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: Reportez les problèmes via les issues GitHub
- **Discussions**: Utilisez les discussions GitHub pour les questions

---

**See also**: [Architecture](docs/ARCHITECTURE.md) | [CLI Reference](docs/CLI.md) | [Pipeline](docs/PIPELINE.md) | [Export Formats](docs/EXPORTS.md)
