# Documentation Index

Welcome to the Zandoli documentation. This index provides quick access to all documentation sections.

## Getting Started

- **[README](README.md)** - Project overview, quick start, and key features
- **[CLI Reference](CLI.md)** - Complete command-line interface documentation
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions

## Technical Documentation

- **[Architecture](ARCHITECTURE.md)** - System design and module relationships
- **[Pipeline](PIPELINE.md)** - Data processing workflow and algorithms
- **[Data Model](DATA_MODEL.md)** - Core data structures and schemas

## Protocol and Network Details

- **[Layer 2 Protocols](L2_PROTOCOLS.md)** - CDP, LLDP, STP, 802.1X protocol details
- **[Export Formats](EXPORTS.md)** - HTML, CSV, JSON, Markdown, XML specifications

## Operations and Maintenance

- **[Logging](LOGGING.md)** - Log configuration and analysis
- **[Security](SECURITY.md)** - Security considerations and best practices

## Development and Contribution

- **[Contributing](CONTRIBUTING.md)** - Development guidelines and contribution process
- **[Glossary](GLOSSARY.md)** - Networking terminology and Zandoli-specific terms
- **[Changelog](CHANGELOG.md)** - Version history and migration guides

## Quick Reference

### Common Commands
```bash
# Analyze PCAP file
zandoli --pcap traffic.pcap --formats html,json

# Live network scanning
sudo zandoli --combined --passive-duration 60 --interface eth0

# Passive sniffing only
sudo zandoli --passive --passive-duration 120 --interface eth0
```

### Key Features
- **Layer 2 Protocol Analysis**: CDP, LLDP, STP, 802.1X
- **Role Inference**: Client, server, network device classification
- **Anomaly Detection**: ARP storms, duplicate IPs, suspicious patterns
- **Multiple Export Formats**: HTML, CSV, JSON, Markdown, XML
- **Dual-Stack Support**: IPv4 and IPv6 network analysis

### Documentation Structure
- **13 comprehensive documents** covering all aspects of Zandoli
- **4,659 total lines** of detailed documentation
- **Cross-referenced** with internal links between documents
- **Practical examples** and real-world usage scenarios

## Need Help?

1. **Start with [README](README.md)** for project overview
2. **Check [CLI Reference](CLI.md)** for command usage
3. **Consult [Troubleshooting](TROUBLESHOOTING.md)** for common issues
4. **Review [Glossary](GLOSSARY.md)** for terminology
5. **See [Contributing](CONTRIBUTING.md)** for development questions

## Documentation Statistics

| Document | Lines | Purpose |
|----------|-------|---------|
| [README](README.md) | 212 | Project overview and quick start |
| [CLI Reference](CLI.md) | 463 | Command-line interface documentation |
| [Troubleshooting](TROUBLESHOOTING.md) | 542 | Issue resolution and debugging |
| [Export Formats](EXPORTS.md) | 428 | Output format specifications |
| [Data Model](DATA_MODEL.md) | 433 | Core data structures |
| [Pipeline](PIPELINE.md) | 347 | Processing workflow |
| [Layer 2 Protocols](L2_PROTOCOLS.md) | 338 | Protocol details |
| [Logging](LOGGING.md) | 384 | Log configuration |
| [Contributing](CONTRIBUTING.md) | 387 | Development guidelines |
| [Security](SECURITY.md) | 310 | Security considerations |
| [Architecture](ARCHITECTURE.md) | 286 | System design |
| [Changelog](CHANGELOG.md) | 251 | Version history |
| [Glossary](GLOSSARY.md) | 278 | Terminology reference |

**Total: 4,659 lines of comprehensive documentation**
